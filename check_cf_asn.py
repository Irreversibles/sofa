import asyncio
import ssl
import sys
import os
import re
import resource
import json
import ipaddress
import random
import socket
import multiprocessing
import urllib.request
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache

import geoip2.database


def optimize_system_limits():
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target_limit = max(65535, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, target_limit))
    except Exception:
        pass
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        sysctl_settings = {
            "/proc/sys/net/core/somaxconn": "65535",
            "/proc/sys/net/ipv4/tcp_tw_reuse": "1",
            "/proc/sys/net/ipv4/ip_local_port_range": "1024 65535",
        }
        for path, value in sysctl_settings.items():
            try:
                with open(path, "w") as f:
                    f.write(value)
            except Exception:
                pass

optimize_system_limits()

try:
    import uvloop
    uvloop.install()
    UVLOOP_ENABLED = True
except ImportError:
    UVLOOP_ENABLED = False

# ==================== 配置区域 ====================
DEFAULT_TARGET = os.getenv("ASN_LIST", "AS36002")
DEFAULT_NAME = os.getenv("NAME_LABEL", "auto")
DEFAULT_PORTS = os.getenv("PORTS", "443,2053,2083,2096,8443")
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "")

GEOIP_DB = "GeoLite2-Country.mmdb"

CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = 50
STAGE1_TIMEOUT = 2
STAGE3_TIMEOUT = 2
CPU_CORES = max(1, os.cpu_count() or 1)

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

try:
    geo_reader = geoip2.database.Reader(GEOIP_DB)
except Exception:
    geo_reader = None

global_counter = None
global_pass_counter = None
global_lock = None
global_total = 0
global_step = 0
global_printed_milestones = None


def get_country(ip):
    if geo_reader is None:
        return "??"
    try:
        return geo_reader.country(ip).country.iso_code or "??"
    except Exception:
        return "??"


def parse_ports(port_str):
    if not port_str:
        return [443, 2053, 2083, 2096, 8443]
    ports = set()
    parts = re.split(r'[\s,]+', str(port_str).strip())
    for part in parts:
        if '-' in part:
            try:
                start, end = part.split('-')
                s_idx, e_idx = max(1, int(start)), min(65535, int(end))
                if s_idx <= e_idx:
                    ports.update(range(s_idx, e_idx + 1))
            except ValueError:
                continue
        elif part.isdigit():
            val = int(part)
            if 1 <= val <= 65535:
                ports.add(val)
    return sorted(list(ports)) if ports else [443, 2053, 2083, 2096, 8443]


def get_asn_name(asn_clean):
    try:
        url = f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_clean}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode()).get("data", {})
            holder = data.get("holder", "")
            if holder:
                return holder
    except Exception:
        pass
    try:
        url = f"https://api.bgpview.io/asn/{asn_clean}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode()).get("data", {})
            return data.get("name") or data.get("description_short") or ""
    except Exception:
        return ""


def simplify_name(full_name):
    if not full_name:
        return ""
    name = full_name.split(" - ")[0].strip()
    suffixes = [
        "Cloud Services", "Cloud Computing", "Cloud", "Networks", "Network",
        "Technologies", "Technology", "Communications", "Communication",
        "International", "Global", "Group", "Holdings", "Solutions",
        "Data Center", "Datacenter", "Hosting", "Internet", "Services",
        "LLC", "L.L.C", "Ltd.", "Ltd", "Limited", "Inc.", "Inc",
        "Co.,", "Co.", "Corporation", "Corp.", "Corp", "GmbH", "S.A.", "B.V.",
    ]
    for suf in suffixes:
        name = re.sub(rf'\b{re.escape(suf)}\b', '', name, flags=re.IGNORECASE)
    name = re.sub(r'[-_]?AS$', '', name, flags=re.IGNORECASE)
    name = name.replace(",", " ").strip()
    parts = name.split()
    if parts:
        return parts[0]
    return full_name.split()[0] if full_name.split() else "RESULT"


@lru_cache(maxsize=32)
def get_ips_from_asn_sync(asn_clean):
    cidrs = []
    try:
        ripe_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_clean}"
        req = urllib.request.Request(ripe_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.loads(response.read().decode())
            for p in data.get("data", {}).get("prefixes", []):
                prefix = p.get("prefix")
                if prefix and ":" not in prefix:
                    cidrs.append(prefix)
    except Exception:
        pass
    if not cidrs:
        try:
            bgp_url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
            req = urllib.request.Request(bgp_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=8) as response:
                data = json.loads(response.read().decode())
                for p in data.get("data", {}).get("ipv4_prefixes", []):
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.append(prefix)
        except Exception:
            pass
    ip_list = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.prefixlen >= 31:
                ip_list.extend([str(ip) for ip in net])
            else:
                ip_list.extend([str(ip) for ip in net.hosts()])
        except Exception:
            continue
    return ip_list


def load_ip_from_file(file_path):
    ip_list = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                item = line.split("#", 1)[0].strip()
                if not item:
                    continue
                try:
                    net = ipaddress.ip_network(item, strict=False)
                    if net.prefixlen >= 31:
                        ip_list.extend([str(ip) for ip in net])
                    else:
                        ip_list.extend([str(ip) for ip in net.hosts()])
                except ValueError:
                    ip_list.append(item)
    except FileNotFoundError:
        pass
    return ip_list


async def parse_targets_async(input_str):
    loop = asyncio.get_running_loop()
    raw_targets = [t.strip() for t in re.split(r'[\s,]+', input_str) if t.strip()]
    all_ips = []
    for item in raw_targets:
        if item.lower().endswith(".txt"):
            all_ips.extend(load_ip_from_file(item))
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
            if net.prefixlen >= 31:
                all_ips.extend([str(ip) for ip in net])
            else:
                all_ips.extend([str(ip) for ip in net.hosts()])
            continue
        except ValueError:
            pass
        asn_clean = item.upper().replace("AS", "")
        if asn_clean.isdigit():
            ips = await loop.run_in_executor(None, get_ips_from_asn_sync, asn_clean)
            all_ips.extend(ips)
    unique_ips = list(dict.fromkeys(all_ips))
    random.shuffle(unique_ips)
    return unique_ips


def match_domain_in_cert(sni_domain, cert_str):
    sni_domain = sni_domain.lower()
    cert_str = cert_str.lower()
    if sni_domain in cert_str:
        return True
    parts = sni_domain.split(".")
    if len(parts) >= 2:
        main_domain = ".".join(parts[-2:])
        if main_domain in cert_str or f"*.{main_domain}" in cert_str:
            return True
    if "cloudflare" in sni_domain and "cloudflare" in cert_str:
        return True
    return False


async def check_tls_sni_async(ip, port, sni, timeout_val, sem):
    async with sem:
        writer = None
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=sni)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout_val)
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ssl_obj = writer.get_extra_info('ssl_object')
            if not ssl_obj:
                return False
            der_cert = ssl_obj.getpeercert(binary_form=True)
            if not der_cert:
                return False
            cert_str = der_cert.decode('latin1', errors='ignore').lower()
            return match_domain_in_cert(sni, cert_str)
        except Exception:
            return False
        finally:
            if writer:
                writer.close()
                try:
                    writer.transport.abort()
                except Exception:
                    pass


def _init_process_worker(counter, pass_counter, lock, total, printed_array):
    global global_counter, global_pass_counter, global_lock, global_total, global_step, global_printed_milestones
    global_counter = counter
    global_pass_counter = pass_counter
    global_lock = lock
    global_total = total
    global_step = max(1, total // 10)
    global_printed_milestones = printed_array


def _process_worker_stage1(targets_chunk):
    if UVLOOP_ENABLED:
        uvloop.install()

    async def _run():
        sem = asyncio.Semaphore(STAGE1_CONCURRENCY)

        async def worker(ip, port):
            res = await check_tls_sni_async(ip, port, CF_SNI_1, STAGE1_TIMEOUT, sem)
            with global_lock:
                global_counter.value += 1
                if res:
                    global_pass_counter.value += 1
                curr = global_counter.value
                passed = global_pass_counter.value
                milestone_idx = curr // global_step
                if 1 <= milestone_idx <= 10:
                    if global_printed_milestones[milestone_idx - 1] == 0:
                        global_printed_milestones[milestone_idx - 1] = 1
                        pct = min(100, milestone_idx * 10)
                        print(f"  [第一阶段进度] {pct}% ({curr:,}/{global_total:,}) | 已通过: {passed:,}", flush=True)
            return res

        tasks = [worker(ip, port) for ip, port in targets_chunk]
        results = await asyncio.gather(*tasks)
        return [targets_chunk[i] for i, ok in enumerate(results) if ok]

    return asyncio.run(_run())


def resolve_name(target_input, name_arg):
    if name_arg and name_arg.lower() != "auto":
        return name_arg
    first = target_input.strip().split(",")[0].strip()
    asn_clean = first.upper().replace("AS", "")
    if asn_clean.isdigit():
        api_name = get_asn_name(asn_clean)
        simple = simplify_name(api_name)
        if simple:
            print(f"[*] 自动识别 AS{asn_clean} -> {simple} (原名: {api_name})", flush=True)
            return simple
        return f"AS{asn_clean}"
    return "RESULT"


async def main():
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    name_arg = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_NAME
    ports_input = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_PORTS

    name_label = resolve_name(target_input, name_arg)
    target_ports = parse_ports(ports_input)

    print(f"\n[*] 正在解析目标...", flush=True)
    all_ips = await parse_targets_async(target_input)
    if not all_ips:
        print("[-] 未能获取到任何待测 IP，程序退出。", flush=True)
        return

    targets = [(ip, port) for ip in all_ips for port in target_ports]
    total_targets_count = len(targets)
    print(f"[*] 引擎：uvloop={UVLOOP_ENABLED} | 进程={CPU_CORES} | 名字={name_label}", flush=True)
    print(f"[*] {len(all_ips)} IP × {len(target_ports)} 端口 = 共 {total_targets_count:,} 个目标。", flush=True)

    # 第一阶段：多进程 TLS 粗筛
    print(f"\n[1/2 第一阶段 TLS 探测] 多进程并发中...", flush=True)
    num_chunks = CPU_CORES * 4
    chunk_size = max(1, total_targets_count // num_chunks)
    chunks = [targets[i:i + chunk_size] for i in range(0, total_targets_count, chunk_size)]

    manager = multiprocessing.Manager()
    counter = manager.Value('i', 0)
    pass_counter = manager.Value('i', 0)
    lock = manager.Lock()
    printed_array = manager.Array('i', [0] * 10)

    pass_1 = []
    loop = asyncio.get_running_loop()
    with ProcessPoolExecutor(
        max_workers=CPU_CORES,
        initializer=_init_process_worker,
        initargs=(counter, pass_counter, lock, total_targets_count, printed_array)
    ) as executor:
        futures = [loop.run_in_executor(executor, _process_worker_stage1, chunk) for chunk in chunks]
        results = await asyncio.gather(*futures)
        for res in results:
            pass_1.extend(res)
    print(f"[+] 第一阶段完成！保留: {len(pass_1)} 个\n", flush=True)
    if not pass_1:
        print("[-] 无有效目标通过第一阶段。", flush=True)
        return

    # 第二阶段：直接 TLS 握手你的域名（跳过 crypto 301）
    sem = asyncio.Semaphore(STAGE1_CONCURRENCY * CPU_CORES)
    final_items = pass_1
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[2/2 自定义域名校验] 校验 {len(pass_1)} 个...", flush=True)
        tasks3 = [check_tls_sni_async(ip, port, domain, STAGE3_TIMEOUT, sem) for ip, port in pass_1]
        res3 = await asyncio.gather(*tasks3)
        final_items = [pass_1[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 域名校验完成！有效目标: {len(final_items)} 个", flush=True)
    else:
        print("[2/2] 未检测到 CUSTOM_CF_DOMAIN，跳过。", flush=True)

    # 加地区，按 (地区, ip, 端口) 排序
    results_out = []
    for ip, port in final_items:
        country = get_country(ip)
        results_out.append((country, ip, port))
    results_out = sorted(set(results_out),
                         key=lambda x: (x[0], ipaddress.ip_address(x[1]), x[2]))

    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"最终有效目标总数: {len(results_out)}", flush=True)

    output_filename = f"{name_label}.txt"
    with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
        for country, ip, port in results_out:
            f.write(f"{ip}:{port}#{country} {name_label}\n")

    print(f"\n[+] 结果已保存至：{output_filename}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
