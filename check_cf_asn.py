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
    print("[*] 正在优化系统内核与文件描述符限制...", flush=True)
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target_limit = max(65535, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, target_limit))
        new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        print(f"[+] 文件描述符上限调整成功: {new_soft}", flush=True)
    except Exception as e:
        print(f"[-] 调整 ulimit 失败: {e}", flush=True)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        for path, value in {
            "/proc/sys/net/core/somaxconn": "65535",
            "/proc/sys/net/ipv4/tcp_tw_reuse": "1",
            "/proc/sys/net/ipv4/ip_local_port_range": "1024 65535",
        }.items():
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
DEFAULT_PORTS = os.getenv("PORTS", "443,8443,2053,2083,2096")
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "zeroo.ccwu.cc")

GEOIP_DB = "GeoLite2-Country.mmdb"
STATE_DIR = "state"   # 状态文件目录（抽过端口、已出货组合）
SAMPLE_N = 50         # 每次随机抽的端口数

CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = 50
STAGE1_TIMEOUT = 2
CF_HOST_TEST = "crypto.cloudflare.com"
STAGE2_TIMEOUT = 1.2
STAGE3_TIMEOUT = 1.2
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


# ==================== 状态管理（抽过端口 / 已出货组合） ====================

def _asn_key(target_input):
    """用目标第一个ASN作为状态key"""
    first = target_input.strip().split(",")[0].strip().split()[0].strip()
    asn = first.upper().replace("AS", "")
    return f"AS{asn}" if asn.isdigit() else re.sub(r'[^\w.-]', '_', first)


def load_scanned_ports(asn_key):
    """读取已抽过的端口集合"""
    os.makedirs(STATE_DIR, exist_ok=True)
    fname = os.path.join(STATE_DIR, f"scanned_ports_{asn_key}.txt")
    ports = set()
    try:
        with open(fname) as f:
            for line in f:
                s = line.strip()
                if s.isdigit():
                    ports.add(int(s))
    except FileNotFoundError:
        pass
    return ports


def save_scanned_ports(asn_key, ports):
    """覆盖写入已抽过端口"""
    os.makedirs(STATE_DIR, exist_ok=True)
    fname = os.path.join(STATE_DIR, f"scanned_ports_{asn_key}.txt")
    with open(fname, "w") as f:
        for p in sorted(ports):
            f.write(f"{p}\n")


def load_found_combos(asn_key):
    """读取已出货的 ip:port 组合集合"""
    os.makedirs(STATE_DIR, exist_ok=True)
    fname = os.path.join(STATE_DIR, f"found_{asn_key}.txt")
    combos = set()
    try:
        with open(fname) as f:
            for line in f:
                s = line.strip()
                if ":" in s:
                    combos.add(s)
    except FileNotFoundError:
        pass
    return combos


def save_found_combos(asn_key, combos):
    """覆盖写入已出货组合"""
    os.makedirs(STATE_DIR, exist_ok=True)
    fname = os.path.join(STATE_DIR, f"found_{asn_key}.txt")
    with open(fname, "w") as f:
        for c in sorted(combos):
            f.write(f"{c}\n")


def pick_ports(port_str, asn_key):
    """区间: 排除已抽过的, 随机抽SAMPLE_N个; 抽完则清空循环。非区间: 按填的。"""
    if not port_str:
        return [443, 8443, 2053, 2083, 2096]
    # 检查是否为区间
    ports = set()
    parts = re.split(r'[\s,]+', str(port_str).strip())
    has_range = any('-' in p for p in parts)

    if has_range:
        # 收集区间所有端口
        all_range = set()
        for part in parts:
            if '-' in part:
                try:
                    a, b = part.split('-')
                    s, e = max(1, int(a)), min(65535, int(b))
                    if s <= e:
                        all_range.update(range(s, e + 1))
                except ValueError:
                    continue
            elif part.isdigit():
                all_range.add(int(part))

        scanned = load_scanned_ports(asn_key)
        available = list(all_range - scanned)
        if len(available) < SAMPLE_N:
            # 抽完了，清空循环
            print(f"[*] {asn_key} 区间端口已抽完，清空记录重新循环", flush=True)
            scanned = set()
            available = list(all_range)
        chosen = random.sample(available, min(SAMPLE_N, len(available)))
        # 更新已抽过
        scanned.update(chosen)
        save_scanned_ports(asn_key, scanned)
        return sorted(chosen)
    else:
        # 非区间，按填的
        for part in parts:
            if part.isdigit():
                v = int(part)
                if 1 <= v <= 65535:
                    ports.add(v)
        return sorted(ports) if ports else [443, 8443, 2053, 2083, 2096]


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
    return parts[0] if parts else (full_name.split()[0] if full_name.split() else "RESULT")


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


async def check_http_async(ip, port, host, timeout_val, sem):
    async with sem:
        writer = None
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=host)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout_val)
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            writer.write(req.encode('latin1'))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=timeout_val)
            if not data:
                return False
            resp_str = data.decode('latin1', errors='ignore').lower()
            return ("http/1.1 301" in resp_str or "http/1.1 302" in resp_str) and ("location:" in resp_str)
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
    asn_key = _asn_key(target_input)

    # 选端口（区间则排除已抽过、随机抽SAMPLE_N、抽完循环）
    target_ports = pick_ports(ports_input, asn_key)
    print(f"[*] 本次使用端口({len(target_ports)}个): {target_ports}", flush=True)

    print(f"\n[*] 正在解析目标...", flush=True)
    all_ips = await parse_targets_async(target_input)
    if not all_ips:
        print("[-] 未能获取到任何待测 IP，程序退出。", flush=True)
        return

    # 读取已出货组合，生成目标时排除这些 ip:port
    found_combos = load_found_combos(asn_key)
    targets = []
    for ip in all_ips:
        for port in target_ports:
            if f"{ip}:{port}" not in found_combos:
                targets.append((ip, port))

    total_targets_count = len(targets)
    print(f"[*] 引擎：uvloop={UVLOOP_ENABLED} | 进程={CPU_CORES} | 名字={name_label}", flush=True)
    print(f"[*] {len(all_ips)} IP × {len(target_ports)} 端口，排除已出货后共 {total_targets_count:,} 个目标。", flush=True)
    if total_targets_count == 0:
        print("[-] 本次无新目标（都已出货或无IP）。", flush=True)
        return

    # 第一阶段
    print(f"\n[1/3 第一阶段 TLS 探测] 多进程并发中...", flush=True)
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

    # 第二阶段 crypto 301
    sem = asyncio.Semaphore(STAGE1_CONCURRENCY * CPU_CORES)
    print(f"[2/3 第二阶段 HTTP 校验] 校验 {len(pass_1)} 个候选...", flush=True)
    tasks2 = [check_http_async(ip, port, CF_HOST_TEST, STAGE2_TIMEOUT, sem) for ip, port in pass_1]
    res2 = await asyncio.gather(*tasks2)
    pass_2 = [pass_1[i] for i, ok in enumerate(res2) if ok]
    print(f"[+] 第二阶段完成！保留: {len(pass_2)} 个\n", flush=True)
    if not pass_2:
        print("[-] 无有效目标通过第二阶段。", flush=True)
        return

    # 第三阶段 你的域名
    final_items = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[3/3 第三阶段自定义域名校验] 校验 {len(pass_2)} 个...", flush=True)
        tasks3 = [check_tls_sni_async(ip, port, domain, STAGE3_TIMEOUT, sem) for ip, port in pass_2]
        res3 = await asyncio.gather(*tasks3)
        final_items = [pass_2[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 第三阶段完成！有效目标: {len(final_items)} 个", flush=True)
    else:
        print("[3/3] 未检测到 CUSTOM_CF_DOMAIN，跳过。", flush=True)

    # 本次新出货的 ip:port
    new_combos = set(f"{ip}:{port}" for ip, port in final_items)

    # 更新"已出货组合"（永久排除）
    found_combos.update(new_combos)
    save_found_combos(asn_key, found_combos)

    # 结果：追加去重，永久保留（读旧结果 + 新结果合并）
    output_filename = f"{name_label}.txt"
    old_lines = set()
    try:
        with open(output_filename, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s:
                    old_lines.add(s)
    except FileNotFoundError:
        pass

    # 新结果行（带地区+名字）
    for ip, port in final_items:
        country = get_country(ip)
        old_lines.add(f"{ip}:{port}#{country} {name_label}")

    # 排序：按地区、IP、端口
    def sort_key(line):
        try:
            addr = line.split("#")[0]
            ip_part, port_part = addr.rsplit(":", 1)
            country = line.split("#")[1].split()[0] if "#" in line else "??"
            return (country, ipaddress.ip_address(ip_part), int(port_part))
        except Exception:
            return ("??", ipaddress.ip_address("0.0.0.0"), 0)

    sorted_lines = sorted(old_lines, key=sort_key)

    with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
        for line in sorted_lines:
            f.write(line + "\n")

    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"本次新出货: {len(new_combos)} 个 | 结果文件累计: {len(sorted_lines)} 个", flush=True)
    print(f"[+] 结果已保存至：{output_filename}（追加去重，永久保留）", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
