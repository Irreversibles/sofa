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
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache


def optimize_system_limits():
    print("[*] 正在尝试优化系统内核与文件描述符限制...", flush=True)
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target_limit = max(65535, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, target_limit))
        new_soft, new_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        print(f"[+] 文件描述符上限调整成功: {new_soft}", flush=True)
    except Exception as e:
        print(f"[-] 调整 ulimit 失败: {e}", flush=True)
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
                print(f"[+] 内核参数已优化: {path} -> {value}", flush=True)
            except Exception as e:
                print(f"[-] 设置 {path} 失败: {e}", flush=True)
    else:
        print("[!] 非 Root，跳过 sysctl 优化", flush=True)

optimize_system_limits()

try:
    import uvloop
    uvloop.install()
    UVLOOP_ENABLED = True
except ImportError:
    UVLOOP_ENABLED = False

# ==================== 配置区域 ====================
DEFAULT_TARGETS = os.getenv("TARGET_LIST", os.getenv("ASN_LIST", "AS36002"))
DEFAULT_PORTS = "443, 8443, 2053, 2083, 2096"
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "zeroo.ccwu.cc")

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

global_counter = None
global_pass_counter = None
global_lock = None
global_total = 0
global_step = 0
global_printed_milestones = None


def parse_ports(port_str):
    if not port_str:
        return [443, 8443, 2053, 2083, 2096]
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
    return sorted(list(ports)) if ports else [443, 8443, 2053, 2083, 2096]


@lru_cache(maxsize=32)
def get_ips_from_asn_sync(asn_clean):
    import urllib.request
    cidrs = []
    try:
        ripe_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_clean}"
        req = urllib.request.Request(ripe_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.loads(response.read().decode())
            prefixes = data.get("data", {}).get("prefixes", [])
            for p in prefixes:
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
                ipv4_prefixes = data.get("data", {}).get("ipv4_prefixes", [])
                for p in ipv4_prefixes:
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


async def parse_targets_async(input_str):
    loop = asyncio.get_running_loop()
    raw_targets = [t.strip() for t in re.split(r'[\s,]+', input_str) if t.strip()]
    all_ips = []
    for item in raw_targets:
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
        wildcard_domain = f"*.{main_domain}"
        if main_domain in cert_str or wildcard_domain in cert_str:
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
                        print(f"  [第一阶段全局进度] {pct}% ({curr:,}/{global_total:,}) | 已通过: {passed:,} 个", flush=True)
            return res

        tasks = [worker(ip, port) for ip, port in targets_chunk]
        results = await asyncio.gather(*tasks)
        return [targets_chunk[i] for i, ok in enumerate(results) if ok]

    return asyncio.run(_run())


async def main():
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGETS
    ports_input = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PORTS

    target_ports = parse_ports(ports_input)

    print(f"\n[*] 正在解析目标地址/ASN...", flush=True)
    all_ips = await parse_targets_async(target_input)
    if not all_ips:
        print("[-] 未能获取到任何待测 IP，程序退出。", flush=True)
        return

    targets = [(ip, port) for ip in all_ips for port in target_ports]
    total_targets_count = len(targets)
    print(f"[*] 引擎初始化：uvloop={UVLOOP_ENABLED} | 并行进程数={CPU_CORES}", flush=True)
    print(f"[*] 解析完成：{len(all_ips)} 个 IP × {len(target_ports)} 个端口 = 共 {total_targets_count:,} 个测试目标。", flush=True)

    print(f"\n[1/3 第一阶段 TLS 探测] 多进程并行并发中...", flush=True)
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

    print(f"[+] 第一阶段完成！匹配 CF 证书保留目标: {len(pass_1)} 个\n", flush=True)
    if not pass_1:
        print("[-] 无有效 IP:端口 通过第一阶段。", flush=True)
        return

    sem = asyncio.Semaphore(STAGE1_CONCURRENCY * CPU_CORES)
    print(f"[2/3 第二阶段 HTTP 校验] 正在快速校验 {len(pass_1)} 个候选目标...", flush=True)
    tasks2 = [check_http_async(ip, port, CF_HOST_TEST, STAGE2_TIMEOUT, sem) for ip, port in pass_1]
    res2 = await asyncio.gather(*tasks2)
    pass_2 = [pass_1[i] for i, ok in enumerate(res2) if ok]
    print(f"[+] 第二阶段完成！可用 301 重定向目标: {len(pass_2)} 个\n", flush=True)
    if not pass_2:
        print("[-] 无有效 IP:端口 通过第二阶段。", flush=True)
        return

    final_items = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[3/3 第三阶段自定义域名校验] 正在校验域名 {domain}...", flush=True)
        tasks3 = [check_tls_sni_async(ip, port, domain, STAGE3_TIMEOUT, sem) for ip, port in pass_2]
        res3 = await asyncio.gather(*tasks3)
        final_items = [pass_2[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 第三阶段完成！支持自定义托管域名的优选反代 IP: {len(final_items)} 个", flush=True)
    else:
        print("[3/3] 未检测到 CUSTOM_CF_DOMAIN，自动跳过第三阶段。", flush=True)

    final_items = sorted(final_items, key=lambda x: (ipaddress.ip_address(x[0]), x[1]))

    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"最终有效目标总数: {len(final_items)}", flush=True)

    clean_name = re.sub(r'[^\w\.-]', '_', target_input.split(',')[0].strip())
    output_filename = f"{clean_name}.txt"

    with open(output_filename, "w", encoding="utf-8") as f:
        for ip, port in final_items:
            f.write(f"{ip}:{port}\n")

    print(f"\n[+] 最终结果已排序保存至：{output_filename} (格式为 IP:PORT)", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
