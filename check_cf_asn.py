import asyncio
import ssl
import sys
import os
import resource
import urllib.request
import json
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor

import geoip2.database

# ==================== 配置区域 ====================
DEFAULT_ASN = os.getenv("ASN_LIST", "AS13335")
DEFAULT_NAME = os.getenv("NAME_LABEL", "RESULT")
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "zeroo.ccwu.cc")

PORTS = [443, 2053, 2083, 2087, 2096, 8443]
GEOIP_DB = "GeoLite2-Country.mmdb"

CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = 800
STAGE1_TIMEOUT = 1.5
CF_HOST_TEST = "crypto.cloudflare.com"

try:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    print(f"[*] 系统 Socket 文件描述符上限已提升至: {hard}", flush=True)
except Exception as e:
    print(f"[!] 提升文件描述符失败 (若非 Linux 可忽略): {e}", flush=True)

custom_executor = ThreadPoolExecutor(max_workers=STAGE1_CONCURRENCY)

try:
    geo_reader = geoip2.database.Reader(GEOIP_DB)
except Exception:
    geo_reader = None
    print("[!] 未找到 GeoIP 数据库，地区将显示 ??", flush=True)


def get_country(ip):
    if geo_reader is None:
        return "??"
    try:
        return geo_reader.country(ip).country.iso_code or "??"
    except Exception:
        return "??"


def get_ips_from_asn(asn_input):
    asn_clean = asn_input.strip().upper().replace("AS", "")
    if not asn_clean.isdigit():
        print(f"[-] 无效的 ASN 输入: {asn_input}", flush=True)
        return []

    print(f"[*] 正在自动查询并拉取 AS{asn_clean} 的网段信息...", flush=True)
    cidrs = []

    try:
        ripe_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_clean}"
        req = urllib.request.Request(ripe_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            prefixes = data.get("data", {}).get("prefixes", [])
            for p in prefixes:
                prefix = p.get("prefix")
                if prefix and ":" not in prefix:
                    cidrs.append(prefix)
    except Exception as e:
        print(f"[!] RIPE API 获取失败: {e}", flush=True)

    if not cidrs:
        try:
            bgp_url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
            req = urllib.request.Request(bgp_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                ipv4_prefixes = data.get("data", {}).get("ipv4_prefixes", [])
                for p in ipv4_prefixes:
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.append(prefix)
        except Exception as e:
            print(f"[!] BGPView API 获取失败: {e}", flush=True)

    ip_list = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.prefixlen >= 31:
                for ip in net:
                    ip_list.append(str(ip))
            else:
                for ip in net.hosts():
                    ip_list.append(str(ip))
        except Exception:
            continue

    print(f"[+] AS{asn_clean} 共解析出 {len(ip_list)} 个待测 IPv4 地址。", flush=True)
    return ip_list


def check_tls_sni(ip, port, sni, timeout_val):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ssl.create_connection((ip, port), timeout=timeout_val) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return False
                cert_str = der_cert.decode('latin1', errors='ignore').lower()
                return sni.lower() in cert_str
    except Exception:
        return False


def find_alive_port(ip, sni, timeout_val):
    """粗筛：逐端口试 TLS，返回第一个通过的端口；全不过返回 None。"""
    for port in PORTS:
        if check_tls_sni(ip, port, sni, timeout_val):
            return port
    return None


def check_http_via_curl(ip, port, host, timeout_val):
    cmd = [
        "curl", "-I", "-s",
        "-o", "/dev/null",
        "-w", "%{http_code}",
        "--connect-timeout", "3",
        "-m", str(int(timeout_val)),
        "--resolve", f"{host}:{port}:{ip}",
        f"https://{host}:{port}/",
    ]
    try:
        res = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return res.stdout.strip() in ("301", "302")
    except Exception:
        return False


async def run_stage1_worker_queue(ip_list):
    """粗筛：多端口，任一 TLS 过即保留，记录 (ip, 通过的端口)。"""
    total = len(ip_list)
    completed = 0
    passed = []
    step = max(1, total // 10)
    last_printed_step = 0

    queue = asyncio.Queue()
    for ip in ip_list:
        queue.put_nowait(ip)

    print(f"\n[1/3 第一阶段 TLS 探测(多端口)] 开始测试，共 {total} 个目标...", flush=True)
    loop = asyncio.get_running_loop()

    async def worker():
        nonlocal completed, last_printed_step
        while True:
            try:
                ip = queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            port = await loop.run_in_executor(
                custom_executor, find_alive_port, ip, CF_SNI_1, STAGE1_TIMEOUT
            )
            completed += 1
            if port is not None:
                passed.append((ip, port))

            current_step = completed // step
            if current_step > last_printed_step or completed == total:
                last_printed_step = current_step
                percent = (completed / total) * 100
                print(
                    f"[1/3 进度] {completed}/{total} ({percent:.1f}%) | "
                    f"当前通过: {len(passed)} 个",
                    flush=True,
                )
            queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(STAGE1_CONCURRENCY)]
    await asyncio.gather(*workers)
    return passed


async def full_check(ip, first_port):
    """从粗筛通过的端口开始，逐端口做 HTTP301 + 域名验证，命中即返回。"""
    loop = asyncio.get_running_loop()
    ordered_ports = [first_port] + [p for p in PORTS if p != first_port]
    for port in ordered_ports:
        ok_http = await loop.run_in_executor(
            custom_executor, check_http_via_curl, ip, port, CF_HOST_TEST, 4.0
        )
        if not ok_http:
            continue
        if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
            ok_domain = await loop.run_in_executor(
                custom_executor, check_tls_sni, ip, port, CUSTOM_CF_DOMAIN.strip(), 3.0
            )
            if not ok_domain:
                continue
        country = get_country(ip)
        return (country, f"{ip}:{port}")
    return None


async def main():
    asn_raw = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ASN
    name_label = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_NAME

    asn_clean = asn_raw.strip().upper()
    if not asn_clean.startswith("AS"):
        asn_clean = f"AS{asn_clean}"

    all_ips = get_ips_from_asn(asn_clean)
    all_ips = list(dict.fromkeys(all_ips))
    if not all_ips:
        print("[-] 未能获取到任何待测 IP，程序退出。", flush=True)
        return

    pass_1 = await run_stage1_worker_queue(all_ips)
    print(f"[+] 第一阶段完成！保留 IP: {len(pass_1)} 个\n", flush=True)
    if not pass_1:
        print("[-] 无有效 IP 通过第一阶段。", flush=True)
        return

    print(f"[2/3 第二三阶段] 对 {len(pass_1)} 个候选做 HTTP+域名验证...", flush=True)
    tasks = [full_check(ip, port) for ip, port in pass_1]
    results = await asyncio.gather(*tasks)
    final = [r for r in results if r is not None]
    print(f"[+] 最终有效节点: {len(final)} 个", flush=True)

    final = sorted(set(final), key=lambda x: (x[0], x[1]))

    output_filename = f"{name_label}.txt"
    with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
        for country, addr in final:
            f.write(f"{addr}#{country} {name_label}\n")

    print(f"\n[+] 结果已保存至：{output_filename}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
