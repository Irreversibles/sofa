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

TARGET_PORTS = [443, 2053, 2083, 2096, 8443]

EDT_KEYWORD = "edgetunnel"
EDT_PATH = "/admin"

GEOIP_DB = "GeoLite2-Country.mmdb"

CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = 2000
STAGE1_TIMEOUT = 0.5

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


def load_ip_from_file(file_path):
    """读取文件，支持单个 IP 和 CIDR 网段（不解析名字）。"""
    ip_list = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                item = line.split("#", 1)[0].strip()
                if not item:
                    continue
                if "/" in item:
                    try:
                        net = ipaddress.ip_network(item, strict=False)
                        if net.prefixlen >= 31:
                            ip_list.extend(str(ip) for ip in net)
                        else:
                            ip_list.extend(str(ip) for ip in net.hosts())
                    except ValueError:
                        print(f"[警告] 无效网段: {item}", flush=True)
                else:
                    ip_list.append(item)
    except FileNotFoundError:
        print(f"[-] 找不到文件 {file_path}", flush=True)
    print(f"[+] 从文件 {file_path} 读取到 {len(ip_list)} 个待测 IP。", flush=True)
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


def check_edt_backend(ip, port, domain, timeout_val):
    """访问 域名/admin，检查响应是否包含 EDT 后台特征。"""
    cmd = [
        "curl", "-s", "-L",
        "--connect-timeout", "4",
        "-m", str(int(timeout_val)),
        "--resolve", f"{domain}:{port}:{ip}",
        f"https://{domain}:{port}{EDT_PATH}",
    ]
    try:
        res = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return EDT_KEYWORD.lower() in res.stdout.lower()
    except Exception:
        return False


async def stage2_task(item, domain):
    ip, port = item
    loop = asyncio.get_running_loop()
    ok = await loop.run_in_executor(
        custom_executor, check_edt_backend, ip, port, domain, 8.0
    )
    return item if ok else None


async def run_stage1_worker_queue(targets):
    total = len(targets)
    completed = 0
    passed_items = []
    step = max(1, total // 10)
    last_printed_step = 0

    queue = asyncio.Queue()
    for item in targets:
        queue.put_nowait(item)

    print(f"\n[1/2 第一阶段 TLS 探测] 开始测试，共 {total} 个目标 (IP:端口组合)...", flush=True)
    loop = asyncio.get_running_loop()

    async def worker():
        nonlocal completed, last_printed_step
        while True:
            try:
                ip, port = queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            ok = await loop.run_in_executor(
                custom_executor, check_tls_sni, ip, port, CF_SNI_1, STAGE1_TIMEOUT
            )
            completed += 1
            if ok:
                passed_items.append((ip, port))

            current_step = completed // step
            if current_step > last_printed_step or completed == total:
                last_printed_step = current_step
                percent = (completed / total) * 100
                print(
                    f"[1/2 进度] {completed}/{total} ({percent:.1f}%) | "
                    f"当前通过: {len(passed_items)} 个",
                    flush=True,
                )
            queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(STAGE1_CONCURRENCY)]
    await asyncio.gather(*workers)
    return passed_items


async def main():
    input_arg = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ASN
    name_label = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_NAME

    arg = input_arg.strip()
    upper = arg.upper()

    # 判断模式：AS开头 或 纯数字 → ASN 模式；否则 → 文件模式
    if upper.startswith("AS") or arg.isdigit():
        asn_clean = upper if upper.startswith("AS") else f"AS{arg}"
        print(f"[*] 模式：自动拉取 ASN {asn_clean}", flush=True)
        all_ips = get_ips_from_asn(asn_clean)
    else:
        print(f"[*] 模式：读取文件 {arg}", flush=True)
        all_ips = load_ip_from_file(arg)

    all_ips = list(dict.fromkeys(all_ips))
    if not all_ips:
        print("[-] 未能获取到任何待测 IP，程序退出。", flush=True)
        return

    targets = [(ip, port) for ip in all_ips for port in TARGET_PORTS]
    print(
        f"[*] {len(all_ips)} 个 IP × {len(TARGET_PORTS)} 个端口 = "
        f"共 {len(targets)} 个连接目标。",
        flush=True,
    )

    pass_1 = await run_stage1_worker_queue(targets)
    print(f"[+] 第一阶段完成！保留目标: {len(pass_1)} 个\n", flush=True)
    if not pass_1:
        print("[-] 无有效目标通过第一阶段。", flush=True)
        return

    domain = CUSTOM_CF_DOMAIN.strip()
    print(f"[2/2 第二阶段 EDT后台校验] 访问 {domain}{EDT_PATH}，校验 {len(pass_1)} 个候选...", flush=True)
    tasks2 = [stage2_task(item, domain) for item in pass_1]
    res2 = await asyncio.gather(*tasks2)
    final_items = [item for item in res2 if item is not None]
    print(f"[+] 第二阶段完成！可访问 EDT 后台的有效目标: {len(final_items)} 个", flush=True)

    results = []
    for ip, port in final_items:
        country = get_country(ip)
        results.append((country, ip, port))
    results = sorted(set(results), key=lambda x: (x[0], ipaddress.ip_address(x[1]), x[2]))

    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"输入: {arg} | 端口: {TARGET_PORTS}", flush=True)
    print(f"最终有效目标总数: {len(results)}", flush=True)

    output_filename = f"{name_label}.txt"
    with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
        for country, ip, port in results:
            f.write(f"{ip}:{port}#{country} {name_label}\n")
    print(f"\n[+] 结果已保存至：{output_filename}", flush=True)
if __name__ == "__main__":
    asyncio.run(main())            
