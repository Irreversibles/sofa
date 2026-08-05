import asyncio
import ssl
import sys
import os
import re
import resource
import ipaddress
import json
import urllib.request

import geoip2.database

# ==================== 配置区域（敏感信息从 Secret 读） ====================
DEFAULT_TARGET = os.getenv("ASN_LIST", "AS13335")
DEFAULT_NAME = os.getenv("NAME_LABEL", "RESULT")
DEFAULT_PORTS = os.getenv("PORTS", "443,2053,2083,2096,8443")

CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "")
EDT_PATH = os.getenv("EDT_PATH", "/login")
EDT_KEYWORD = os.getenv("EDT_KEYWORD", "")

GEOIP_DB = "GeoLite2-Country.mmdb"

CF_SNI_1 = "www.cloudflare.com"
CONCURRENCY = 1000
STAGE1_TIMEOUT = 1.2
STAGE_EDT_TIMEOUT = 6.0

try:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    print(f"[*] Socket 文件描述符上限已提升至: {hard}", flush=True)
except Exception as e:
    print(f"[!] 提升文件描述符失败(非Linux可忽略): {e}", flush=True)

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

try:
    geo_reader = geoip2.database.Reader(GEOIP_DB)
except Exception:
    geo_reader = None
    print("[!] 未找到 GeoIP 数据库，地区显示 ??", flush=True)


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
    raw = re.split(r'[\s,]+', str(port_str).strip())
    ports = [int(p) for p in raw if p.isdigit() and 1 <= int(p) <= 65535]
    return list(dict.fromkeys(ports)) if ports else [443, 2053, 2083, 2096, 8443]


def get_ips_from_asn(asn_clean):
    print(f"[*] 正在查询 AS{asn_clean} 的网段...", flush=True)
    cidrs = []
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_clean}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
            for p in data.get("data", {}).get("prefixes", []):
                prefix = p.get("prefix")
                if prefix and ":" not in prefix:
                    cidrs.append(prefix)
    except Exception as e:
        print(f"[!] RIPE 获取失败: {e}", flush=True)

    if not cidrs:
        try:
            url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode())
                for p in data.get("data", {}).get("ipv4_prefixes", []):
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.append(prefix)
        except Exception as e:
            print(f"[!] BGPView 获取失败: {e}", flush=True)

    ip_list = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.prefixlen >= 31:
                ip_list.extend(str(ip) for ip in net)
            else:
                ip_list.extend(str(ip) for ip in net.hosts())
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
                        ip_list.extend(str(ip) for ip in net)
                    else:
                        ip_list.extend(str(ip) for ip in net.hosts())
                except ValueError:
                    ip_list.append(item)
    except FileNotFoundError:
        print(f"[-] 找不到文件", flush=True)
    return ip_list


def parse_targets(input_str):
    """智能解析：文件名 / ASN / CIDR / 单IP。"""
    all_ips = []
    raw = [t.strip() for t in re.split(r'[\s,]+', input_str) if t.strip()]

    for item in raw:
        # 文件模式：以 .txt 结尾
        if item.lower().endswith(".txt"):
            print(f"[*] 模式：读取文件", flush=True)
            ips = load_ip_from_file(item)
            print(f"[+] 从文件读取到 {len(ips)} 个 IP", flush=True)
            all_ips.extend(ips)
            continue
        # 网段/单IP
        try:
            net = ipaddress.ip_network(item, strict=False)
            if net.prefixlen >= 31:
                all_ips.extend(str(ip) for ip in net)
            else:
                all_ips.extend(str(ip) for ip in net.hosts())
            continue
        except ValueError:
            pass
        # ASN
        asn_clean = item.upper().replace("AS", "")
        if asn_clean.isdigit():
            ips = get_ips_from_asn(asn_clean)
            print(f"[+] AS{asn_clean} 提取出 {len(ips)} 个 IP", flush=True)
            all_ips.extend(ips)
        else:
            print(f"[-] 无法识别的目标格式", flush=True)

    unique = list(dict.fromkeys(all_ips))
    print(f"[+] 去重后共 {len(unique)} 个待测 IP", flush=True)
    return unique


def match_domain_in_cert(sni_domain, cert_str):
    sni_domain = sni_domain.lower()
    cert_str = cert_str.lower()
    if sni_domain in cert_str:
        return True
    parts = sni_domain.split(".")
    if len(parts) >= 2:
        main = ".".join(parts[-2:])
        if main in cert_str or f"*.{main}" in cert_str:
            return True
    if "cloudflare" in sni_domain and "cloudflare" in cert_str:
        return True
    return False


async def check_tls_async(ip, port, sni, timeout, sem):
    """异步 TLS 握手 + 证书匹配（粗筛用）。"""
    async with sem:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=sni),
                timeout=timeout,
            )
            ssl_obj = writer.get_extra_info('ssl_object')
            der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            if not der:
                return False
            cert_str = der.decode('latin1', errors='ignore').lower()
            return match_domain_in_cert(sni, cert_str)
        except Exception:
            return False
        finally:
            if writer:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
                except Exception:
                    pass


async def check_edt_async(ip, port, domain, timeout, sem):
    """两步验证：1) /admin 返回302跳转  2) /login 页含 EDT_KEYWORD(edgetunnel)。"""
    async with sem:
        # 第一步：访问 /admin，确认返回 301/302 跳转
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=domain),
                timeout=timeout,
            )
            req = (
                f"GET /admin HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(req.encode('latin1'))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            resp = data.decode('latin1', errors='ignore').lower()
            first_line = resp.split("\r\n", 1)[0]
            if not ("301" in first_line or "302" in first_line):
                return False
            if "login" not in resp:
                return False
        except Exception:
            return False
        finally:
            if writer:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
                except Exception:
                    pass

        # 第二步：访问 /login，验证页面含关键词(edgetunnel)
        writer2 = None
        try:
            reader2, writer2 = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=domain),
                timeout=timeout,
            )
            req2 = (
                f"GET /login HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer2.write(req2.encode('latin1'))
            await writer2.drain()
            data2 = b""
            while len(data2) < 65536:
                chunk = await asyncio.wait_for(reader2.read(8192), timeout=timeout)
                if not chunk:
                    break
                data2 += chunk
            body = data2.decode('latin1', errors='ignore').lower()
            if not EDT_KEYWORD:
                return True
            return EDT_KEYWORD.lower() in body
        except Exception:
            return False
        finally:
            if writer2:
                writer2.close()
                try:
                    await asyncio.wait_for(writer2.wait_closed(), timeout=0.5)
                except Exception:
                    pass


async def run_stage1(targets, sem):
    total = len(targets)
    completed = 0
    passed = []
    step = max(1, total // 10)
    last_step = 0

    print(f"\n[1/2 第一阶段 TLS 探测] 共 {total} 个目标...", flush=True)
    queue = asyncio.Queue()
    for item in targets:
        queue.put_nowait(item)

    async def worker():
        nonlocal completed, last_step
        while not queue.empty():
            try:
                ip, port = queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            ok = await check_tls_async(ip, port, CF_SNI_1, STAGE1_TIMEOUT, sem)
            completed += 1
            if ok:
                passed.append((ip, port))
            cur = completed // step
            if cur > last_step or completed == total:
                last_step = cur
                pct = completed / total * 100
                print(f"[1/2 进度] {completed}/{total} ({pct:.1f}%) | 通过: {len(passed)}", flush=True)
            queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(min(CONCURRENCY, total))]
    await asyncio.gather(*workers)
    return passed


async def main():
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    name_label = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_NAME
    ports_input = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_PORTS

    target_ports = parse_ports(ports_input)
    all_ips = parse_targets(target_input)
    if not all_ips:
        print("[-] 未获取到任何待测 IP，退出。", flush=True)
        return

    targets = [(ip, port) for ip in all_ips for port in target_ports]
    print(f"[*] {len(all_ips)} IP × {len(target_ports)} 端口 = {len(targets)} 个目标。端口: {target_ports}", flush=True)

    sem = asyncio.Semaphore(CONCURRENCY)

    pass_1 = await run_stage1(targets, sem)
    print(f"[+] 第一阶段完成！保留: {len(pass_1)} 个\n", flush=True)
    if not pass_1:
        print("[-] 无有效目标。", flush=True)
        return

    domain = CUSTOM_CF_DOMAIN.strip()
    print(f"[2/2 第二阶段 校验] 校验 {len(pass_1)} 个候选...", flush=True)
    tasks = [check_edt_async(ip, port, domain, STAGE_EDT_TIMEOUT, sem) for ip, port in pass_1]
    res = await asyncio.gather(*tasks)
    final_items = [pass_1[i] for i, ok in enumerate(res) if ok]
    print(f"[+] 第二阶段完成！有效目标: {len(final_items)} 个", flush=True)

    results = []
    for ip, port in final_items:
        country = get_country(ip)
        results.append((country, ip, port))
    results = sorted(set(results), key=lambda x: (x[0], ipaddress.ip_address(x[1]), x[2]))

    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"最终有效目标总数: {len(results)}", flush=True)

    output_filename = f"{name_label}.txt"
    with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
        for country, ip, port in results:
            f.write(f"{ip}:{port}#{country} {name_label}\n")

    print(f"\n[+] 结果已保存至：{output_filename}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())    
