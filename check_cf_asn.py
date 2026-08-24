import asyncio
import ssl
import sys
import os
import re
import time
import resource
import json
import ipaddress
import random
import socket
import urllib.parse
import urllib.request
from collections import Counter
from functools import lru_cache

import aiohttp
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
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "")
MASK_PORT_LOG = os.getenv("MASK_PORT_LOG", "0") == "1"

# ==================== 硬时间闸门 ====================
# 无论配额估得多离谱（吞吐骤降 / IP 暴增 / runner 变慢），进程都在这个
# 墙钟预算内优雅收尾，绝不被 GitHub 的 350 分钟上限强杀。
#   TCP 阶段跑到预算 70% 就停止扫剩余目标，用已探活结果继续
#   TLS 阶段跑到预算 95% 就停，写出已有结果
# 被截断而未完整覆盖的端口不会写进 scan_done_ports.txt，下轮自动优先补。
# 设为 0（默认）= 关闭闸门，行为与旧版完全一致。
SCAN_DEADLINE_MIN = float(os.getenv("SCAN_DEADLINE_MIN", "0"))
TCP_BUDGET_FRAC = float(os.getenv("TCP_BUDGET_FRAC", "0.70"))
TLS_BUDGET_FRAC = float(os.getenv("TLS_BUDGET_FRAC", "0.95"))

GEOIP_DB = "GeoLite2-Country.mmdb"

CF_SNI_1 = "www.cloudflare.com"
CF_HOST_TEST = "crypto.cloudflare.com"

ASN_FETCH_TIMEOUT = 15    # 大 ASN 的 prefix 列表 JSON 很大，超时给足

# ==================== 按 ASN 的策略档案 ====================
ASN_PROFILES = {
    "25820": {                       # IT7NET - IT7 Networks
        "name": "IT7",
        "tcp_stage": "off",
        "tls_conc": 200,
        "tls_retry": 0,
        "stage1_timeout": 2,
        "note": "DDoS防护商，有扫描检测；禁用TCP预筛，并用原版参数(200并发/2s/无重试)保证跑得完",
    },
}

# 阶段零：TCP 探活（默认值，可被策略档案或环境变量覆盖）
TCP_STAGE_ENABLED = True
TCP_CONCURRENCY = 2500
TCP_TIMEOUT = float(os.getenv("TCP_TIMEOUT", "3.0"))
TCP_RETRY = int(os.getenv("TCP_RETRY", "1"))
TCP_BATCH_MIN = 50000
TCP_BATCH_MAX = 500000

# 黑洞 IP 过滤：仅在端口数足够多时有意义
BLACKHOLE_MIN_PORTS = 10
BLACKHOLE_RATIO = 0.05
BLACKHOLE_MIN = 20

# 三阶段 TLS 校验
TLS_CONCURRENCY = 300
TLS_CHUNK = 20000
STAGE1_TIMEOUT = 3
STAGE2_TIMEOUT = 2.5
STAGE3_TIMEOUT = 2.5
TLS_RETRY = 1

# ==================== 第四阶段：自建 API 确认落地 ====================
CHECK_API = os.getenv("CHECK_API", "").strip()
API_CONCURRENCY = int(os.getenv("API_CONC", "20"))
API_TIMEOUT = 30
API_RETRY = 2

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

try:
    geo_reader = geoip2.database.Reader(GEOIP_DB)
except Exception:
    geo_reader = None


def apply_asn_profile(asn_clean):
    """按 ASN 套用策略档案。环境变量为 auto/空时交给档案，显式指定则覆盖档案。"""
    global TCP_STAGE_ENABLED, TCP_CONCURRENCY
    global TLS_CONCURRENCY, TLS_RETRY, STAGE1_TIMEOUT

    prof = ASN_PROFILES.get(asn_clean, {})
    if prof:
        print(f"[*] 命中 AS{asn_clean} 策略档案: {prof.get('note', '')}", flush=True)

    env_stage = os.getenv("TCP_STAGE", "auto").strip().lower()
    if env_stage in ("", "auto"):
        stage = prof.get("tcp_stage", "on")
        src = "策略档案" if "tcp_stage" in prof else "默认"
    else:
        stage, src = env_stage, "手动指定"
    TCP_STAGE_ENABLED = (stage != "off")

    env_tcp = os.getenv("TCP_CONC", "auto").strip().lower()
    if env_tcp.isdigit():
        TCP_CONCURRENCY = int(env_tcp)
    elif "tcp_conc" in prof:
        TCP_CONCURRENCY = int(prof["tcp_conc"])

    env_tls = os.getenv("TLS_CONC", "auto").strip().lower()
    if env_tls.isdigit():
        TLS_CONCURRENCY = int(env_tls)
    elif "tls_conc" in prof:
        TLS_CONCURRENCY = int(prof["tls_conc"])

    env_retry = os.getenv("TLS_RETRY", "auto").strip().lower()
    if env_retry.isdigit():
        TLS_RETRY = int(env_retry)
    elif "tls_retry" in prof:
        TLS_RETRY = int(prof["tls_retry"])

    env_s1 = os.getenv("STAGE1_TIMEOUT", "auto").strip().lower()
    try:
        STAGE1_TIMEOUT = float(env_s1)
    except ValueError:
        if "stage1_timeout" in prof:
            STAGE1_TIMEOUT = float(prof["stage1_timeout"])

    print(f"[*] 策略: TCP预筛={'启用' if TCP_STAGE_ENABLED else '禁用'}（{src}） | "
          f"并发 TCP={TCP_CONCURRENCY} TLS={TLS_CONCURRENCY} | "
          f"TLS重试={TLS_RETRY} 一阶段超时={STAGE1_TIMEOUT}s", flush=True)


def get_country(ip):
    if geo_reader is None:
        return "??"
    try:
        return geo_reader.country(ip).country.iso_code or "??"
    except Exception:
        return "??"


def pick_ports(port_str):
    if not port_str:
        return [443, 8443, 2053, 2083, 2096]
    ports = set()
    parts = re.split(r'[\s,]+', str(port_str).strip())
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


def _safe_filename(name):
    cleaned = re.sub(r'[^\w.-]', '_', name).strip('._')
    return cleaned or "RESULT"


@lru_cache(maxsize=32)
def get_ips_from_asn_sync(asn_clean):
    cidrs = []
    try:
        ripe_url = (f"https://stat.ripe.net/data/announced-prefixes/data.json"
                    f"?resource=AS{asn_clean}")
        req = urllib.request.Request(ripe_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=ASN_FETCH_TIMEOUT) as response:
            data = json.loads(response.read().decode())
            for p in data.get("data", {}).get("prefixes", []):
                prefix = p.get("prefix")
                if prefix and ":" not in prefix:
                    cidrs.append(prefix)
    except Exception as e:
        print(f"[!] RIPE 拉取失败({type(e).__name__})，尝试 bgpview...", flush=True)
    if not cidrs:
        try:
            bgp_url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
            req = urllib.request.Request(bgp_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=ASN_FETCH_TIMEOUT) as response:
                data = json.loads(response.read().decode())
                for p in data.get("data", {}).get("ipv4_prefixes", []):
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.append(prefix)
        except Exception as e:
            print(f"[-] bgpview 也失败: {type(e).__name__}", flush=True)
    if cidrs:
        print(f"[*] AS{asn_clean}: 拿到 {len(cidrs)} 个 IPv4 前缀", flush=True)
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
    before = len(all_ips)
    unique_ips = list(dict.fromkeys(all_ips))
    if len(unique_ips) < before:
        print(f"[*] IP 去重: {before:,} → {len(unique_ips):,}"
              f"（BGP 前缀重叠，省掉 {before - len(unique_ips):,} 个重复探测）",
              flush=True)
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


async def tcp_alive(ip, port, sem):
    async with sem:
        for attempt in range(TCP_RETRY + 1):
            writer = None
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=TCP_TIMEOUT)
                return (ip, port)
            except Exception:
                if attempt < TCP_RETRY:
                    await asyncio.sleep(0.5 + random.random())
                    continue
                return None
            finally:
                if writer:
                    writer.close()
                    try:
                        writer.transport.abort()
                    except Exception:
                        pass
        return None


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
                return None
            der_cert = ssl_obj.getpeercert(binary_form=True)
            if not der_cert:
                return None
            cert_str = der_cert.decode('latin1', errors='ignore').lower()
            return match_domain_in_cert(sni, cert_str)
        except Exception:
            return None
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
            req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
                   f"Connection: close\r\n\r\n")
            writer.write(req.encode('latin1'))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=timeout_val)
            if not data:
                return None
            resp = data.decode('latin1', errors='ignore').lower()
            return (("http/1.1 301" in resp or "http/1.1 302" in resp)
                    and ("location:" in resp))
        except Exception:
            return None
        finally:
            if writer:
                writer.close()
                try:
                    writer.transport.abort()
                except Exception:
                    pass


async def retry_check(fn, ip, port, arg, timeout_val, sem):
    for attempt in range(TLS_RETRY + 1):
        r = await fn(ip, port, arg, timeout_val, sem)
        if r is not None:
            return r
        if attempt < TLS_RETRY:
            await asyncio.sleep(0.5 + random.random())
    return False


async def api_verify(session, ip, port, sem):
    async with sem:
        url = f"{CHECK_API}?proxyip={urllib.parse.quote(f'{ip}:{port}')}"
        for attempt in range(API_RETRY + 1):
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=API_TIMEOUT)
                ) as resp:
                    if resp.status != 200:
                        if attempt < API_RETRY:
                            await asyncio.sleep(2 * (attempt + 1))
                            continue
                        return ("error", "??")
                    ctype = (resp.headers.get("content-type") or "").lower()
                    if "json" not in ctype:
                        if attempt < API_RETRY:
                            await asyncio.sleep(2 * (attempt + 1))
                            continue
                        return ("error", "??")
                    data = await resp.json(content_type=None)
            except Exception:
                if attempt < API_RETRY:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                return ("error", "??")

            if data.get("success") is True:
                country = "??"
                for fam in ("ipv4", "ipv6"):
                    try:
                        c = data["probe_results"][fam]["exit"]["country"]
                        if c:
                            country = c
                            break
                    except Exception:
                        continue
                return ("ok", country)
            return ("dead", "??")
        return ("error", "??")


async def gather_staged(items, make_coro, label, deadline_ts=None):
    """分块执行 + 进度打印。过 deadline_ts 就停止启动新块并返回 truncated=True。"""
    total = len(items)
    results = []
    truncated = False
    for i in range(0, total, TLS_CHUNK):
        if deadline_ts and time.monotonic() > deadline_ts:
            truncated = True
            print(f"  [{label}] 触及时间闸门，停止（已处理 {len(results):,}/{total:,}）",
                  flush=True)
            break
        part = items[i:i + TLS_CHUNK]
        res = await asyncio.gather(*[make_coro(ip, p) for ip, p in part])
        results.extend(res)
        if total > TLS_CHUNK:
            print(f"  [{label}] {min(i + TLS_CHUNK, total):,}/{total:,} | "
                  f"通过: {sum(1 for x in results if x):,}", flush=True)
    return results, truncated


def resolve_name(target_input, name_arg):
    if name_arg and name_arg.lower() != "auto":
        return _safe_filename(name_arg)
    first = target_input.strip().split(",")[0].strip()
    asn_clean = first.upper().replace("AS", "")
    if asn_clean.isdigit():
        prof_name = ASN_PROFILES.get(asn_clean, {}).get("name")
        if prof_name:
            print(f"[*] AS{asn_clean} 使用档案指定名字: {prof_name}", flush=True)
            return _safe_filename(prof_name)
        api_name = get_asn_name(asn_clean)
        simple = simplify_name(api_name)
        if simple:
            safe = _safe_filename(simple)
            if safe != simple:
                print(f"[*] 文件名净化: {simple} -> {safe}", flush=True)
            print(f"[*] 自动识别 AS{asn_clean} -> {safe} (原名: {api_name})", flush=True)
            return safe
        return f"AS{asn_clean}"
    return "RESULT"


async def main():
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    name_arg = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_NAME
    ports_input = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_PORTS
    if not CHECK_API:
        print("[-] CHECK_API 未配置，退出。", flush=True)
        with open("count.txt", "w", encoding="utf-8") as f:
            f.write("0")
        return

    name_label = resolve_name(target_input, name_arg)
    with open("name.txt", "w") as f:
        f.write(name_label)

    first_target = target_input.strip().split(",")[0].strip()
    apply_asn_profile(first_target.upper().replace("AS", ""))

    target_ports = pick_ports(ports_input)
    if MASK_PORT_LOG:
        print(f"[*] 本次使用端口数: {len(target_ports)}（已隐藏）", flush=True)
    else:
        print(f"[*] 本次使用端口({len(target_ports)}个): {target_ports}", flush=True)

    print(f"\n[*] 正在解析目标...", flush=True)
    all_ips = await parse_targets_async(target_input)

    # ---- 时间闸门基准 ----
    scan_start = time.monotonic()
    deadline_sec = SCAN_DEADLINE_MIN * 60 if SCAN_DEADLINE_MIN > 0 else None
    tcp_deadline = (scan_start + deadline_sec * TCP_BUDGET_FRAC) if deadline_sec else None
    tls_deadline = (scan_start + deadline_sec * TLS_BUDGET_FRAC) if deadline_sec else None
    if deadline_sec:
        print(f"[*] 时间闸门: 总预算 {SCAN_DEADLINE_MIN:.0f} 分钟"
              f"（TCP 到 {TCP_BUDGET_FRAC:.0%}={SCAN_DEADLINE_MIN*TCP_BUDGET_FRAC:.0f}min，"
              f"TLS 到 {TLS_BUDGET_FRAC:.0%}={SCAN_DEADLINE_MIN*TLS_BUDGET_FRAC:.0f}min）",
              flush=True)

    # 覆盖跟踪：默认全覆盖，TCP 被闸门截断时缩小为已完整探完的端口
    tcp_covered_ports = list(target_ports)
    pipeline_truncated = False   # TLS/API 阶段被截断 → 结果不完整，本轮不推进轮转
    tcp_metrics = {}

    def write_scan_artifacts():
        """写给 build_dmit_ports.py --finalize 和 yml Notify 用。
        仅在启用时间闸门时产出，避免污染其它 ASN 的手动扫描。
          scan_done_ports.txt = 本轮真正扫完、可推进轮转的端口
          scan_metrics.json   = TCP 实测吞吐，供 EMA 自校准
          scan_truncated.txt  = 1/0，本轮是否被闸门截断（Notify 读）"""
        if not deadline_sec:
            return
        try:
            dp = [] if pipeline_truncated else tcp_covered_ports
            with open("scan_done_ports.txt", "w", encoding="utf-8", newline="\n") as f:
                for p in dp:
                    f.write(f"{p}\n")
        except Exception:
            pass
        try:
            tcp_metrics["pipeline_truncated"] = pipeline_truncated
            with open("scan_metrics.json", "w", encoding="utf-8") as f:
                json.dump(tcp_metrics, f)
        except Exception:
            pass
        try:
            trunc = tcp_metrics.get("truncated") or pipeline_truncated
            with open("scan_truncated.txt", "w", encoding="utf-8") as f:
                f.write("1" if trunc else "0")
        except Exception:
            pass

    if not all_ips:
        with open("count.txt", "w") as f:
            f.write("0")
        write_scan_artifacts()
        print("[-] 未能获取到任何待测 IP，程序退出。", flush=True)
        return

    total = len(all_ips) * len(target_ports)
    tcp_batch = min(TCP_BATCH_MAX, max(TCP_BATCH_MIN, total // 20))

    print(f"[*] 引擎：uvloop={UVLOOP_ENABLED} | 单进程异步 | 名字={name_label}", flush=True)
    print(f"[*] {len(all_ips):,} IP × {len(target_ports)} 端口，"
          f"共 {total:,} 个目标", flush=True)

    # ==================== 阶段零：TCP 探活 ====================
    if TCP_STAGE_ENABLED:
        print(f"\n[0/4 阶段零 TCP 探活] 并发={TCP_CONCURRENCY} "
              f"超时={TCP_TIMEOUT}s 重试={TCP_RETRY}...", flush=True)
        tcp_sem = asyncio.Semaphore(TCP_CONCURRENCY)
        open_ports = []
        batch = []
        done = 0
        tcp_start = time.monotonic()

        async def flush_batch(b):
            nonlocal done
            res = await asyncio.gather(*[tcp_alive(ip, p, tcp_sem) for ip, p in b])
            open_ports.extend([r for r in res if r])
            done += len(b)
            print(f"  [探活] {done:,}/{total:,} | 开放: {len(open_ports):,}", flush=True)

        # 端口优先（外层端口、内层 IP）：每个端口连续贡献 len(all_ips) 个目标，
        # 所以被闸门截断时"已完整覆盖端口数 = done // len(all_ips)"精确成立。
        stop = False
        for port in target_ports:
            if stop:
                break
            for ip in all_ips:
                batch.append((ip, port))
                if len(batch) >= tcp_batch:
                    await flush_batch(batch)
                    batch = []
                    if tcp_deadline and time.monotonic() > tcp_deadline:
                        stop = True
                        break
        if batch and not stop:
            await flush_batch(batch)

        tcp_elapsed = max(1e-6, time.monotonic() - tcp_start)
        thr = done / (tcp_elapsed / 60.0)
        tcp_metrics = {
            "tcp_throughput_per_min": round(thr, 1),
            "tcp_targets": done,
            "tcp_seconds": round(tcp_elapsed, 1),
            "truncated": stop,
        }
        if stop:
            covered_n = done // max(1, len(all_ips))
            tcp_covered_ports = list(target_ports[:covered_n])
            print(f"[!] TCP 触及时间闸门：已完整覆盖 {covered_n}/{len(target_ports)} "
                  f"个端口，剩余下轮优先补扫", flush=True)
        print(f"[*] TCP 实测吞吐 {thr:,.0f} 目标/分钟"
              f"（{done:,} 个 / {tcp_elapsed / 60:.1f} 分钟）", flush=True)

        print(f"[+] 探活完成！开放: {len(open_ports):,} 个"
              f"（TLS 阶段工作量降至 {len(open_ports) / max(total, 1) * 100:.2f}%）",
              flush=True)

        if not open_ports:
            with open("count.txt", "w") as f:
                f.write("0")
            write_scan_artifacts()
            print("[-] 无开放端口。", flush=True)
            return

        if len(target_ports) > BLACKHOLE_MIN_PORTS:
            threshold = max(BLACKHOLE_MIN, int(len(target_ports) * BLACKHOLE_RATIO))
            ip_cnt = Counter(ip for ip, _ in open_ports)
            bad_ips = {ip for ip, c in ip_cnt.items() if c >= threshold}
            if bad_ips:
                before = len(open_ports)
                open_ports = [(ip, p) for ip, p in open_ports if ip not in bad_ips]
                print(f"[*] 剔除疑似黑洞 IP {len(bad_ips)} 个（单IP开放 ≥ {threshold}），"
                      f"开放数 {before:,} → {len(open_ports):,}", flush=True)
                for ip in sorted(bad_ips, key=lambda x: -ip_cnt[x])[:10]:
                    print(f"    x {ip} (开放 {ip_cnt[ip]} 个)", flush=True)
                if len(bad_ips) > 10:
                    print(f"    ... 另有 {len(bad_ips) - 10} 个", flush=True)
        else:
            print(f"[*] 端口数 {len(target_ports)} ≤ {BLACKHOLE_MIN_PORTS}，"
                  f"跳过黑洞IP过滤", flush=True)
    else:
        open_ports = [(ip, p) for p in target_ports for ip in all_ips]
        print(f"\n[0/4 阶段零] TCP预筛已禁用，"
              f"直接对全部 {len(open_ports):,} 个目标做 TLS", flush=True)

    tls_sem = asyncio.Semaphore(TLS_CONCURRENCY)

    # ==================== 第一阶段：CF 证书 ====================
    print(f"\n[1/4 第一阶段 TLS 探测] 校验 {len(open_ports):,} 个"
          f"（并发={TLS_CONCURRENCY} 超时={STAGE1_TIMEOUT}s 重试={TLS_RETRY}）...",
          flush=True)
    r1, t1 = await gather_staged(
        open_ports,
        lambda ip, p: retry_check(check_tls_sni_async, ip, p,
                                  CF_SNI_1, STAGE1_TIMEOUT, tls_sem),
        "第一阶段", tls_deadline)
    if t1:
        pipeline_truncated = True
    pass_1 = [open_ports[i] for i, ok in enumerate(r1) if ok]
    print(f"[+] 第一阶段完成！保留: {len(pass_1):,} 个\n", flush=True)
    if not pass_1:
        with open("count.txt", "w") as f:
            f.write("0")
        write_scan_artifacts()
        print("[-] 无有效目标通过第一阶段。", flush=True)
        return

    # ==================== 第二阶段：crypto 301 ====================
    print(f"[2/4 第二阶段 HTTP 校验] 校验 {len(pass_1):,} 个候选...", flush=True)
    r2, t2 = await gather_staged(
        pass_1,
        lambda ip, p: retry_check(check_http_async, ip, p,
                                  CF_HOST_TEST, STAGE2_TIMEOUT, tls_sem),
        "第二阶段", tls_deadline)
    if t2:
        pipeline_truncated = True
    pass_2 = [pass_1[i] for i, ok in enumerate(r2) if ok]
    print(f"[+] 第二阶段完成！保留: {len(pass_2):,} 个\n", flush=True)
    if not pass_2:
        with open("count.txt", "w") as f:
            f.write("0")
        write_scan_artifacts()
        print("[-] 无有效目标通过第二阶段。", flush=True)
        return

    # ==================== 第三阶段：自定义域名 ====================
    final_items = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[3/4 第三阶段自定义域名校验] 校验 {len(pass_2):,} 个...", flush=True)
        r3, t3 = await gather_staged(
            pass_2,
            lambda ip, p: retry_check(check_tls_sni_async, ip, p,
                                      domain, STAGE3_TIMEOUT, tls_sem),
            "第三阶段", tls_deadline)
        if t3:
            pipeline_truncated = True
        final_items = [pass_2[i] for i, ok in enumerate(r3) if ok]
        print(f"[+] 第三阶段完成！有效目标: {len(final_items):,} 个", flush=True)
    else:
        print("[3/4] 未检测到 CUSTOM_CF_DOMAIN，跳过。", flush=True)

    # ==================== 第四阶段：API 确认 + 拿真实落地 ====================
    api_results = []
    uniq = sorted(set(final_items),
                  key=lambda x: (ipaddress.ip_address(x[0]), x[1]))
    if final_items and CHECK_API and CHECK_API.strip():
        if tls_deadline and time.monotonic() > tls_deadline:
            pipeline_truncated = True
            print("[!] 触及时间闸门，跳过 API 确认，country 留 ?? 待 recheck", flush=True)
            api_results = [(ip, port, "??") for ip, port in uniq]
        else:
            print(f"\n[4/4 API 确认] 校验 {len(uniq)} 个"
                  f"（并发={API_CONCURRENCY} 超时={API_TIMEOUT}s 重试={API_RETRY}）...",
                  flush=True)
            api_sem = asyncio.Semaphore(API_CONCURRENCY)
            async with aiohttp.ClientSession() as session:
                a_res = await asyncio.gather(
                    *[api_verify(session, ip, p, api_sem) for ip, p in uniq]
                )
            ok_n = dead_n = err_n = 0
            for (ip, port), (st, country) in zip(uniq, a_res):
                if st == "ok":
                    api_results.append((ip, port, country))
                    ok_n += 1
                elif st == "error":
                    api_results.append((ip, port, "??"))
                    err_n += 1
                else:
                    dead_n += 1
            print(f"[+] API 确认: 通过 {ok_n} | 不通(丢弃) {dead_n} | "
                  f"异常(收录待复验) {err_n}", flush=True)
    else:
        api_results = [(ip, port, "??") for ip, port in uniq]
        print("[4/4] 未配置 CHECK_API，country 留 ?? 待 recheck 填。", flush=True)

    # ==================== 结果输出（追加去重 + 防覆盖保护） ====================
    output_filename = f"{name_label}.txt"

    if not api_results:
        with open("count.txt", "w") as f:
            f.write("0")
        write_scan_artifacts()
        print("\n==================== 扫描结束 ====================", flush=True)
        print("[!] 本次无有效结果，跳过写文件，不覆盖已有结果。", flush=True)
        return

    old_lines = set()
    try:
        with open(output_filename, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s:
                    old_lines.add(s)
    except FileNotFoundError:
        pass

    old_count = len(old_lines)

    new_count = 0
    for ip, port, country in api_results:
        line = f"{ip}:{port}#{country} {name_label}"
        if line not in old_lines:
            new_count += 1
        old_lines.add(line)

    def sort_key(line):
        try:
            addr = line.split("#")[0]
            ip_part, port_part = addr.rsplit(":", 1)
            country = line.split("#")[1].split()[0] if "#" in line else "??"
            return (country, ipaddress.ip_address(ip_part), int(port_part))
        except Exception:
            return ("??", ipaddress.ip_address("0.0.0.0"), 0)

    sorted_lines = sorted(old_lines, key=sort_key)

    if old_count > 20 and len(sorted_lines) < old_count * 0.5:
        print(f"[!] 合并后结果({len(sorted_lines)})远少于原有({old_count})，"
              f"疑似读取异常，不覆盖！", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        write_scan_artifacts()
        return

    with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
        for line in sorted_lines:
            f.write(line + "\n")

    with open("count.txt", "w") as f:
        f.write(str(new_count))

    write_scan_artifacts()

    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"本次新增: {new_count} 个 | 文件累计: {len(sorted_lines)} 个", flush=True)
    if pipeline_truncated:
        print("[!] 本轮被时间闸门截断，端口未标记已扫，下轮优先补扫", flush=True)
    print(f"[+] 结果已保存（追加去重，详见私库）", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
