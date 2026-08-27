#!/usr/bin/env python3
"""
masscan 探活 + asyncio 三阶段 TLS + API 确认。

以手动腾讯脚本 check_cf_asn_masscan.py 的探活逻辑为蓝本（保证与已验证
的实现一致），额外加了自动流程需要的三样，全部由环境变量控制：
  - 硬时间闸门 SCAN_DEADLINE_MIN：masscan 到预算 70% terminate（整轮作废），
    TLS 到 95% 停，绝不被 GitHub 350 分钟上限强杀
  - metrics 输出：masscan 实测吞吐，供 build_dmit_ports.py EMA 自校准配额
  - 覆盖跟踪：整轮成功=选中端口全标记已扫；截断=不标记，下轮重扫（不漏）
不设 SCAN_DEADLINE_MIN 时闸门关闭，可当普通 masscan 脚本用。

目标/名字/端口全由 argv 传入，实现是通用的（文件名带 dmit 只是历史原因），
DMIT / xTom / 长尾等多条线共用本脚本。第一个参数支持逗号分隔多 ASN 或 CIDR。

单文件 vs 分文件输出：
  不设 ASN_NAMES → 全部结果写 {argv[2]}.txt，标签统一。DMIT、xTom 用这个，
      因为一条线内的多个 ASN 属于同一家服务商。
  设了 ASN_NAMES → 按 IP 归属的服务商分组，各写 {服务商名}.txt，标签用各自
      的名字。长尾线用这个，一条线内是十几家不同服务商。
      格式 ASN_NAMES="61112=AkileCloud,967=VMISS,400464=VMISS"，
      多个 ASN 可映射到同一名字（同服务商的多个 ASN 合并成一个文件）；
      未列出的 ASN 兜底用 AS{num}.txt。

日志不输出任何 IP：本仓库公开，Actions 日志虽不进代码搜索索引但登录可见。
结果只写入文件、推送私库。
"""
import asyncio
import bisect
import ssl
import sys
import os
import re
import time
import json
import ipaddress
import random
import socket
import resource
import threading
import subprocess
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from functools import lru_cache

import aiohttp


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


optimize_system_limits()

try:
    import uvloop
    uvloop.install()
    UVLOOP_ENABLED = True
except ImportError:
    UVLOOP_ENABLED = False

# ==================== 配置 ====================
DEFAULT_TARGET = os.getenv("ASN_LIST", "906")
DEFAULT_NAME = os.getenv("NAME_LABEL", "DMIT")
DEFAULT_PORTS = os.getenv("PORTS", "443,8443,2053,2083,2096")
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "")
MASK_PORT_LOG = os.getenv("MASK_PORT_LOG", "0") == "1"
ASN_NAMES_RAW = os.getenv("ASN_NAMES", "").strip()

TMP_DIR = ".tmp"
TARGETS_FILE = os.path.join(TMP_DIR, "targets.txt")
MASSCAN_OUT = os.path.join(TMP_DIR, "masscan_out.json")
OUT_FILES_LIST = "scan_out_files.txt"

CF_SNI_1 = "www.cloudflare.com"
CF_HOST_TEST = "crypto.cloudflare.com"
ASN_FETCH_TIMEOUT = 20

# ==================== 硬时间闸门 ====================
SCAN_DEADLINE_MIN = float(os.getenv("SCAN_DEADLINE_MIN", "0"))
TCP_BUDGET_FRAC = float(os.getenv("TCP_BUDGET_FRAC", "0.70"))
TLS_BUDGET_FRAC = float(os.getenv("TLS_BUDGET_FRAC", "0.95"))

# ==================== masscan 探活参数 ====================
# 实测（AS132203 双端口 424万目标）：masscan 5000pps 48m vs asyncio 3h05m，
# 开放数几乎一致（188,971 vs 188,731）。retries 用于"确保不漏"而非"多捞"：
# 每目标发 1+retries 个 SYN，漏检概率降到 p^(1+retries)。
MASSCAN_RATE = int(os.getenv("MASSCAN_RATE", "5000"))
MASSCAN_RETRIES = int(os.getenv("MASSCAN_RETRIES", "2"))
MASSCAN_WAIT = int(os.getenv("MASSCAN_WAIT", "5"))

# ==================== 三阶段 TLS 校验 ====================
TLS_CONCURRENCY = int(os.getenv("TLS_CONC", "300"))
TLS_CHUNK = 20000
STAGE1_TIMEOUT = 3
STAGE2_TIMEOUT = 2.5
STAGE3_TIMEOUT = 2.5
TLS_RETRY = int(os.getenv("TLS_RETRY", "1"))

# ==================== 第四阶段：自建 API 确认落地 ====================
CHECK_API = os.getenv("CHECK_API", "").strip()
API_CONCURRENCY = int(os.getenv("API_CONC", "20"))
API_TIMEOUT = 30
API_RETRY = 2

# 黑洞 IP 过滤
BLACKHOLE_MIN_PORTS = 10
BLACKHOLE_RATIO = 0.05
BLACKHOLE_MIN = 20

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3


def _safe_filename(name):
    cleaned = re.sub(r'[^\w.-]', '_', name).strip('._')
    return cleaned or "RESULT"


def parse_asn_names(raw):
    """解析 ASN_NAMES="61112=AkileCloud,967=VMISS" → {"61112": "AkileCloud", ...}

    允许多个 ASN 指向同一名字（同服务商多 ASN 合并输出）。
    """
    mapping = {}
    for item in re.split(r'[,\n]+', raw or ""):
        item = item.strip()
        if not item or "=" not in item:
            continue
        k, v = item.split("=", 1)
        k = k.strip().upper().replace("AS", "")
        v = _safe_filename(v.strip())
        if k.isdigit() and v:
            mapping[k] = v
    return mapping


def pick_ports(port_str):
    if not port_str:
        return [443]
    ports = set()
    for part in re.split(r'[\s,]+', str(port_str).strip()):
        if not part:
            continue
        if '-' in part:
            try:
                a, b = part.split('-')
                s, e = max(1, int(a)), min(65535, int(b))
                if s <= e:
                    ports.update(range(s, e + 1))
            except ValueError:
                continue
        elif part.isdigit():
            v = int(part)
            if 1 <= v <= 65535:
                ports.add(v)
    return sorted(ports) if ports else [443]


@lru_cache(maxsize=256)
def get_asn_prefixes(asn_clean):
    cidrs = []
    try:
        url = (f"https://stat.ripe.net/data/announced-prefixes/data.json"
               f"?resource=AS{asn_clean}")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=ASN_FETCH_TIMEOUT) as r:
            data = json.loads(r.read().decode())
            for p in data.get("data", {}).get("prefixes", []):
                prefix = p.get("prefix")
                if prefix and ":" not in prefix:
                    cidrs.append(prefix)
    except Exception as e:
        print(f"[!] AS{asn_clean} RIPE 失败({type(e).__name__})，尝试 bgpview...",
              flush=True)

    if not cidrs:
        try:
            url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=ASN_FETCH_TIMEOUT) as r:
                data = json.loads(r.read().decode())
                for p in data.get("data", {}).get("ipv4_prefixes", []):
                    if p.get("prefix"):
                        cidrs.append(p["prefix"])
        except Exception as e:
            print(f"[-] AS{asn_clean} bgpview 也失败: {type(e).__name__}", flush=True)

    if cidrs:
        print(f"[*] AS{asn_clean}: 拿到 {len(cidrs)} 个 IPv4 前缀", flush=True)
    return cidrs


def build_targets_file(target_input):
    """写 masscan 目标文件，同时建 IP→ASN 反查表。

    两份数据用途不同：
      给 masscan 的段做全局 collapse（跨 ASN 合并重叠，扫得最省）
      反查表按 ASN 各自 collapse（不跨 ASN 合并，否则归属就丢了）
    返回 (段数, 总IP数, 反查表)。反查表为 (起点列表, 区间列表)，供 bisect 用。
    """
    os.makedirs(TMP_DIR, exist_ok=True)
    by_asn = defaultdict(list)      # asn(str) -> [network]
    plain_nets = []                 # 直接给的 CIDR，无 ASN 归属

    for item in re.split(r'[\s,]+', str(target_input).strip()):
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
            if net.version == 4:
                plain_nets.append(net)
            continue
        except ValueError:
            pass
        asn = item.upper().replace("AS", "").strip()
        if not asn.isdigit():
            continue
        for c in get_asn_prefixes(asn):
            try:
                n = ipaddress.ip_network(c, strict=False)
                if n.version == 4:
                    by_asn[asn].append(n)
            except ValueError:
                continue

    all_nets = list(plain_nets)
    for v in by_asn.values():
        all_nets.extend(v)
    if not all_nets:
        return 0, 0, None

    # ---- 写给 masscan：全局 collapse ----
    before = len(all_nets)
    collapsed = sorted(ipaddress.collapse_addresses(all_nets))
    total_ips = sum(n.num_addresses for n in collapsed)
    if len(collapsed) < before:
        print(f"[*] 段合并去重: {before} → {len(collapsed)} 段", flush=True)

    with open(TARGETS_FILE, "w", encoding="utf-8", newline="\n") as f:
        for n in collapsed:
            f.write(str(n) + "\n")

    # ---- 反查表：ASN 内部 collapse，不跨 ASN ----
    ranges = []
    for asn, nets in by_asn.items():
        for n in ipaddress.collapse_addresses(nets):
            ranges.append((int(n.network_address), int(n.broadcast_address), asn))
    ranges.sort()
    starts = [r[0] for r in ranges]
    lookup = (starts, ranges) if ranges else None

    return len(collapsed), total_ips, lookup


def asn_of_ip(ip, lookup):
    """反查 IP 属于哪个 ASN。查不到返回 None。

    不跨 ASN collapse 后可能存在嵌套段（A 宣告 /16、B 宣告其中一个 /24），
    bisect 命中的那个未必包含 v，需继续往前找更大的包含段。段数只有几千、
    待查 IP 只有几百个，不做剪枝直接走到底也是毫秒级，换取正确性。
    """
    if not lookup:
        return None
    starts, ranges = lookup
    v = int(ipaddress.ip_address(ip))
    i = bisect.bisect_right(starts, v) - 1
    while i >= 0:
        s, e, asn = ranges[i]
        if v <= e:
            return asn
        i -= 1
    return None


def run_masscan(ports, deadline_ts=None):
    """调 masscan 探活。deadline_ts 到点则 terminate（整轮作废）。
    返回 (targets, truncated, last_pct)。"""
    port_arg = ",".join(str(p) for p in ports)
    cmd = [
        "sudo", "masscan",
        "-iL", TARGETS_FILE,
        "-p", port_arg,
        "--rate", str(MASSCAN_RATE),
        "--retries", str(MASSCAN_RETRIES),
        "--wait", str(MASSCAN_WAIT),
        "-oJ", MASSCAN_OUT,
    ]
    print(f"[*] masscan: rate={MASSCAN_RATE}pps retries={MASSCAN_RETRIES} "
          f"wait={MASSCAN_WAIT}s", flush=True)

    pattern = re.compile(r'([\d.]+)%\s+done.*?found=(\d+)')
    rate_pattern = re.compile(r'rate:\s*([\d.]+)-?k?pps', re.IGNORECASE)
    # masscan 的错误行可能带目标 IP，日志里只保留类型不回显原文
    ip_like = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
    state = {"last_ms": -1, "last_pct": 0.0}

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
    except FileNotFoundError:
        print("[-] 找不到 masscan，请先 apt-get install masscan", flush=True)
        return None, False, 0.0

    def reader():
        for line in proc.stdout:
            m = pattern.search(line)
            if m:
                pct = float(m.group(1))
                state["last_pct"] = pct
                found = m.group(2)
                ms = int(pct // 5) * 5
                if ms > state["last_ms"]:
                    state["last_ms"] = ms
                    rm = rate_pattern.search(line)
                    rate_str = f" | 实际速率≈{rm.group(1)}kpps" if rm else ""
                    print(f"  [masscan] {ms}% | 开放: {found}{rate_str}", flush=True)
            elif "FAIL" in line or "error" in line.lower():
                safe = ip_like.sub("<ip>", line.rstrip())
                print(f"  [masscan] {safe}", flush=True)

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    truncated = False
    while True:
        rc = proc.poll()
        if rc is not None:
            break
        if deadline_ts and time.monotonic() > deadline_ts:
            print("[!] masscan 触及时间闸门，终止本轮（整轮作废，端口不标记已扫）",
                  flush=True)
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
            truncated = True
            break
        time.sleep(2)

    t.join(timeout=5)
    if not truncated and proc.returncode not in (0, None):
        print(f"[!] masscan 退出码 {proc.returncode}（可能部分完成，继续读结果）",
              flush=True)

    return load_masscan_result(), truncated, state["last_pct"]


def load_masscan_result():
    if not os.path.exists(MASSCAN_OUT):
        print(f"[-] 找不到 {MASSCAN_OUT}", flush=True)
        return []

    targets = []
    try:
        with open(MASSCAN_OUT, encoding="utf-8") as f:
            content = f.read().strip()
        if not content:
            return []
        if content.endswith(","):
            content = content[:-1]
        if not content.startswith("["):
            content = "[" + content
        if not content.endswith("]"):
            content += "]"
        for item in json.loads(content):
            ip = item.get("ip")
            for p in item.get("ports", []):
                port = p.get("port")
                if ip and port and p.get("status", "open") == "open":
                    targets.append((ip, int(port)))
    except Exception as e:
        print(f"[-] 解析 masscan 输出失败: {type(e).__name__}: {e}", flush=True)
        return []

    before = len(targets)
    targets = list(dict.fromkeys(targets))
    if len(targets) < before:
        print(f"[*] masscan 结果去重: {before} → {len(targets)}", flush=True)
    return targets


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


def load_old_lines(path):
    lines = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s:
                    lines.add(s)
    except FileNotFoundError:
        pass
    return lines


def filter_blackhole(open_ports, port_total):
    """剔除单 IP 开放端口数异常多的目标 —— 那是防护设备的假开放，
    不是真服务。日志只给统计分布，不输出 IP。"""
    if port_total <= BLACKHOLE_MIN_PORTS:
        print(f"[*] 端口数 {port_total} ≤ {BLACKHOLE_MIN_PORTS}，"
              f"跳过黑洞IP过滤", flush=True)
        return open_ports

    threshold = max(BLACKHOLE_MIN, int(port_total * BLACKHOLE_RATIO))
    ip_cnt = Counter(ip for ip, _ in open_ports)
    bad = {ip: c for ip, c in ip_cnt.items() if c >= threshold}
    if not bad:
        print(f"[*] 黑洞IP过滤：无 IP 达到阈值（单IP开放 ≥ {threshold}）", flush=True)
        return open_ports

    before = len(open_ports)
    kept = [(ip, p) for ip, p in open_ports if ip not in bad]
    counts = sorted(bad.values(), reverse=True)
    mid = counts[len(counts) // 2]
    print(f"[*] 剔除疑似黑洞 IP {len(bad)} 个（单IP开放 ≥ {threshold}），"
          f"开放数 {before:,} → {len(kept):,}", flush=True)
    print(f"    开放端口数分布: 最高 {counts[0]} / 中位 {mid} / 最低 {counts[-1]}"
          f"（共剔除 {before - len(kept):,} 条候选）", flush=True)
    return kept


def sort_key(line):
    try:
        addr = line.split("#")[0]
        ip_part, port_part = addr.rsplit(":", 1)
        country = line.split("#")[1].split()[0] if "#" in line else "??"
        return (country, ipaddress.ip_address(ip_part), int(port_part))
    except Exception:
        return ("??", ipaddress.ip_address("0.0.0.0"), 0)


def write_result_file(fname, label, entries):
    """追加去重写入单个结果文件，带防覆盖保护。

    返回新增条数；触发防覆盖保护时返回 None（不写文件）。
    注意：依赖 fname 在本地已存在（workflow 必须先从私库拉下来），
    否则 old_count=0，保护不触发，会用只含本轮结果的文件覆盖历史累积。
    """
    old_lines = load_old_lines(fname)
    old_count = len(old_lines)

    new_count = 0
    for ip, port, country in entries:
        line = f"{ip}:{port}#{country} {label}"
        if line not in old_lines:
            new_count += 1
        old_lines.add(line)

    sorted_lines = sorted(old_lines, key=sort_key)
    if old_count > 20 and len(sorted_lines) < old_count * 0.5:
        print(f"[!] {fname} 合并后({len(sorted_lines)})远少于原有({old_count})，"
              f"疑似读取异常，不覆盖！", flush=True)
        return None

    with open(fname, "w", encoding="utf-8", newline="\n") as f:
        for line in sorted_lines:
            f.write(line + "\n")
    return new_count


async def main():
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    name_arg = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_NAME
    ports_input = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_PORTS
    if not CHECK_API:
        print("[-] CHECK_API 未配置，退出。", flush=True)
        with open("count.txt", "w", encoding="utf-8") as f:
            f.write("0")
        return

    asn_names = parse_asn_names(ASN_NAMES_RAW)
    split_mode = bool(asn_names)

    name_label = _safe_filename(name_arg)
    with open("name.txt", "w", encoding="utf-8") as f:
        f.write(name_label)

    target_ports = pick_ports(ports_input)
    print(f"[*] 引擎：uvloop={UVLOOP_ENABLED} | masscan探活 + asyncio三阶段 + API确认",
          flush=True)
    if split_mode:
        uniq_labels = sorted(set(asn_names.values()))
        print(f"[*] 输出：按服务商分文件 | {len(asn_names)} 个 ASN → "
              f"{len(uniq_labels)} 个文件", flush=True)
    else:
        print(f"[*] 输出：单文件 {name_label}.txt", flush=True)
    if MASK_PORT_LOG:
        print(f"[*] 端口数: {len(target_ports)}（已隐藏）", flush=True)
    else:
        print(f"[*] 端口({len(target_ports)}个): {target_ports}", flush=True)

    # ---- 时间闸门基准 ----
    scan_start = time.monotonic()
    deadline_sec = SCAN_DEADLINE_MIN * 60 if SCAN_DEADLINE_MIN > 0 else None
    masscan_deadline = (scan_start + deadline_sec * TCP_BUDGET_FRAC) if deadline_sec else None
    tls_deadline = (scan_start + deadline_sec * TLS_BUDGET_FRAC) if deadline_sec else None
    if deadline_sec:
        print(f"[*] 时间闸门: 总预算 {SCAN_DEADLINE_MIN:.0f} 分钟"
              f"（masscan 到 {TCP_BUDGET_FRAC:.0%}，TLS 到 {TLS_BUDGET_FRAC:.0%}）",
              flush=True)

    pipeline_truncated = False
    scan_metrics = {}

    def write_scan_artifacts():
        """仅在启用时间闸门时产出。整轮成功=全部端口，截断=空。"""
        if not deadline_sec:
            return
        try:
            dp = [] if pipeline_truncated else list(target_ports)
            with open("scan_done_ports.txt", "w", encoding="utf-8", newline="\n") as f:
                for p in dp:
                    f.write(f"{p}\n")
        except Exception:
            pass
        try:
            scan_metrics["pipeline_truncated"] = pipeline_truncated
            with open("scan_metrics.json", "w", encoding="utf-8") as f:
                json.dump(scan_metrics, f)
        except Exception:
            pass
        try:
            with open("scan_truncated.txt", "w", encoding="utf-8") as f:
                f.write("1" if pipeline_truncated else "0")
        except Exception:
            pass

    def bail(reason=None):
        """无结果时统一收尾：count 归零、产出文件清单置空、写闸门产物。"""
        if reason:
            print(reason, flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        with open(OUT_FILES_LIST, "w", encoding="utf-8") as f:
            pass
        write_scan_artifacts()

    # ==================== 阶段零：masscan 探活 ====================
    print(f"\n[*] 解析目标...", flush=True)
    seg_count, total_ips, lookup = build_targets_file(target_input)
    if not seg_count:
        bail("[-] 未解析到任何 IPv4 目标。")
        return
    if split_mode and not lookup:
        bail("[-] ASN_NAMES 已设置但未能建立 IP→ASN 映射（目标里没有 ASN？）")
        return

    total_scans = total_ips * len(target_ports)
    print(f"[+] {seg_count} 段 | {total_ips:,} IP × {len(target_ports)} 端口 "
          f"= {total_scans:,} 次探测", flush=True)
    eta = total_scans * (1 + MASSCAN_RETRIES) / max(MASSCAN_RATE, 1) / 60
    print(f"[*] masscan 预估约 {eta:.0f} 分钟（含 {MASSCAN_RETRIES} 次重传）",
          flush=True)

    print(f"\n[0/4 阶段零 masscan 探活]", flush=True)
    masscan_start = time.monotonic()
    open_ports, mtrunc, last_pct = run_masscan(target_ports, masscan_deadline)
    masscan_elapsed = max(1e-6, time.monotonic() - masscan_start)

    if mtrunc:
        pipeline_truncated = True

    done_scans = total_scans * (last_pct / 100.0 if last_pct > 0 else 1.0)
    thr = done_scans / (masscan_elapsed / 60.0)
    scan_metrics = {
        "tcp_throughput_per_min": round(thr, 1),
        "tcp_targets": int(done_scans),
        "tcp_seconds": round(masscan_elapsed, 1),
        "truncated": mtrunc,
    }
    print(f"[*] masscan 实测吞吐 {thr:,.0f} 目标/分钟"
          f"（{int(done_scans):,} 次 / {masscan_elapsed / 60:.1f} 分钟）", flush=True)

    if open_ports is None:
        bail("[-] masscan 未能运行，退出。")
        return
    if not open_ports:
        bail("[-] 无开放端口。")
        return

    print(f"[+] 探活完成！开放: {len(open_ports):,} 个"
          f"（TLS 阶段工作量降至 {len(open_ports)/max(total_scans,1)*100:.2f}%）",
          flush=True)

    open_ports = filter_blackhole(open_ports, len(target_ports))

    random.shuffle(open_ports)
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
        bail("[-] 无有效目标通过第一阶段。")
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
        bail("[-] 无有效目标通过第二阶段。")
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

    # ==================== 第四阶段：API 确认 ====================
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

    if not api_results:
        print("\n==================== 扫描结束 ====================", flush=True)
        bail("[!] API 确认后无有效结果，不覆盖已有文件。")
        return

    # ==================== 结果输出 ====================
    total_new = 0
    out_files = []

    if not split_mode:
        fname = f"{name_label}.txt"
        n = write_result_file(fname, name_label, api_results)
        if n is None:
            bail()      # 防覆盖保护已打印原因
            return
        total_new = n
        out_files.append(fname)
        print("\n==================== 扫描结束 ====================", flush=True)
        print(f"本次新增: {total_new} 个", flush=True)
    else:
        # 按服务商标签分组（不是按 ASN）：多个 ASN 可映射到同一个名字，
        # 比如 AS967 和 AS400464 都是 VMISS，合并写一个文件
        groups = defaultdict(list)
        label_asns = defaultdict(set)
        unmapped = 0
        for ip, port, country in api_results:
            asn = asn_of_ip(ip, lookup)
            if asn is None:
                unmapped += 1
                label = "_UNKNOWN"
            else:
                label = asn_names.get(asn, f"AS{asn}")
                label_asns[label].add(asn)
            groups[label].append((ip, port, country))

        print("\n==================== 扫描结束 ====================", flush=True)
        print(f"[*] 结果分属 {len(groups)} 个服务商", flush=True)
        if unmapped:
            # 理论上不该出现：masscan 的目标全部来自这些 ASN 的前缀
            print(f"[!] {unmapped} 条未能归属到 ASN，已写入 _UNKNOWN.txt 待查",
                  flush=True)

        for label in sorted(groups, key=lambda l: -len(groups[l])):
            fname = f"{label}.txt"
            n = write_result_file(fname, label, groups[label])
            if n is None:
                continue
            total_new += n
            out_files.append(fname)
            asns = label_asns.get(label)
            src = f" (AS{'+AS'.join(sorted(asns))})" if asns and len(asns) > 1 else ""
            print(f"      {label:<22} 本轮 {len(groups[label]):>4} 条 | "
                  f"新增 {n:>4}{src}", flush=True)

        print(f"[+] 合计新增: {total_new} 个 | 产出 {len(out_files)} 个文件",
              flush=True)

    with open("count.txt", "w") as f:
        f.write(str(total_new))
    with open(OUT_FILES_LIST, "w", encoding="utf-8", newline="\n") as f:
        for fn in out_files:
            f.write(fn + "\n")

    write_scan_artifacts()

    if pipeline_truncated:
        print("[!] 本轮被时间闸门截断，端口未标记已扫，下轮重扫", flush=True)
    print(f"[+] 结果已保存（追加去重，详见私库）", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
