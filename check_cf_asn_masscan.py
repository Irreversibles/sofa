import asyncio
import ssl
import sys
import os
import re
import json
import ipaddress
import random
import socket
import resource
import subprocess
import urllib.parse
import urllib.request
from collections import Counter
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
DEFAULT_TARGET = os.getenv("ASN_LIST", "132203")
DEFAULT_NAME = os.getenv("NAME_LABEL", "Tencent")
DEFAULT_PORTS = os.getenv("PORTS", "443,8443")
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "")

TMP_DIR = ".tmp"
TARGETS_FILE = os.path.join(TMP_DIR, "targets.txt")
MASSCAN_OUT = os.path.join(TMP_DIR, "masscan_out.json")

CF_SNI_1 = "www.cloudflare.com"
CF_HOST_TEST = "crypto.cloudflare.com"
ASN_FETCH_TIMEOUT = 20

# ==================== masscan 探活参数 ====================
# 无状态 SYN 扫描：不建连接、不等回应，速度只受 pps 限制，比 asyncio 快一倍多。
# 实测对比（AS132203 双端口 424万目标）：
#   asyncio 2500并发 → 开放188,731 一阶段5,713 有效214，耗时 3h05m
#   masscan 5000pps  → 开放188,971 一阶段5,738 有效218，耗时 48m
# 准确度等价，速度快 74%。retries 的作用是"确保不漏"而非"多捞"。
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
# 三阶段只证明"TLS 能透传到 CF 边缘"，不证明"能作为 proxyip 转发"。
# 这一步用自建 Worker 实测转发并拿真实落地国家 —— GeoIP 给的是 IP 注册地，
# 与落地常不一致（云厂商尤其明显），所以 country 只认这里的结果。
CHECK_API = os.getenv("CHECK_API", "").strip()
API_CONCURRENCY = int(os.getenv("API_CONC", "20"))
API_TIMEOUT = 30
API_RETRY = 2

# 黑洞 IP 过滤：端口数太少时无法区分"全开"是异常还是正常，自动跳过
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


def pick_ports(port_str):
    """解析端口：支持 '443,8443'、'443 8443'、'20000-20100' 区间"""
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


@lru_cache(maxsize=64)
def get_asn_prefixes(asn_clean):
    """单个 ASN 的 IPv4 前缀，RIPE 优先、bgpview 兜底"""
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
    """把 ASN / CIDR / 单IP 混合输入解析成 CIDR 列表写文件。

    masscan 直接吃 CIDR，不用像 asyncio 版那样把几百万 IP 展开成字符串列表 ——
    这本身就省掉了大量内存和启动时间。
    """
    os.makedirs(TMP_DIR, exist_ok=True)
    nets = []
    for item in re.split(r'[\s,]+', str(target_input).strip()):
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
            if net.version == 4:
                nets.append(net)
            continue
        except ValueError:
            pass
        asn = item.upper().replace("AS", "").strip()
        if asn.isdigit():
            for c in get_asn_prefixes(asn):
                try:
                    n = ipaddress.ip_network(c, strict=False)
                    if n.version == 4:
                        nets.append(n)
                except ValueError:
                    continue

    if not nets:
        return [], 0

    # collapse 合并重叠/相邻段，避免同一 IP 被扫两遍
    before = len(nets)
    collapsed = sorted(ipaddress.collapse_addresses(nets))
    total_ips = sum(n.num_addresses for n in collapsed)
    if len(collapsed) < before:
        print(f"[*] 段合并去重: {before} → {len(collapsed)} 段", flush=True)

    with open(TARGETS_FILE, "w", encoding="utf-8", newline="\n") as f:
        for n in collapsed:
            f.write(str(n) + "\n")

    return collapsed, total_ips


def run_masscan(ports):
    """调 masscan 探活，边跑边打印进度，返回 [(ip, port)]"""
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
    print(f"    {' '.join(cmd)}", flush=True)

    pattern = re.compile(r'([\d.]+)%\s+done.*?found=(\d+)')
    last_ms = -1
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
    except FileNotFoundError:
        print("[-] 找不到 masscan，请先 apt-get install masscan", flush=True)
        return None

    for line in proc.stdout:
        m = pattern.search(line)
        if m:
            pct = float(m.group(1))
            found = m.group(2)
            ms = int(pct // 5) * 5
            if ms > last_ms:
                last_ms = ms
                print(f"  [masscan] {ms}% | 开放: {found}", flush=True)
        elif "FAIL" in line or "error" in line.lower():
            print(f"  [masscan] {line.rstrip()}", flush=True)

    rc = proc.wait()
    if rc != 0:
        print(f"[!] masscan 退出码 {rc}（可能部分完成，继续尝试读结果）", flush=True)

    return load_masscan_result()


def load_masscan_result():
    """解析 masscan -oJ 输出。它的 JSON 可能缺尾括号或多逗号，需容错。"""
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
                # masscan 也会记录 closed（收到 RST），只取 open
                if ip and port and p.get("status", "open") == "open":
                    targets.append((ip, int(port)))
    except Exception as e:
        print(f"[-] 解析 masscan 输出失败: {type(e).__name__}: {e}", flush=True)
        return []

    # masscan 对同一目标的多次响应会重复输出，实测 20万条里约 1.2万重复
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
    """True=证书匹配 / False=明确不匹配 / None=握手未完成（可重试）"""
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
    """True=拿到301/302 / False=拿到响应但不符 / None=没拿到响应（可重试）"""
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
    """三态重试：None（握手未完成）才重试，False（明确不符）立即返回"""
    for attempt in range(TLS_RETRY + 1):
        r = await fn(ip, port, arg, timeout_val, sem)
        if r is not None:
            return r
        if attempt < TLS_RETRY:
            await asyncio.sleep(0.5 + random.random())
    return False


async def api_verify(session, ip, port, sem):
    """自建 API 确认转发能力 + 拿真实落地国家。

    返回 ("ok", country) / ("dead", "??") / ("error", "??")
    关键：区分"API 明确说不通"和"API 自己没答上来"。后者归 error，
    不当作失效 —— 否则 API 抖一下就会丢掉好货。
    """
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
                        # CF 错误页（1027 超额 / 1102 超限）是 text/html
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


async def gather_staged(items, make_coro, label):
    """分块执行 + 进度打印，避免大批量时日志长时间静默"""
    total = len(items)
    results = []
    for i in range(0, total, TLS_CHUNK):
        part = items[i:i + TLS_CHUNK]
        res = await asyncio.gather(*[make_coro(ip, p) for ip, p in part])
        results.extend(res)
        if total > TLS_CHUNK:
            print(f"  [{label}] {min(i + TLS_CHUNK, total):,}/{total:,} | "
                  f"通过: {sum(1 for x in results if x):,}", flush=True)
    return results


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


async def main():
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    name_arg = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_NAME
    ports_input = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_PORTS
    if not CHECK_API:
        print("[-] CHECK_API 未配置，退出。", flush=True)
        with open("count.txt", "w", encoding="utf-8") as f:
            f.write("0")
        return

    name_label = _safe_filename(name_arg)
    with open("name.txt", "w", encoding="utf-8") as f:
        f.write(name_label)

    target_ports = pick_ports(ports_input)
    print(f"[*] 引擎：uvloop={UVLOOP_ENABLED} | masscan探活 + asyncio三阶段 + API确认 | "
          f"名字={name_label}", flush=True)
    print(f"[*] 端口({len(target_ports)}个): {target_ports}", flush=True)

    # ==================== 阶段零：masscan 探活 ====================
    print(f"\n[*] 解析目标...", flush=True)
    nets, total_ips = build_targets_file(target_input)
    if not nets:
        print("[-] 未解析到任何 IPv4 目标。", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        return

    total_scans = total_ips * len(target_ports)
    print(f"[+] {len(nets)} 段 | {total_ips:,} IP × {len(target_ports)} 端口 "
          f"= {total_scans:,} 次探测", flush=True)
    eta = total_scans * (1 + MASSCAN_RETRIES) / max(MASSCAN_RATE, 1) / 60
    print(f"[*] masscan 预估约 {eta:.0f} 分钟（含 {MASSCAN_RETRIES} 次重传）",
          flush=True)

    print(f"\n[0/4 阶段零 masscan 探活]", flush=True)
    open_ports = run_masscan(target_ports)
    if open_ports is None:
        print("[-] masscan 未能运行，退出。", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        return
    if not open_ports:
        print("[-] 无开放端口。", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        return

    print(f"[+] 探活完成！开放: {len(open_ports):,} 个"
          f"（TLS 阶段工作量降至 {len(open_ports)/max(total_scans,1)*100:.2f}%）",
          flush=True)

    # 黑洞 IP 过滤（端口数太少时无法判定，自动跳过）
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

    random.shuffle(open_ports)
    tls_sem = asyncio.Semaphore(TLS_CONCURRENCY)

    # ==================== 第一阶段：CF 证书 ====================
    print(f"\n[1/4 第一阶段 TLS 探测] 校验 {len(open_ports):,} 个"
          f"（并发={TLS_CONCURRENCY} 超时={STAGE1_TIMEOUT}s 重试={TLS_RETRY}）...",
          flush=True)
    r1 = await gather_staged(
        open_ports,
        lambda ip, p: retry_check(check_tls_sni_async, ip, p,
                                  CF_SNI_1, STAGE1_TIMEOUT, tls_sem),
        "第一阶段")
    pass_1 = [open_ports[i] for i, ok in enumerate(r1) if ok]
    print(f"[+] 第一阶段完成！保留: {len(pass_1):,} 个\n", flush=True)
    if not pass_1:
        with open("count.txt", "w") as f:
            f.write("0")
        print("[-] 无有效目标通过第一阶段。", flush=True)
        return

    # ==================== 第二阶段：crypto 301 ====================
    print(f"[2/4 第二阶段 HTTP 校验] 校验 {len(pass_1):,} 个候选...", flush=True)
    r2 = await gather_staged(
        pass_1,
        lambda ip, p: retry_check(check_http_async, ip, p,
                                  CF_HOST_TEST, STAGE2_TIMEOUT, tls_sem),
        "第二阶段")
    pass_2 = [pass_1[i] for i, ok in enumerate(r2) if ok]
    print(f"[+] 第二阶段完成！保留: {len(pass_2):,} 个\n", flush=True)
    if not pass_2:
        with open("count.txt", "w") as f:
            f.write("0")
        print("[-] 无有效目标通过第二阶段。", flush=True)
        return

    # ==================== 第三阶段：自定义域名 ====================
    final_items = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[3/4 第三阶段自定义域名校验] 校验 {len(pass_2):,} 个...", flush=True)
        r3 = await gather_staged(
            pass_2,
            lambda ip, p: retry_check(check_tls_sni_async, ip, p,
                                      domain, STAGE3_TIMEOUT, tls_sem),
            "第三阶段")
        final_items = [pass_2[i] for i, ok in enumerate(r3) if ok]
        print(f"[+] 第三阶段完成！有效目标: {len(final_items):,} 个", flush=True)
    else:
        print("[3/4] 未检测到 CUSTOM_CF_DOMAIN，跳过。", flush=True)

    # ==================== 第四阶段：API 确认 + 拿真实落地 ====================
    api_results = []      # [(ip, port, country)]
    if final_items and CHECK_API and CHECK_API.strip():
        uniq = sorted(set(final_items),
                      key=lambda x: (ipaddress.ip_address(x[0]), x[1]))
        print(f"\n[4/4 API 确认] 校验 {len(uniq)} 个"
              f"（并发={API_CONCURRENCY} 超时={API_TIMEOUT}s "
              f"重试={API_RETRY}）...", flush=True)
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
                # API 没答上来 → 仍收录但 country 留占位，等 recheck 补
                api_results.append((ip, port, "??"))
                err_n += 1
            else:
                dead_n += 1      # API 明确说不通 → 丢弃
        print(f"[+] API 确认: 通过 {ok_n} | 不通(丢弃) {dead_n} | "
              f"异常(收录待复验) {err_n}", flush=True)
    else:
        api_results = [(ip, port, "??") for ip, port in
                       sorted(set(final_items),
                              key=lambda x: (ipaddress.ip_address(x[0]), x[1]))]
        print("[4/4] 未配置 CHECK_API，country 留 ?? 待 recheck 填。", flush=True)

    if not api_results:
        with open("count.txt", "w") as f:
            f.write("0")
        print("\n==================== 扫描结束 ====================", flush=True)
        print("[!] API 确认后无有效结果，不覆盖已有文件。", flush=True)
        return

    # ==================== 结果输出（追加去重 + 防覆盖保护） ====================
    output_filename = f"{name_label}.txt"
    old_lines = load_old_lines(output_filename)
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
        return

    with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
        for line in sorted_lines:
            f.write(line + "\n")

    with open("count.txt", "w") as f:
        f.write(str(new_count))

    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"本次新增: {new_count} 个 | 文件累计: {len(sorted_lines)} 个", flush=True)
    print(f"[+] 结果已保存（追加去重，详见私库）", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
