import asyncio
import ssl
import os
import sys
import re
import json
import time
import ipaddress
import random
import socket
import urllib.request
import resource
from functools import lru_cache

import geoip2.database

# ==================== 系统优化 ====================
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
DEFAULT_TARGET = os.getenv("ASN_LIST", "AS45102")
DEFAULT_NAME = os.getenv("NAME_LABEL", "Alibaba")
DEFAULT_PORTS = "443"  # 全量扫描固定443
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "")

GEOIP_DB = "GeoLite2-Country.mmdb"
STATE_DIR = "state"
ASN_FETCH_TIMEOUT = int(os.getenv("ASN_FETCH_TIMEOUT", "20"))
META_TTL_SEC = int(os.getenv("META_TTL_SEC", str(7 * 86400)))  # 前缀元数据缓存7天

# 阶段零：TCP 探活（全量443）
TCP_CONCURRENCY = int(os.getenv("TCP_CONCURRENCY", "2500"))
TCP_TIMEOUT = float(os.getenv("TCP_TIMEOUT", "3.0"))
BUDGET_IPS = int(os.getenv("BUDGET_IPS", "200000"))
TCP_BATCH = int(os.getenv("TCP_BATCH", "50000"))

# 三阶段 TLS/HTTP 筛选（与原大号一致）
TLS_CONCURRENCY = int(os.getenv("TLS_CONCURRENCY", "300"))
TLS_CHUNK = 20000
STAGE1_TIMEOUT = 3
STAGE2_TIMEOUT = 2.5
STAGE3_TIMEOUT = 2.5
TLS_RETRY = 1

CF_SNI_1 = "www.cloudflare.com"
CF_HOST_TEST = "crypto.cloudflare.com"

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

try:
    geo_reader = geoip2.database.Reader(GEOIP_DB)
except Exception:
    geo_reader = None

# ==================== ASN -> 固定名称映射 ====================
ASN_NAME_MAP = {
    "45102": "Alibaba",
    "396982": "Google",
    "8075": "Microsoft",
}

def get_fixed_name(asn_clean):
    return ASN_NAME_MAP.get(asn_clean, None)

def get_country(ip):
    if geo_reader is None:
        return "??"
    try:
        return geo_reader.country(ip).country.iso_code or "??"
    except Exception:
        return "??"

def _safe_filename(name):
    cleaned = re.sub(r'[^\w.-]', '_', name).strip('._')
    return cleaned or "RESULT"

def resolve_name(target_input, name_arg):
    # 优先使用固定映射名
    asn_clean = target_input.upper().replace("AS", "").strip()
    fixed = get_fixed_name(asn_clean)
    if fixed:
        print(f"[*] AS{asn_clean} 使用固定名称: {fixed}", flush=True)
        return fixed
    if name_arg and name_arg.lower() != "auto":
        return _safe_filename(name_arg)
    return f"AS{asn_clean}"

@lru_cache(maxsize=32)
def get_asn_prefixes(asn_clean):
    cidrs = []
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_clean}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
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
            url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(url, timeout=ASN_FETCH_TIMEOUT) as response:
                data = json.loads(response.read().decode())
                for p in data.get("data", {}).get("ipv4_prefixes", []):
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.append(prefix)
        except Exception as e:
            print(f"[-] bgpview 也失败: {type(e).__name__}", flush=True)

    cidrs = sorted(set(cidrs))
    if cidrs:
        print(f"[*] AS{asn_clean}: 拿到 {len(cidrs)} 个 IPv4 前缀", flush=True)
    return cidrs

def _usable_range(net):
    if net.prefixlen >= 31:
        s = int(net.network_address)
        e = int(net.broadcast_address)
        return s, e, e - s + 1
    s = int(net.network_address) + 1
    e = int(net.broadcast_address) - 1
    c = max(0, e - s + 1)
    return s, e, c

def _meta_file(asn_clean):
    os.makedirs(STATE_DIR, exist_ok=True)
    return os.path.join(STATE_DIR, f"prefix_meta_AS{asn_clean}.json")

def _state_file(asn_clean):
    os.makedirs(STATE_DIR, exist_ok=True)
    return os.path.join(STATE_DIR, f"fullcover_state_AS{asn_clean}.json")

def _load_or_build_meta(asn_clean):
    mfile = _meta_file(asn_clean)
    if os.path.exists(mfile):
        try:
            with open(mfile, "r", encoding="utf-8") as f:
                d = json.load(f)
            built = d.get("built_ts", 0)
            age = time.time() - built
            if "meta" in d and "total_ips" in d and age < META_TTL_SEC:
                print(f"[*] 前缀元数据缓存命中（{age/86400:.1f}天前构建）", flush=True)
                return d["meta"], int(d["total_ips"])
            else:
                print(f"[*] 前缀元数据已过期（{age/86400:.1f}天），重新拉取", flush=True)
        except Exception:
            pass

    cidrs = get_asn_prefixes(asn_clean)
    if not cidrs:
        # 拉取失败时，若有旧缓存则降级沿用，避免整轮空跑
        if os.path.exists(mfile):
            try:
                with open(mfile, "r", encoding="utf-8") as f:
                    d = json.load(f)
                if "meta" in d and "total_ips" in d:
                    print("[!] 前缀拉取失败，降级沿用旧缓存", flush=True)
                    return d["meta"], int(d["total_ips"])
            except Exception:
                pass
        return [], 0

    meta = []
    total_ips = 0
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if net.version != 4:
                continue
            s, e, cnt = _usable_range(net)
            if cnt <= 0:
                continue
            meta.append({
                "cidr": str(net),
                "start": s,
                "end": e,
                "count": cnt
            })
            total_ips += cnt
        except Exception:
            continue

    with open(mfile, "w", encoding="utf-8") as f:
        json.dump({
            "asn": asn_clean,
            "built_ts": int(time.time()),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "prefix_count": len(cidrs),
            "segment_count": len(meta),
            "total_ips": total_ips,
            "meta": meta
        }, f, ensure_ascii=False)

    return meta, total_ips

def _load_or_init_state(asn_clean, total_ips):
    sfile = _state_file(asn_clean)
    if os.path.exists(sfile):
        try:
            with open(sfile, "r", encoding="utf-8") as f:
                s = json.load(f)
            if all(k in s for k in ("cursor_prefix_index", "cursor_offset", "round", "scanned_this_round")):
                if int(s.get("total_ips", 0)) != int(total_ips):
                    print(f"[!] total_ips 变化: {s.get('total_ips')} -> {total_ips}，重置游标", flush=True)
                    s["cursor_prefix_index"] = 0
                    s["cursor_offset"] = 0
                    s["scanned_this_round"] = 0
                    s["total_ips"] = total_ips
                return s
        except Exception:
            pass

    return {
        "asn": asn_clean,
        "version": 1,
        "cursor_prefix_index": 0,
        "cursor_offset": 0,
        "round": 1,
        "total_ips": total_ips,
        "scanned_this_round": 0,
        "last_run_utc": "",
    }

def _save_state(asn_clean, s):
    s["last_run_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sfile = _state_file(asn_clean)
    tmp = sfile + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=False, indent=2)
    os.replace(tmp, sfile)

def _int_to_ip(v):
    return str(ipaddress.ip_address(v))

def _next_batch(meta, s, budget):
    if not meta or budget <= 0:
        return [], s, False

    n = len(meta)
    idx = int(s["cursor_prefix_index"])
    off = int(s["cursor_offset"])
    need = int(budget)
    wrapped = False
    out = []
    added_this_round = 0    # 本批中属于“当前轮”的计数（跨轮后重新累计）

    while need > 0:
        seg = meta[idx]
        cnt = int(seg["count"])

        if off >= cnt:
            off = 0
            idx += 1
            if idx >= n:
                idx = 0
                wrapped = True
                added_this_round = 0    # 跨过尾部，新一轮从这里开始计
            continue

        take = min(need, cnt - off)
        start_int = int(seg["start"]) + off
        end_int = start_int + take - 1

        for v in range(start_int, end_int + 1):
            out.append(_int_to_ip(v))

        off += take
        need -= take
        added_this_round += take

        if off >= cnt:
            off = 0
            idx += 1
            if idx >= n:
                idx = 0
                wrapped = True
                added_this_round = 0

    if wrapped:
        s["round"] = int(s["round"]) + 1
        s["scanned_this_round"] = added_this_round
    else:
        s["scanned_this_round"] = int(s.get("scanned_this_round", 0)) + len(out)

    s["cursor_prefix_index"] = idx
    s["cursor_offset"] = off

    return out, s, wrapped
# ==================== TCP 443 探活 ====================
async def tcp_open_443(ip, sem):
    """纯 TCP 443 握手。成功返回 ip，失败返回 None"""
    async with sem:
        writer = None
        try:
            conn = asyncio.open_connection(ip, 443)
            reader, writer = await asyncio.wait_for(conn, timeout=TCP_TIMEOUT)
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return ip
        except Exception:
            return None
        finally:
            if writer:
                writer.close()
                try:
                    writer.transport.abort()
                except Exception:
                    pass


async def scan_tcp_443(ips):
    """分块并发扫描 443，返回开放 IP 列表"""
    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    alive = []
    total = len(ips)
    done = 0
    for i in range(0, total, TCP_BATCH):
        part = ips[i:i + TCP_BATCH]
        res = await asyncio.gather(*[tcp_open_443(ip, sem) for ip in part])
        alive.extend([x for x in res if x])
        done += len(part)
        print(f"  [443探活] {done:,}/{total:,} | 开放: {len(alive):,}", flush=True)
    return alive


# ==================== 三阶段 TLS/HTTP 筛选（与你大号原逻辑一致） ====================
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


# ==================== 结果保存（与你大号完全一致） ====================
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


def save_lines_sorted(path, lines_set):
    def sort_key(line):
        try:
            addr = line.split("#")[0]
            ip_part, port_part = addr.rsplit(":", 1)
            country = line.split("#")[1].split()[0] if "#" in line else "??"
            return (country, ipaddress.ip_address(ip_part), int(port_part))
        except Exception:
            return ("??", ipaddress.ip_address("0.0.0.0"), 0)

    sorted_lines = sorted(lines_set, key=sort_key)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        for line in sorted_lines:
            f.write(line + "\n")
    os.replace(tmp, path)
# ==================== 主流程 ====================
async def main():
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    name_arg = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_NAME

    asn_clean = target_input.upper().replace("AS", "").strip()
    if not asn_clean.isdigit():
        print(f"[-] 仅支持 ASN 输入（如 AS45102 / 45102），收到: {target_input}", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        return

    name_label = resolve_name(target_input, name_arg)

    with open("name.txt", "w", encoding="utf-8") as f:
        f.write(name_label)

    print(f"[*] 引擎：uvloop={UVLOOP_ENABLED} | ASN=AS{asn_clean} | 名字={name_label}", flush=True)
    print(f"[*] 参数：TCP并发={TCP_CONCURRENCY} 超时={TCP_TIMEOUT}s 每轮预算={BUDGET_IPS:,}", flush=True)
    print(f"[*] 端口固定：443（全量断点续扫）", flush=True)

    # 1) 加载/构建前缀元数据
    meta, total_ips = _load_or_build_meta(asn_clean)
    if not meta or total_ips <= 0:
        print("[-] 未获取到可扫描 IPv4 前缀。", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        return

    print(f"[+] AS{asn_clean} 可扫描主机总数: {total_ips:,} | 段数: {len(meta):,}", flush=True)

    # 2) 加载/初始化扫描状态
    s = _load_or_init_state(asn_clean, total_ips)
    print(f"[*] 当前状态: round={s['round']} "
          f"cursor=({s['cursor_prefix_index']},{s['cursor_offset']}) "
          f"scanned_this_round={s.get('scanned_this_round',0):,}/{total_ips:,}",
          flush=True)

    # 3) 生成本轮待扫描IP
    batch_ips, s, wrapped = _next_batch(meta, s, BUDGET_IPS)
    if not batch_ips:
        print("[!] 本轮无目标，退出。", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        _save_state(asn_clean, s)
        return

    if wrapped:
        print(f"[!] 已跨越尾部，进入新一轮 round={s['round']}", flush=True)

    # 打乱本批：顺序扫连续 IP 段极易触发云厂商扫描检测/限速，
    # 打乱后同一时刻的并发落在分散地址上（不影响覆盖，游标已记录进度）
    random.shuffle(batch_ips)

    print(f"[*] 本轮扫描 IP 数: {len(batch_ips):,}（仅端口 443，已打乱顺序）", flush=True)

    # 4) TCP 443 探活
    alive_ips = await scan_tcp_443(batch_ips)
    print(f"[+] 本轮 TCP 开放 443: {len(alive_ips):,}", flush=True)

    if not alive_ips:
        with open("count.txt", "w") as f:
            f.write("0")
        print("[-] 无开放 443，跳过三阶段，不覆盖已有结果。", flush=True)
        _save_state(asn_clean, s)
        return

    # 5) 三阶段筛选（与原大号逻辑完全一致）
    tls_sem = asyncio.Semaphore(TLS_CONCURRENCY)

    # 第一阶段：CF 证书
    targets = [(ip, 443) for ip in alive_ips]
    print(f"\n[1/3 第一阶段 TLS 探测] 校验 {len(targets):,} 个...", flush=True)
    r1 = await gather_staged(
        targets,
        lambda ip, p: retry_check(check_tls_sni_async, ip, p,
                                  CF_SNI_1, STAGE1_TIMEOUT, tls_sem),
        "第一阶段")
    pass_1 = [targets[i] for i, ok in enumerate(r1) if ok]
    print(f"[+] 第一阶段完成！保留: {len(pass_1):,} 个\n", flush=True)
    if not pass_1:
        with open("count.txt", "w") as f:
            f.write("0")
        print("[-] 无有效目标通过第一阶段。", flush=True)
        _save_state(asn_clean, s)
        return

    # 第二阶段：crypto 301
    print(f"[2/3 第二阶段 HTTP 校验] 校验 {len(pass_1):,} 个候选...", flush=True)
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
        _save_state(asn_clean, s)
        return

    # 第三阶段：自定义域名
    final_items = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[3/3 第三阶段自定义域名校验] 校验 {len(pass_2):,} 个...", flush=True)
        r3 = await gather_staged(
            pass_2,
            lambda ip, p: retry_check(check_tls_sni_async, ip, p,
                                      domain, STAGE3_TIMEOUT, tls_sem),
            "第三阶段")
        final_items = [pass_2[i] for i, ok in enumerate(r3) if ok]
        print(f"[+] 第三阶段完成！有效目标: {len(final_items):,} 个", flush=True)
    else:
        print("[3/3] 未检测到 CUSTOM_CF_DOMAIN，跳过。", flush=True)

    if not final_items:
        with open("count.txt", "w") as f:
            f.write("0")
        print("\n==================== 扫描结束 ====================", flush=True)
        print("[!] 本次无有效结果，跳过写文件，不覆盖已有结果。", flush=True)
        _save_state(asn_clean, s)
        return

    # 6) 结果输出（与你大号完全一致）
    output_filename = f"{name_label}.txt"
    old_lines = load_old_lines(output_filename)
    old_count = len(old_lines)

    new_count = 0
    for ip, port in final_items:
        country = get_country(ip)
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
        _save_state(asn_clean, s)
        return

    with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
        for line in sorted_lines:
            f.write(line + "\n")

    with open("count.txt", "w") as f:
        f.write(str(new_count))

    _save_state(asn_clean, s)

    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"本次新增: {new_count} 个 | 文件累计: {len(sorted_lines)} 个", flush=True)
    print(f"[+] 结果已保存（追加去重，详见私库）", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
