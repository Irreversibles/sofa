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
import urllib.parse
import urllib.request
import resource
from functools import lru_cache

import aiohttp
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
DEFAULT_TARGET = os.getenv("ASN_LIST", "45102")
DEFAULT_NAME = os.getenv("NAME_LABEL", "Alibaba")
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

# 三阶段 TLS/HTTP 筛选
TLS_CONCURRENCY = int(os.getenv("TLS_CONCURRENCY", "300"))
TLS_CHUNK = 20000
STAGE1_TIMEOUT = 3
STAGE2_TIMEOUT = 2.5
STAGE3_TIMEOUT = 2.5
TLS_RETRY = 1

# ==================== 第四阶段：自建 API 确认落地 ====================
# 三阶段只证明"TLS 能透传到 CF 边缘"，不证明"能作为 proxyip 转发"。
# 这一步用自建 Worker 实测转发并拿真实落地国家 —— GeoIP 给的是 IP 注册地，
# 与落地常不一致（云厂商尤其明显），所以 country 只认这里的结果。
CHECK_API = os.getenv("CHECK_API", "").strip()
API_CONCURRENCY = int(os.getenv("API_CONC", "20"))
API_TIMEOUT = 30
API_RETRY = 2

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


def get_country(ip):
    """GeoIP 查的是 IP 注册地，仅在 API 不可用时作兜底参考。
    真实落地由第四阶段的自建 API 提供。"""
    if geo_reader is None:
        return "??"
    try:
        return geo_reader.country(ip).country.iso_code or "??"
    except Exception:
        return "??"


def _safe_filename(name):
    cleaned = re.sub(r'[^\w.-]', '_', name).strip('._')
    return cleaned or "RESULT"


def resolve_name(name_arg):
    return _safe_filename(name_arg or "RESULT")


def parse_asn_list(target_input):
    """支持逗号/空格分隔的多 ASN：'45102,37963' 或 'AS45102 AS37963'"""
    parts = re.split(r'[\s,]+', str(target_input).strip())
    asns = []
    for p in parts:
        c = p.upper().replace("AS", "").strip()
        if c.isdigit() and c not in asns:
            asns.append(c)
    return asns


@lru_cache(maxsize=64)
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
        print(f"[!] AS{asn_clean} RIPE 拉取失败({type(e).__name__})，尝试 bgpview...",
              flush=True)

    if not cidrs:
        try:
            url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=ASN_FETCH_TIMEOUT) as response:
                data = json.loads(response.read().decode())
                for p in data.get("data", {}).get("ipv4_prefixes", []):
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.append(prefix)
        except Exception as e:
            print(f"[-] AS{asn_clean} bgpview 也失败: {type(e).__name__}", flush=True)

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


def _meta_file(name_key):
    os.makedirs(STATE_DIR, exist_ok=True)
    return os.path.join(STATE_DIR, f"prefix_meta_{name_key}.json")


def _state_file(name_key):
    os.makedirs(STATE_DIR, exist_ok=True)
    return os.path.join(STATE_DIR, f"fullcover_state_{name_key}.json")


def _build_meta_from_asns(asn_list):
    """拉取一组 ASN 的所有前缀，合并去重（collapse 掉重叠/相邻段），构建有序 meta"""
    all_cidrs = []
    for asn in asn_list:
        all_cidrs.extend(get_asn_prefixes(asn))

    nets = []
    for c in all_cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
            if n.version == 4:
                nets.append(n)
        except Exception:
            continue
    if not nets:
        return [], 0

    # collapse：多个 ASN 间的重叠段合并，避免重复扫
    collapsed = list(ipaddress.collapse_addresses(nets))

    meta = []
    total_ips = 0
    for net in collapsed:
        s, e, cnt = _usable_range(net)
        if cnt <= 0:
            continue
        meta.append({"cidr": str(net), "start": s, "end": e, "count": cnt})
        total_ips += cnt
    meta.sort(key=lambda m: m["start"])   # 游标稳定推进
    return meta, total_ips


def _load_or_build_meta(name_key, asn_list):
    mfile = _meta_file(name_key)
    asn_set = sorted(asn_list)

    if os.path.exists(mfile):
        try:
            with open(mfile, "r", encoding="utf-8") as f:
                d = json.load(f)
            built = d.get("built_ts", 0)
            age = time.time() - built
            cached_asns = sorted(d.get("asns", []))
            if ("meta" in d and "total_ips" in d and cached_asns == asn_set
                    and age < META_TTL_SEC):
                print(f"[*] 前缀元数据缓存命中（{age/86400:.1f}天前构建，"
                      f"ASN组={asn_set}）", flush=True)
                return d["meta"], int(d["total_ips"])
            elif cached_asns != asn_set:
                print(f"[*] ASN 组变化 {cached_asns} -> {asn_set}，重建元数据",
                      flush=True)
            else:
                print(f"[*] 前缀元数据已过期（{age/86400:.1f}天），重新拉取", flush=True)
        except Exception:
            pass

    meta, total_ips = _build_meta_from_asns(asn_list)

    if not meta:
        # 拉取失败时降级沿用旧缓存，避免整轮空跑
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

    with open(mfile, "w", encoding="utf-8") as f:
        json.dump({
            "name": name_key,
            "asns": asn_set,
            "built_ts": int(time.time()),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "segment_count": len(meta),
            "total_ips": total_ips,
            "meta": meta
        }, f, ensure_ascii=False)

    return meta, total_ips


def _load_or_init_state(name_key, asn_list, total_ips):
    sfile = _state_file(name_key)
    asn_set = sorted(asn_list)
    if os.path.exists(sfile):
        try:
            with open(sfile, "r", encoding="utf-8") as f:
                s = json.load(f)
            if all(k in s for k in ("cursor_prefix_index", "cursor_offset",
                                    "round", "scanned_this_round")):
                # total_ips 或 ASN 组变化 → 段结构变了，游标失去意义，重置
                if (int(s.get("total_ips", 0)) != int(total_ips)
                        or sorted(s.get("asns", [])) != asn_set):
                    print(f"[!] 段结构变化（total {s.get('total_ips')}→{total_ips} / "
                          f"asns {sorted(s.get('asns', []))}→{asn_set}），重置游标",
                          flush=True)
                    s["cursor_prefix_index"] = 0
                    s["cursor_offset"] = 0
                    s["scanned_this_round"] = 0
                    s["total_ips"] = total_ips
                    s["asns"] = asn_set
                return s
        except Exception:
            pass

    return {
        "name": name_key,
        "asns": asn_set,
        "version": 2,
        "cursor_prefix_index": 0,
        "cursor_offset": 0,
        "round": 1,
        "total_ips": total_ips,
        "scanned_this_round": 0,
        "last_run_utc": "",
    }


def _save_state(name_key, s):
    s["last_run_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sfile = _state_file(name_key)
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
    if idx >= n:      # 段数变少时的越界保护
        idx, off = 0, 0
    need = int(budget)
    wrapped = False
    out = []
    added_this_round = 0

    while need > 0:
        seg = meta[idx]
        cnt = int(seg["count"])

        if off >= cnt:
            off = 0
            idx += 1
            if idx >= n:
                idx = 0
                wrapped = True
                added_this_round = 0
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


# ==================== 三阶段 TLS/HTTP 筛选 ====================
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


# ==================== 主流程 ====================
async def main():
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    name_arg = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_NAME
    if not CHECK_API:
        print("[-] CHECK_API 未配置，退出。", flush=True)
        with open("count.txt", "w", encoding="utf-8") as f:
            f.write("0")
        return

    asn_list = parse_asn_list(target_input)
    if not asn_list:
        print(f"[-] 未解析到有效 ASN，收到: {target_input}", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        return

    name_label = resolve_name(name_arg)
    name_key = _safe_filename(name_label)

    with open("name.txt", "w", encoding="utf-8") as f:
        f.write(name_label)

    print(f"[*] 引擎：uvloop={UVLOOP_ENABLED} | ASN组={asn_list} | "
          f"名字={name_label}", flush=True)
    print(f"[*] 参数：TCP并发={TCP_CONCURRENCY} 超时={TCP_TIMEOUT}s "
          f"每轮预算={BUDGET_IPS:,}", flush=True)
    print(f"[*] 端口固定：443（全量断点续扫）", flush=True)

    meta, total_ips = _load_or_build_meta(name_key, asn_list)
    if not meta or total_ips <= 0:
        print("[-] 未获取到可扫描 IPv4 前缀。", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        return

    print(f"[+] {name_label}(ASN组{asn_list}) 可扫描主机总数: {total_ips:,} | "
          f"段数: {len(meta):,}", flush=True)

    s = _load_or_init_state(name_key, asn_list, total_ips)
    print(f"[*] 当前状态: round={s['round']} "
          f"cursor=({s['cursor_prefix_index']},{s['cursor_offset']}) "
          f"scanned_this_round={s.get('scanned_this_round',0):,}/{total_ips:,}",
          flush=True)

    batch_ips, s, wrapped = _next_batch(meta, s, BUDGET_IPS)
    if not batch_ips:
        print("[!] 本轮无目标，退出。", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        _save_state(name_key, s)
        return

    if wrapped:
        print(f"[!] 已跨越尾部，进入新一轮 round={s['round']}", flush=True)

    # 打乱本批：顺序扫连续 IP 段极易触发云厂商扫描检测/限速，
    # 打乱后同一时刻的并发落在分散地址上（不影响覆盖，游标已记录进度）
    random.shuffle(batch_ips)

    print(f"[*] 本轮扫描 IP 数: {len(batch_ips):,}（仅端口 443，已打乱顺序）",
          flush=True)

    # ==================== 阶段零：TCP 443 探活 ====================
    alive_ips = await scan_tcp_443(batch_ips)
    print(f"[+] 本轮 TCP 开放 443: {len(alive_ips):,}", flush=True)

    if not alive_ips:
        with open("count.txt", "w") as f:
            f.write("0")
        print("[-] 无开放 443，跳过后续阶段，不覆盖已有结果。", flush=True)
        _save_state(name_key, s)
        return

    tls_sem = asyncio.Semaphore(TLS_CONCURRENCY)

    # ==================== 第一阶段：CF 证书 ====================
    targets = [(ip, 443) for ip in alive_ips]
    print(f"\n[1/4 第一阶段 TLS 探测] 校验 {len(targets):,} 个...", flush=True)
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
        _save_state(name_key, s)
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
        _save_state(name_key, s)
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
        print("[!] 本次无有效结果，跳过写文件，不覆盖已有结果。", flush=True)
        _save_state(name_key, s)
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
        _save_state(name_key, s)
        return

    with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
        for line in sorted_lines:
            f.write(line + "\n")

    with open("count.txt", "w") as f:
        f.write(str(new_count))

    _save_state(name_key, s)

    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"本次新增: {new_count} 个 | 文件累计: {len(sorted_lines)} 个", flush=True)
    print(f"[+] 结果已保存（追加去重，详见私库）", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
