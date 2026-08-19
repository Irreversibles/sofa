#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ASN 443 全覆盖增量扫描（断点续跑）
----------------------------------
目标：
- 给定 ASN（如 8075 / AS8075），自动拉取该 ASN 全部 IPv4 前缀
- 按“全覆盖游标”扫描，不是随机抽样
- 每次扫描固定预算 IP 数（BUDGET_IPS）
- 混合前缀（/12 /16 /23 /24 ...）自动处理
- 扫描结果累积写入 <NAME_LABEL>.txt（格式：ip:443）
- 扫描进度保存在 state/fullcover_ASxxxx.json

用法：
  python scan_asn_443_fullcover.py "AS8075" "MSFT443"

可选环境变量：
  TCP_CONCURRENCY=800
  TCP_TIMEOUT=2.5
  BUDGET_IPS=200000
  ASN_FETCH_TIMEOUT=20
"""

import asyncio
import ipaddress
import json
import os
import random
import resource
import socket
import sys
import time
import urllib.request
from functools import lru_cache

# ==================== 可调参数 ====================
STATE_DIR = "state"

TCP_CONCURRENCY = int(os.getenv("TCP_CONCURRENCY", "800"))
TCP_TIMEOUT = float(os.getenv("TCP_TIMEOUT", "2.5"))
BUDGET_IPS = int(os.getenv("BUDGET_IPS", "200000"))

ASN_FETCH_TIMEOUT = int(os.getenv("ASN_FETCH_TIMEOUT", "20"))

# 单次 gather 分块，避免一次创建过多协程对象
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50000"))

# ==================== 系统优化 ====================
def optimize_system_limits():
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = max(65535, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, target))
        new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        print(f"[+] ulimit 调整成功: {new_soft}", flush=True)
    except Exception as e:
        print(f"[!] ulimit 调整失败: {e}", flush=True)

optimize_system_limits()

try:
    import uvloop
    uvloop.install()
    UVLOOP_ENABLED = True
except Exception:
    UVLOOP_ENABLED = False

# ==================== 工具函数 ====================
def _safe_name(name: str) -> str:
    import re
    s = re.sub(r"[^\w.\-]", "_", name).strip("._")
    return s or "RESULT"

def state_file(asn_clean: str) -> str:
    os.makedirs(STATE_DIR, exist_ok=True)
    return os.path.join(STATE_DIR, f"fullcover_AS{asn_clean}.json")

def prefixes_cache_file(asn_clean: str) -> str:
    os.makedirs(STATE_DIR, exist_ok=True)
    return os.path.join(STATE_DIR, f"prefixes_AS{asn_clean}.json")

def now_utc_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))

def int_to_ip(v: int) -> str:
    return str(ipaddress.ip_address(v))

def iter_usable_host_int_range(net: ipaddress.IPv4Network):
    """
    与你现有脚本规则对齐：
    - /31 和 /32：扫描全部地址
    - 其他前缀：跳过网络地址与广播地址（hosts）
    返回 (start_int, end_int, count)
    """
    if net.prefixlen >= 31:
        start = int(net.network_address)
        end = int(net.broadcast_address)
        count = end - start + 1
        return start, end, count

    # 一般网段：去掉 network / broadcast
    start = int(net.network_address) + 1
    end = int(net.broadcast_address) - 1
    count = max(0, end - start + 1)
    return start, end, count

@lru_cache(maxsize=32)
def fetch_asn_prefixes(asn_clean: str):
    """
    返回该 ASN 的 IPv4 前缀列表（字符串）
    RIPE 失败后回退 BGPView
    """
    cidrs = []

    # RIPE
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_clean}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=ASN_FETCH_TIMEOUT) as r:
            data = json.loads(r.read().decode())
        for p in data.get("data", {}).get("prefixes", []):
            pref = p.get("prefix")
            if pref and ":" not in pref:
                cidrs.append(pref)
    except Exception as e:
        print(f"[!] RIPE 拉取失败: {type(e).__name__}", flush=True)

    # BGPView fallback
    if not cidrs:
        try:
            url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=ASN_FETCH_TIMEOUT) as r:
                data = json.loads(r.read().decode())
            for p in data.get("data", {}).get("ipv4_prefixes", []):
                pref = p.get("prefix")
                if pref:
                    cidrs.append(pref)
        except Exception as e:
            print(f"[-] BGPView 拉取失败: {type(e).__name__}", flush=True)

    cidrs = sorted(set(cidrs))
    return cidrs

def build_prefix_meta(cidrs):
    """
    将 CIDR 列表转换为可扫描段元数据：
    [
      {
        "cidr": "1.2.3.0/24",
        "start_int": 16909057,
        "end_int": 16909310,
        "count": 254
      },
      ...
    ]
    """
    meta = []
    total_ips = 0

    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if net.version != 4:
                continue
            start, end, count = iter_usable_host_int_range(net)
            if count <= 0:
                continue
            item = {
                "cidr": str(net),
                "start_int": start,
                "end_int": end,
                "count": count
            }
            meta.append(item)
            total_ips += count
        except Exception:
            continue

    return meta, total_ips

def load_or_init_prefixes(asn_clean: str):
    """
    加载前缀元数据缓存，不存在则在线拉取并构建。
    """
    cache = prefixes_cache_file(asn_clean)
    if os.path.exists(cache):
        try:
            with open(cache, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "prefix_meta" in data:
                return data["prefix_meta"], int(data.get("total_ips", 0))
        except Exception:
            pass

    cidrs = fetch_asn_prefixes(asn_clean)
    if not cidrs:
        return [], 0

    prefix_meta, total_ips = build_prefix_meta(cidrs)

    with open(cache, "w", encoding="utf-8") as f:
        json.dump(
            {
                "asn": asn_clean,
                "updated_at": now_utc_iso(),
                "prefix_count": len(cidrs),
                "segment_count": len(prefix_meta),
                "total_ips": total_ips,
                "prefix_meta": prefix_meta,
            },
            f,
            ensure_ascii=False,
        )

    return prefix_meta, total_ips

def load_state(asn_clean: str, total_ips: int):
    """
    载入扫描游标状态；首次扫描则初始化。
    """
    path = state_file(asn_clean)

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                s = json.load(f)
            # 基础校验
            if (
                isinstance(s, dict)
                and "cursor_prefix_index" in s
                and "cursor_offset_in_prefix" in s
                and "round" in s
            ):
                # 如果总 IP 变化（ASN 前缀变更），保留 round，重置游标可选
                if int(s.get("total_ips", 0)) != int(total_ips):
                    print(
                        f"[!] total_ips 变化: {s.get('total_ips')} -> {total_ips}，保留轮次，重置游标",
                        flush=True,
                    )
                    s["cursor_prefix_index"] = 0
                    s["cursor_offset_in_prefix"] = 0
                    s["total_ips"] = total_ips
                return s
        except Exception:
            pass

    # 初始化
    return {
        "asn": asn_clean,
        "version": 1,
        "cursor_prefix_index": 0,
        "cursor_offset_in_prefix": 0,
        "round": 1,
        "total_ips": total_ips,
        "scanned_ips_this_round": 0,
        "last_run_utc": "",
    }

def save_state(asn_clean: str, s: dict):
    path = state_file(asn_clean)
    tmp = path + ".tmp"
    s["last_run_utc"] = now_utc_iso()
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def next_batch_ips(prefix_meta, state_obj, budget_ips: int):
    """
    根据游标取下一批 IP（字符串列表），严格顺序推进，支持跨段。
    返回: (ips, updated_state, wrapped_round)
      wrapped_round=True 表示本轮从尾部回到了头部（round+1）
    """
    if not prefix_meta or budget_ips <= 0:
        return [], state_obj, False

    n = len(prefix_meta)
    idx = int(state_obj["cursor_prefix_index"])
    off = int(state_obj["cursor_offset_in_prefix"])
    need = int(budget_ips)

    out = []
    wrapped_round = False

    while need > 0:
        seg = prefix_meta[idx]
        seg_count = int(seg["count"])

        # 修正越界偏移
        if off >= seg_count:
            off = 0
            idx += 1
            if idx >= n:
                idx = 0
                wrapped_round = True
            continue

        take = min(need, seg_count - off)
        start_ip_int = int(seg["start_int"]) + off
        end_ip_int = start_ip_int + take - 1

        # 生成本段 IP
        for v in range(start_ip_int, end_ip_int + 1):
            out.append(int_to_ip(v))

        off += take
        need -= take

        # 段耗尽，跳下一段
        if off >= seg_count:
            off = 0
            idx += 1
            if idx >= n:
                idx = 0
                wrapped_round = True

    # 更新状态
    prev_round = int(state_obj["round"])
    if wrapped_round:
        state_obj["round"] = prev_round + 1
        state_obj["scanned_ips_this_round"] = len(out)  # 新一轮已扫数量从本批开始
    else:
        state_obj["scanned_ips_this_round"] = int(state_obj.get("scanned_ips_this_round", 0)) + len(out)

    state_obj["cursor_prefix_index"] = idx
    state_obj["cursor_offset_in_prefix"] = off

    return out, state_obj, wrapped_round

async def tcp_open_443(ip: str, sem: asyncio.Semaphore):
    """
    仅 TCP 443 探活：成功返回 ip，失败返回 None
    """
    async with sem:
        writer = None
        try:
            conn = asyncio.open_connection(ip, 443)
            reader, writer = await asyncio.wait_for(conn, timeout=TCP_TIMEOUT)

            sock = writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            return ip
        except Exception:
            return None
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

async def scan_batch_443(ips):
    """
    分块并发扫描，返回开放 443 的 IP 列表
    """
    sem = asyncio.Semaphore(TCP_CONCURRENCY)

    alive = []
    total = len(ips)
    done = 0

    for i in range(0, total, BATCH_SIZE):
        part = ips[i:i + BATCH_SIZE]
        tasks = [tcp_open_443(ip, sem) for ip in part]
        res = await asyncio.gather(*tasks)
        part_alive = [x for x in res if x]
        alive.extend(part_alive)

        done += len(part)
        print(f"  [443探活] {done:,}/{total:,} | open: {len(alive):,}", flush=True)

    return alive

def load_old_results(path):
    s = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                t = line.strip()
                if t:
                    s.add(t)
    except FileNotFoundError:
        pass
    return s

def save_results(path, result_set):
    def k(line):
        try:
            ip = line.split(":")[0]
            return ip_to_int(ip)
        except Exception:
            return 0
    lines = sorted(result_set, key=k)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        for x in lines:
            f.write(x + "\n")
    os.replace(tmp, path)

async def main():
    if len(sys.argv) < 2:
        print("Usage: python scan_asn_443_fullcover.py ASxxxx [NameLabel]")
        with open("count.txt", "w") as f:
            f.write("0")
        return

    raw_asn = sys.argv[1].strip()
    asn_clean = raw_asn.upper().replace("AS", "").strip()
    if not asn_clean.isdigit():
        print(f"[-] ASN 非法: {raw_asn}")
        with open("count.txt", "w") as f:
            f.write("0")
        return

    label = sys.argv[2].strip() if len(sys.argv) > 2 and sys.argv[2].strip() else f"AS{asn_clean}_443"
    label = _safe_name(label)

    with open("name.txt", "w", encoding="utf-8") as f:
        f.write(label)

    print(f"[*] uvloop={UVLOOP_ENABLED} | ASN=AS{asn_clean} | label={label}", flush=True)
    print(f"[*] TCP_CONCURRENCY={TCP_CONCURRENCY}, TCP_TIMEOUT={TCP_TIMEOUT}, BUDGET_IPS={BUDGET_IPS}", flush=True)

    # 1) 加载前缀元数据
    prefix_meta, total_ips = load_or_init_prefixes(asn_clean)
    if not prefix_meta or total_ips <= 0:
        print("[-] 无可扫描 IPv4 前缀")
        with open("count.txt", "w") as f:
            f.write("0")
        return

    print(f"[+] AS{asn_clean} 可扫描主机总数: {total_ips:,} | 段数: {len(prefix_meta):,}", flush=True)

    # 2) 加载状态
    s = load_state(asn_clean, total_ips)
    print(
        f"[*] 当前状态: round={s['round']} "
        f"cursor=({s['cursor_prefix_index']},{s['cursor_offset_in_prefix']}) "
        f"scanned_this_round={s.get('scanned_ips_this_round', 0):,}/{total_ips:,}",
        flush=True,
    )

    # 3) 取本轮 batch
    batch_ips, s, wrapped = next_batch_ips(prefix_meta, s, BUDGET_IPS)
    if not batch_ips:
        print("[!] 本轮未生成扫描目标")
        with open("count.txt", "w") as f:
            f.write("0")
        save_state(asn_clean, s)
        return

    if wrapped:
        print(f"[!] 已跨越尾部，进入 round={s['round']} 新一轮", flush=True)

    print(f"[*] 本轮计划扫描 IP 数: {len(batch_ips):,}", flush=True)

    # 4) TCP 443 探活
    alive_ips = await scan_batch_443(batch_ips)
    print(f"[+] 本轮开放 443: {len(alive_ips):,}", flush=True)

    # 5) 结果合并
    out_file = f"{label}.txt"
    old = load_old_results(out_file)
    before = len(old)

    for ip in alive_ips:
        old.add(f"{ip}:443")

    after = len(old)
    new_count = after - before

    save_results(out_file, old)

    # 6) 写状态 / 计数
    save_state(asn_clean, s)

    with open("count.txt", "w", encoding="utf-8") as f:
        f.write(str(new_count))

    progress = (int(s.get("scanned_ips_this_round", 0)) / total_ips * 100) if total_ips else 0.0

    print("================================================", flush=True)
    print(
        f"[+] 本次新增: {new_count} | 累计: {after} | "
        f"round={s['round']} 进度={progress:.2f}% "
        f"({s.get('scanned_ips_this_round', 0):,}/{total_ips:,})",
        flush=True,
    )

if __name__ == "__main__":
    asyncio.run(main())
