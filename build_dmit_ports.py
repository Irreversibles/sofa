#!/usr/bin/env python3
"""
决定本轮扫哪些端口、以及本轮到底跑不跑。

配额：按时间预算反推，池子变大时每轮端口数不缩水。
节奏：按"轮转一圈需要几轮(cycle)"自适应——
    cycle == 1（池子 ≤ 配额，一轮扫全）      → 隔 3 天，避免每天重扫同一批
    cycle 2-3                                → 隔 2 天
    cycle >= 4（池子远大于配额）             → 每天，尽快转完一圈
判据用 cycle 而非池子大小：一轮能不能扫全取决于池子/配额的比值，
而配额随 IP 数变，所以 cycle 才是真正自适应的量。

模式：
    默认        选端口 + 决策 SHOULD_RUN，写进 GITHUB_ENV
    --finalize  扫描成功后调用，标记已扫 + 记录本轮扫描时刻
"""
import ipaddress
import json
import math
import os
import sys
import urllib.request

from port_state import load_state, save_state, now_ts

STATE_FILE = os.environ.get("STATE_FILE", "dmit_ports_state.json")
ASN = os.environ.get("ASN", "906").replace("AS", "").strip()

DEFAULT_PORTS = os.environ.get("DEFAULT_PORTS", "443,8443,2053,2083,2096")

SCAN_BUDGET_MIN = float(os.environ.get("SCAN_BUDGET_MIN", "170"))
TCP_THROUGHPUT = float(os.environ.get("TCP_THROUGHPUT", "28000"))
PORTS_MIN_TOTAL = int(os.environ.get("PORTS_MIN_TOTAL", "10"))
PORTS_MAX_TOTAL = int(os.environ.get("PORTS_MAX_TOTAL", "80"))

HOT_MIN_COUNT = int(os.environ.get("HOT_MIN_COUNT", "5"))
HOT_SHARE = float(os.environ.get("HOT_SHARE", "0.5"))

# 节奏档位：cycle -> 最小间隔天数
CADENCE_1 = int(os.environ.get("CADENCE_CYCLE1_DAYS", "3"))
CADENCE_2 = int(os.environ.get("CADENCE_CYCLE2_DAYS", "2"))
CADENCE_4 = int(os.environ.get("CADENCE_CYCLE4_DAYS", "1"))
FORCE_RUN = os.environ.get("FORCE_RUN", "0") == "1"

FETCH_TIMEOUT = 15
UA = {"User-Agent": "Mozilla/5.0"}


def parse_ports(s):
    out = set()
    for x in (s or "").replace(" ", "").split(","):
        if x.isdigit():
            p = int(x)
            if 1 <= p <= 65535:
                out.add(p)
    return out


def _prefixes_ripe(asn):
    url = (f"https://stat.ripe.net/data/announced-prefixes/data.json"
           f"?resource=AS{asn}")
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
        data = json.loads(r.read().decode())
    return [p["prefix"] for p in data.get("data", {}).get("prefixes", [])
            if p.get("prefix") and ":" not in p["prefix"]]


def _prefixes_bgpview(asn):
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
        data = json.loads(r.read().decode())
    return [p["prefix"] for p in
            data.get("data", {}).get("ipv4_prefixes", []) if p.get("prefix")]


def count_asn_ips(asn):
    prefixes = []
    for fn, label in ((_prefixes_ripe, "RIPE"), (_prefixes_bgpview, "bgpview")):
        try:
            prefixes = fn(asn)
            if prefixes:
                print(f"[*] {label}: {len(prefixes)} 个 IPv4 前缀", flush=True)
                break
        except Exception as e:
            print(f"[!] {label} 拉取失败: {type(e).__name__}", flush=True)
    if not prefixes:
        return 0
    nets = []
    for c in prefixes:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except Exception:
            continue
    if not nets:
        return 0
    total = 0
    for net in ipaddress.collapse_addresses(nets):
        n = net.num_addresses
        total += n if net.prefixlen >= 31 else max(0, n - 2)
    return total


def write_env(pairs):
    path = os.environ.get("GITHUB_ENV")
    if not path:
        for k, v in pairs.items():
            print(f"[ENV] {k}={v}", flush=True)
        return
    with open(path, "a", encoding="utf-8") as f:
        for k, v in pairs.items():
            f.write(f"{k}={v}\n")


def interval_for_cycle(cycle):
    if cycle <= 1:
        return CADENCE_1
    if cycle <= 3:
        return CADENCE_2
    return CADENCE_4


def finalize():
    st = load_state(STATE_FILE)
    pend = [int(p) for p in st.get("pending_selected", []) if str(p).isdigit()]
    ts = now_ts()
    n = 0
    for p in pend:
        rec = st["ports"].get(str(p))
        if rec is not None:
            rec["last_scanned"] = ts
            n += 1
    st["pending_selected"] = []
    st["last_scan_ts"] = ts          # 供下轮 cadence 判定
    save_state(STATE_FILE, st)
    print(f"[OK] finalize: {n} 个端口标记为已扫，last_scan_ts={ts}", flush=True)


def main():
    if "--finalize" in sys.argv:
        finalize()
        return

    st = load_state(STATE_FILE)
    ports = st["ports"]
    default_ports = sorted(parse_ports(DEFAULT_PORTS))
    default_set = set(default_ports)

    fetched = count_asn_ips(ASN)
    prev = int(st.get("ip_count_seen", 0) or 0)
    if fetched <= 0:
        ip_count = prev
        src = "历史缓存（本次拉取失败）"
    elif prev > 0 and fetched < prev * 0.5:
        ip_count = prev
        src = f"历史缓存（本次仅 {fetched:,}，不足历史 {prev:,} 的一半）"
    else:
        ip_count = fetched
        src = "实时拉取"
        st["ip_count_seen"] = fetched
    if ip_count <= 0:
        ip_count = 80000
        src = "兜底估值"
    print(f"[*] AS{ASN} IP 数: {ip_count:,}（{src}）", flush=True)

    budget_targets = SCAN_BUDGET_MIN * TCP_THROUGHPUT
    raw_total = int(budget_targets // max(1, ip_count))
    total_ports = max(PORTS_MIN_TOTAL, min(PORTS_MAX_TOTAL, raw_total))
    print(f"[*] 预算 {SCAN_BUDGET_MIN:.0f}min × {TCP_THROUGHPUT:,.0f}/min "
          f"= {budget_targets:,.0f} 目标 → 配额 {raw_total} "
          f"（夹到 [{PORTS_MIN_TOTAL},{PORTS_MAX_TOTAL}] → {total_ports}）",
          flush=True)

    pool = [int(k) for k in ports if int(k) not in default_set]
    extra_quota = max(0, total_ports - len(default_ports))

    hot_all = sorted(
        (p for p in pool if int(ports[str(p)].get("count", 1) or 1) >= HOT_MIN_COUNT),
        key=lambda p: (-int(ports[str(p)].get("count", 1) or 1), p))
    hot_cap = int(extra_quota * HOT_SHARE)
    hot_sel = hot_all[:hot_cap]

    rest = [p for p in pool if p not in set(hot_sel)]
    rest.sort(key=lambda p: (int(ports[str(p)].get("last_scanned", 0) or 0),
                             -int(ports[str(p)].get("count", 1) or 1), p))
    rotate_sel = rest[:max(0, extra_quota - len(hot_sel))]

    selected = sorted(set(hot_sel) | set(rotate_sel))
    merged = sorted(default_set | set(selected))
    merged_str = ",".join(str(p) for p in merged)

    st["pending_selected"] = selected
    save_state(STATE_FILE, st)

    # ---- 节奏决策 ----
    cycle = math.ceil(len(pool) / max(1, len(rotate_sel))) if rotate_sel else 1
    interval = interval_for_cycle(cycle)
    last_scan_ts = int(st.get("last_scan_ts", 0) or 0)
    elapsed_days = (now_ts() - last_scan_ts) / 86400.0 if last_scan_ts else 1e9

    if FORCE_RUN:
        should_run = True
        reason = "手动强制"
    elif elapsed_days >= interval:
        should_run = True
        reason = f"距上次 {elapsed_days:.1f}d ≥ 间隔 {interval}d"
    else:
        should_run = False
        reason = f"距上次 {elapsed_days:.1f}d < 间隔 {interval}d"

    est_targets = ip_count * len(merged)
    est_min = est_targets / TCP_THROUGHPUT

    print(f"[*] 档案 {len(ports)} 端口（可轮转 {len(pool)}，"
          f"频次≥{HOT_MIN_COUNT} 的 {len(hot_all)}）", flush=True)
    print(f"[*] 本轮: 默认 {len(default_ports)} + 高频 {len(hot_sel)} "
          f"+ 轮转 {len(rotate_sel)} = {len(merged)} 端口", flush=True)
    print(f"[*] 轮转一圈 {cycle} 轮 → 间隔 {interval} 天 | {reason} "
          f"→ SHOULD_RUN={should_run}", flush=True)
    print(f"[*] 预计 {est_targets:,} 目标 / TCP 约 {est_min:.0f} 分钟", flush=True)

    write_env({
        "SHOULD_RUN": "true" if should_run else "false",
        "MERGED_PORTS": merged_str,
        "MERGED_PORTS_COUNT": len(merged),
        "POOL_COUNT": len(ports),
        "HOT_COUNT": len(hot_sel),
        "ROTATE_COUNT": len(rotate_sel),
        "CYCLE_ROUNDS": cycle,
        "CADENCE_DAYS": interval,
        "EST_MINUTES": f"{est_min:.0f}",
        "IP_COUNT": ip_count,
    })


if __name__ == "__main__":
    main()
