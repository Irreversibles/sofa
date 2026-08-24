#!/usr/bin/env python3
"""
决定本轮扫哪些端口。

两个模式：
    默认        选出本轮端口写进 GITHUB_ENV，并记入 pending_selected
    --finalize  扫描成功后调用，把 pending_selected 标记为已扫

配额不是写死的档位，而是按时间预算反推：
    端口数 = 预算分钟 × 吞吐(目标/分钟) / IP 数
这样池子变大时每轮扫的端口不会缩水（旧的档位式配额在池子 >500 时
只取 10 个，转一圈要 50 天，而那时一轮才跑 50 分钟，预算大量闲置）。

选择顺序：
    1. 默认端口（443/8443/... 每轮必扫）
    2. 高频端口（count ≥ HOT_MIN_COUNT，按频次降序，占额不超过 HOT_SHARE）
    3. 其余按 last_scanned 升序轮转（最久没扫的先扫）
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

# 时间预算：只算 TCP 探活阶段。TLS 三阶段 + API 确认通常再加 20-40 分钟，
# 所以 170 + 40 ≈ 210 分钟，距 workflow 的 350 分钟上限留足余量。
SCAN_BUDGET_MIN = float(os.environ.get("SCAN_BUDGET_MIN", "170"))
# 实测吞吐：2500 并发 / 3s 超时 / TCP_RETRY=1 下约 30k 目标/分钟，取保守值
TCP_THROUGHPUT = float(os.environ.get("TCP_THROUGHPUT", "28000"))
PORTS_MIN_TOTAL = int(os.environ.get("PORTS_MIN_TOTAL", "10"))
PORTS_MAX_TOTAL = int(os.environ.get("PORTS_MAX_TOTAL", "80"))

HOT_MIN_COUNT = int(os.environ.get("HOT_MIN_COUNT", "5"))
HOT_SHARE = float(os.environ.get("HOT_SHARE", "0.5"))

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
    """只数不展开。重叠前缀用 collapse_addresses 合并，与扫描脚本的去重口径一致。"""
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


def finalize():
    """扫描成功后才把选中端口标记为已扫 —— 失败的轮次不该消耗轮转配额，
    否则那些端口会被延后整整一圈。"""
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
    save_state(STATE_FILE, st)
    print(f"[OK] finalize: {n} 个端口标记为已扫", flush=True)


def main():
    if "--finalize" in sys.argv:
        finalize()
        return

    st = load_state(STATE_FILE)
    ports = st["ports"]
    default_ports = sorted(parse_ports(DEFAULT_PORTS))
    default_set = set(default_ports)

    # ---- IP 数：用于把时间预算换算成端口配额 ----
    fetched = count_asn_ips(ASN)
    prev = int(st.get("ip_count_seen", 0) or 0)
    if fetched <= 0:
        ip_count = prev
        src = "历史缓存（本次拉取失败）"
    elif prev > 0 and fetched < prev * 0.5:
        # BGP API 偶发返回不全。若据此算配额，端口数会被放大数倍，
        # 而扫描脚本自己拉到完整 IP 列表时就会严重超时。
        ip_count = prev
        src = f"历史缓存（本次仅拿到 {fetched:,}，不足历史 {prev:,} 的一半）"
    else:
        ip_count = fetched
        src = "实时拉取"
        st["ip_count_seen"] = fetched
    if ip_count <= 0:
        ip_count = 80000
        src = "兜底估值"
    print(f"[*] AS{ASN} IP 数: {ip_count:,}（{src}）", flush=True)

    # ---- 时间预算 → 端口配额 ----
    budget_targets = SCAN_BUDGET_MIN * TCP_THROUGHPUT
    raw_total = int(budget_targets // max(1, ip_count))
    total_ports = max(PORTS_MIN_TOTAL, min(PORTS_MAX_TOTAL, raw_total))
    print(f"[*] 预算 {SCAN_BUDGET_MIN:.0f} 分钟 × {TCP_THROUGHPUT:,.0f}/分钟 "
          f"= {budget_targets:,.0f} 目标 → 端口配额 {raw_total} "
          f"（夹到 [{PORTS_MIN_TOTAL},{PORTS_MAX_TOTAL}] → {total_ports}）",
          flush=True)

    pool = [int(k) for k in ports if int(k) not in default_set]
    extra_quota = max(0, total_ports - len(default_ports))

    # ---- 高频优先 ----
    hot_all = sorted(
        (p for p in pool if int(ports[str(p)].get("count", 1) or 1) >= HOT_MIN_COUNT),
        key=lambda p: (-int(ports[str(p)].get("count", 1) or 1), p))
    hot_cap = int(extra_quota * HOT_SHARE)
    hot_sel = hot_all[:hot_cap]

    # ---- 其余按最久没扫排序 ----
    rest = [p for p in pool if p not in set(hot_sel)]
    rest.sort(key=lambda p: (int(ports[str(p)].get("last_scanned", 0) or 0),
                             -int(ports[str(p)].get("count", 1) or 1), p))
    rotate_sel = rest[:max(0, extra_quota - len(hot_sel))]

    selected = sorted(set(hot_sel) | set(rotate_sel))
    merged = sorted(default_set | set(selected))
    merged_str = ",".join(str(p) for p in merged)

    st["pending_selected"] = selected
    save_state(STATE_FILE, st)

    est_targets = ip_count * len(merged)
    est_min = est_targets / TCP_THROUGHPUT
    cycle = math.ceil(len(pool) / max(1, len(rotate_sel))) if rotate_sel else 0

    print(f"[*] 档案 {len(ports)} 个端口（可轮转 {len(pool)}，"
          f"频次≥{HOT_MIN_COUNT} 的 {len(hot_all)}）", flush=True)
    print(f"[*] 本轮: 默认 {len(default_ports)} + 高频 {len(hot_sel)} "
          f"+ 轮转 {len(rotate_sel)} = {len(merged)} 个端口", flush=True)
    print(f"[*] 预计 {est_targets:,} 目标 / TCP 约 {est_min:.0f} 分钟"
          f"（+TLS/API 约 20-40 分钟）", flush=True)
    if cycle:
        print(f"[*] 轮转一圈约需 {cycle} 轮", flush=True)

    write_env({
        "MERGED_PORTS": merged_str,
        "MERGED_PORTS_COUNT": len(merged),
        "POOL_COUNT": len(ports),
        "HOT_COUNT": len(hot_sel),
        "ROTATE_COUNT": len(rotate_sel),
        "CYCLE_ROUNDS": cycle,
        "EST_MINUTES": f"{est_min:.0f}",
        "IP_COUNT": ip_count,
    })


if __name__ == "__main__":
    main()
