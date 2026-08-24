#!/usr/bin/env python3
"""
决定本轮扫哪些端口、以及本轮到底跑不跑。

严格覆盖优先（本次核心）：
    只要池子里还有没扫过的端口(last_scanned==0)，就只从未扫端口里选，
    绝不复扫 —— 哪怕配额没用满。只有整个池子都扫过一遍后，才进入复扫
    阶段（最久没扫的优先）。频次不再是插队重扫的理由，只在"同为未扫"
    时决定谁先扫。这样保证：一圈没走完前，任何端口都不会被重复扫。

配额：按时间预算反推，用实测吞吐(EMA)自校准。
节奏：按 cycle（轮转一圈需要几轮）自适应。
截断：被闸门截断而没扫全的端口不标记已扫，下轮自动优先补。

模式：
    默认        选端口 + 决策 SHOULD_RUN，写进 GITHUB_ENV
    --finalize  扫描后调用，标记真正扫完的端口 + EMA 更新吞吐 + 记录时刻
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
TCP_THROUGHPUT_INIT = float(os.environ.get("TCP_THROUGHPUT", "22000"))
THROUGHPUT_SAFETY = float(os.environ.get("THROUGHPUT_SAFETY", "0.85"))
EMA_ALPHA = float(os.environ.get("EMA_ALPHA", "0.5"))
PORTS_MIN_TOTAL = int(os.environ.get("PORTS_MIN_TOTAL", "10"))
PORTS_MAX_TOTAL = int(os.environ.get("PORTS_MAX_TOTAL", "80"))

CADENCE_1 = int(os.environ.get("CADENCE_CYCLE1_DAYS", "3"))
CADENCE_2 = int(os.environ.get("CADENCE_CYCLE2_DAYS", "2"))
CADENCE_4 = int(os.environ.get("CADENCE_CYCLE4_DAYS", "1"))
FORCE_RUN = os.environ.get("FORCE_RUN", "0") == "1"

DONE_FILE = os.environ.get("SCAN_DONE_FILE", "scan_done_ports.txt")
METRICS_FILE = os.environ.get("SCAN_METRICS_FILE", "scan_metrics.json")

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


def _read_done_ports():
    try:
        with open(DONE_FILE, "r", encoding="utf-8") as f:
            return [int(x) for x in f.read().split() if x.isdigit()]
    except Exception:
        return None       # 文件不存在 = 没启用闸门 = 全部选中都算扫完


def _read_metrics():
    try:
        with open(METRICS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def finalize():
    st = load_state(STATE_FILE)
    ts = now_ts()

    # --- 只标记"真正扫完"的端口，被截断的保持旧 last_scanned 以便下轮优先 ---
    done = _read_done_ports()
    pend = [int(p) for p in st.get("pending_selected", []) if str(p).isdigit()]
    mark = pend if done is None else [p for p in pend if p in set(done)]
    n = 0
    for p in mark:
        rec = st["ports"].get(str(p))
        if rec is not None:
            rec["last_scanned"] = ts
            n += 1
    skipped = len(pend) - len(mark)

    # --- EMA 自校准吞吐 ---
    m = _read_metrics()
    measured = float(m.get("tcp_throughput_per_min", 0) or 0)
    if measured > 0:
        prev = float(st.get("throughput_ema", 0) or 0)
        new_ema = measured if prev <= 0 else EMA_ALPHA * measured + (1 - EMA_ALPHA) * prev
        st["throughput_ema"] = round(new_ema, 1)
        print(f"[OK] 吞吐 EMA: {prev:,.0f} + 实测 {measured:,.0f} "
              f"-> {new_ema:,.0f} 目标/分钟", flush=True)

    st["pending_selected"] = []
    st["last_scan_ts"] = ts
    save_state(STATE_FILE, st)
    print(f"[OK] finalize: 标记已扫 {n} 个"
          f"{f'，截断未扫 {skipped} 个（下轮优先补）' if skipped else ''}，"
          f"last_scan_ts={ts}", flush=True)


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

    ema = float(st.get("throughput_ema", 0) or 0)
    if ema > 0:
        thr = ema * THROUGHPUT_SAFETY
        thr_src = f"EMA {ema:,.0f}×{THROUGHPUT_SAFETY}"
    else:
        thr = TCP_THROUGHPUT_INIT * THROUGHPUT_SAFETY
        thr_src = f"初值 {TCP_THROUGHPUT_INIT:,.0f}×{THROUGHPUT_SAFETY}"

    budget_targets = SCAN_BUDGET_MIN * thr
    raw_total = int(budget_targets // max(1, ip_count))
    total_ports = max(PORTS_MIN_TOTAL, min(PORTS_MAX_TOTAL, raw_total))
    print(f"[*] 预算 {SCAN_BUDGET_MIN:.0f}min × {thr:,.0f}/min（{thr_src}）"
          f" = {budget_targets:,.0f} 目标 → 配额 {raw_total} "
          f"（夹到 [{PORTS_MIN_TOTAL},{PORTS_MAX_TOTAL}] → {total_ports}）",
          flush=True)

    pool = [int(k) for k in ports if int(k) not in default_set]
    extra_quota = max(0, total_ports - len(default_ports))

    def ls(p):
        return int(ports[str(p)].get("last_scanned", 0) or 0)

    def cnt(p):
        return int(ports[str(p)].get("count", 1) or 1)

    # ---- 严格覆盖优先 ----
    unscanned = sorted((p for p in pool if ls(p) == 0),
                       key=lambda p: (-cnt(p), p))       # 高频先扫
    scanned = sorted((p for p in pool if ls(p) > 0),
                     key=lambda p: (ls(p), -cnt(p), p))  # 复扫：最久没扫先

    if unscanned:
        # 本圈还有没扫过的 —— 只从未扫端口里选，配额没用满也不复扫
        selected = sorted(unscanned[:extra_quota])
        phase = "覆盖中"
    elif scanned:
        # 整个池子已扫过一遍 —— 进入复扫
        selected = sorted(scanned[:extra_quota])
        phase = "复扫"
    else:
        selected = []
        phase = "空池"

    new_sel = sum(1 for p in selected if ls(p) == 0)
    rescan_sel = len(selected) - new_sel
    remaining_unscanned = (max(0, len(unscanned) - len(selected))
                           if phase == "覆盖中" else 0)

    merged = sorted(default_set | set(selected))
    merged_str = ",".join(str(p) for p in merged)

    st["pending_selected"] = selected
    save_state(STATE_FILE, st)

    cycle = math.ceil(len(pool) / max(1, extra_quota)) if extra_quota > 0 else 1
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

    real_thr = ema if ema > 0 else TCP_THROUGHPUT_INIT
    est_min = (ip_count * len(merged)) / real_thr

    print(f"[*] 档案 {len(ports)} 端口（可轮转 {len(pool)}，未扫 {len(unscanned)}，"
          f"已扫 {len(scanned)}）", flush=True)
    print(f"[*] 阶段={phase} | 本轮: 默认 {len(default_ports)} + 新扫 {new_sel} "
          f"+ 复扫 {rescan_sel} = {len(merged)} 端口"
          f"（待覆盖剩余 {remaining_unscanned}）", flush=True)
    print(f"[*] 轮转一圈 {cycle} 轮 → 间隔 {interval} 天 | {reason} "
          f"→ SHOULD_RUN={should_run}", flush=True)
    print(f"[*] 预计 {ip_count * len(merged):,} 目标 / 约 {est_min:.0f} 分钟", flush=True)

    write_env({
        "SHOULD_RUN": "true" if should_run else "false",
        "MERGED_PORTS": merged_str,
        "MERGED_PORTS_COUNT": len(merged),
        "POOL_COUNT": len(ports),
        "NEW_COUNT": new_sel,
        "RESCAN_COUNT": rescan_sel,
        "SWEEP_PHASE": phase,
        "REMAINING_UNSCANNED": remaining_unscanned,
        "CYCLE_ROUNDS": cycle,
        "CADENCE_DAYS": interval,
        "EST_MINUTES": f"{est_min:.0f}",
        "IP_COUNT": ip_count,
    })


if __name__ == "__main__":
    main()
