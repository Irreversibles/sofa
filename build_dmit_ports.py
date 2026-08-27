#!/usr/bin/env python3
"""
决定本轮扫哪些端口、以及本轮到底跑不跑。

支持多 ASN（ASN="906,32519"）：同一家服务商的多个 ASN 共用一条扫描线。
    一次扫描的端口列表同时打在所有 ASN 的 IP 段上，所以端口的"扫过"状态
    是全局的 —— 合并视图里 count 相加、last_scanned 取各桶最大值，
    finalize 时写回每个含该端口的桶。
    轮转进度/EMA/pending 这些进程状态存在第一个 ASN（主桶）。

严格覆盖优先：只要池子里还有没扫过的端口(last_scanned==0)，就只从未扫
    端口里选，绝不复扫 —— 哪怕配额没用满。只有整个池子都扫过一遍后，
    才进入复扫（最久没扫的优先）。
配额：按时间预算反推，用实测吞吐(EMA)自校准。
节奏：按 cycle（轮转一圈需要几轮）自适应。
截断：被闸门截断而没扫全的端口不标记已扫，下轮自动优先补。

模式：
    默认        选端口 + 决策 SHOULD_RUN，写进 GITHUB_ENV（含 SCAN_TARGET）
    --finalize  扫描后调用，标记真正扫完的端口 + EMA 更新吞吐 + 记录时刻
                ASN 应由 workflow 继承 build 写出的 SCAN_TARGET，不要另写
                一份列表 —— 两处不一致时，缺失桶的 last_scanned 永远标不上，
                那些端口每轮被重选、轮转不推进，且日志看不出异常。

注意：本脚本和扫描器各自独立拉一遍 ASN 前缀（这里为算配额、那边为生成
    masscan 目标）。两者可能拿到不同结果 —— 如果这里少拿到几个 ASN 却
    照旧分配端口，实际扫描量就会超预算。所以下面对拉取失败做了护栏。
"""
import ipaddress
import json
import math
import os
import re
import sys
import time
import urllib.request

from port_state import load_state, save_state, now_ts, get_bucket

STATE_FILE = os.environ.get("STATE_FILE", "dmit_ports_state.json")

# ASN 不做静默兜底：DMIT / xTom / 长尾三条线共用本脚本，若 ASN 传空
# （变量名写错、YAML 缩进错、SCAN_TARGET 未继承到）而这里默认回 906，
# 本该扫长尾的那轮会变成扫 DMIT，还会去标记 DMIT 桶的 last_scanned、
# 污染那条线的轮转进度。宁可整轮失败（可见）也不猜（静默错）。
_raw_asn = os.environ.get("ASN", "").strip()
ASN_LIST = [x.upper().replace("AS", "").strip()
            for x in re.split(r"[\s,]+", _raw_asn) if x.strip()]
ASN_LIST = [x for x in ASN_LIST if x.isdigit()]
if not ASN_LIST:
    print(f"[-] ASN 未设置或无有效值（收到: {_raw_asn!r}）。拒绝猜测目标，退出。",
          flush=True)
    sys.exit(1)
# 去重但保序：主桶必须稳定是第一个，否则轮转进度会换地方存
_seen = set()
ASN_LIST = [a for a in ASN_LIST if not (a in _seen or _seen.add(a))]
PRIMARY_ASN = ASN_LIST[0]

DEFAULT_PORTS = os.environ.get("DEFAULT_PORTS", "443,8443,2053,2083,2096")

SCAN_BUDGET_MIN = float(os.environ.get("SCAN_BUDGET_MIN", "170"))
TCP_THROUGHPUT_INIT = float(os.environ.get("TCP_THROUGHPUT", "60000"))
THROUGHPUT_SAFETY = float(os.environ.get("THROUGHPUT_SAFETY", "0.85"))
EMA_ALPHA = float(os.environ.get("EMA_ALPHA", "0.5"))
PORTS_MIN_TOTAL = int(os.environ.get("PORTS_MIN_TOTAL", "10"))
PORTS_MAX_TOTAL = int(os.environ.get("PORTS_MAX_TOTAL", "80"))

# 前缀拉取失败占比超过此值 → 本次 IP 数不可信，改用历史缓存
FETCH_FAIL_ABORT_RATIO = float(os.environ.get("FETCH_FAIL_ABORT_RATIO", "0.34"))
# ASN 较多时给 RIPE stat 留间隔，避免快速连发被限流
FETCH_GAP_SEC = float(os.environ.get("FETCH_GAP_SEC", "0.5"))

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


def count_asn_ips(asn_list):
    """多个 ASN 的前缀合并后 collapse 再计数 —— 同一家的多个 ASN 常有
    重叠宣告，不合并会重复计数、把配额算大。

    返回 (总 IP 数, 拉取失败的 ASN 数)。失败数交给调用方判断可信度：
    静默按剩下的 ASN 算会低估 IP 数 → 多分端口 → 实际扫描超预算。
    """
    nets = []
    failed = []
    many = len(asn_list) > 4
    for i, asn in enumerate(asn_list):
        if many and i > 0:
            time.sleep(FETCH_GAP_SEC)
        prefixes = []
        for fn, label in ((_prefixes_ripe, "RIPE"), (_prefixes_bgpview, "bgpview")):
            try:
                prefixes = fn(asn)
                if prefixes:
                    print(f"[*] AS{asn} {label}: {len(prefixes)} 个 IPv4 前缀",
                          flush=True)
                    break
            except Exception as e:
                print(f"[!] AS{asn} {label} 拉取失败: {type(e).__name__}", flush=True)
        if not prefixes:
            print(f"[!] AS{asn} 前缀拉取失败，本次不计入", flush=True)
            failed.append(asn)
            continue
        for c in prefixes:
            try:
                n = ipaddress.ip_network(c, strict=False)
                if n.version == 4:
                    nets.append(n)
            except Exception:
                continue

    if failed:
        print(f"[!] 共 {len(failed)}/{len(asn_list)} 个 ASN 拉取失败: "
              f"AS{',AS'.join(failed)}", flush=True)

    if not nets:
        return 0, len(failed)
    total = 0
    for net in ipaddress.collapse_addresses(nets):
        n = net.num_addresses
        total += n if net.prefixlen >= 31 else max(0, n - 2)
    return total, len(failed)


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


def merged_pool(st):
    """把各 ASN 桶的端口合并成虚拟池：{端口: {count, last_scanned}}"""
    pool = {}
    for a in ASN_LIST:
        b = get_bucket(st, a)
        for k, rec in b["ports"].items():
            m = pool.setdefault(int(k), {"count": 0, "last_scanned": 0})
            m["count"] += int(rec.get("count", 1) or 1)
            m["last_scanned"] = max(m["last_scanned"],
                                    int(rec.get("last_scanned", 0) or 0))
    return pool


def _read_done_ports():
    try:
        with open(DONE_FILE, "r", encoding="utf-8") as f:
            return [int(x) for x in f.read().split() if x.isdigit()]
    except Exception:
        return None


def _read_metrics():
    try:
        with open(METRICS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def finalize():
    st = load_state(STATE_FILE)
    pb = get_bucket(st, PRIMARY_ASN)
    ts = now_ts()

    done = _read_done_ports()
    pend = [int(p) for p in pb.get("pending_selected", []) if str(p).isdigit()]
    mark = pend if done is None else [p for p in pend if p in set(done)]

    n = 0
    for a in ASN_LIST:
        b = get_bucket(st, a)
        for p in mark:
            rec = b["ports"].get(str(p))
            if rec is not None:
                rec["last_scanned"] = ts
                n += 1
    skipped = len(pend) - len(mark)

    # 跨桶写入为 0 通常意味着 ASN 列表和 build 那次不一致（继承 SCAN_TARGET
    # 就不会），或 pending 为空（build 没选出端口）。明确报出来，别静默。
    if mark and n == 0:
        print(f"[!] 标记了 {len(mark)} 个端口但没有任何桶命中 —— "
              f"ASN 列表可能与 build 时不一致（当前 AS{','.join(ASN_LIST)}）",
              flush=True)

    m = _read_metrics()
    measured = float(m.get("tcp_throughput_per_min", 0) or 0)
    if measured > 0:
        prev = float(pb.get("throughput_ema", 0) or 0)
        new_ema = measured if prev <= 0 else EMA_ALPHA * measured + (1 - EMA_ALPHA) * prev
        pb["throughput_ema"] = round(new_ema, 1)
        print(f"[OK] 吞吐 EMA: {prev:,.0f} + 实测 {measured:,.0f} "
              f"-> {new_ema:,.0f} 目标/分钟", flush=True)

    pb["pending_selected"] = []
    pb["last_scan_ts"] = ts
    save_state(STATE_FILE, st)
    print(f"[OK] finalize AS{','.join(ASN_LIST)}: 标记 {len(mark)} 个端口"
          f"（跨桶写入 {n} 条）"
          f"{f'，截断未扫 {skipped} 个（下轮优先补）' if skipped else ''}，"
          f"last_scan_ts={ts}", flush=True)


def main():
    if "--finalize" in sys.argv:
        finalize()
        return

    st = load_state(STATE_FILE)
    pb = get_bucket(st, PRIMARY_ASN)
    pool_map = merged_pool(st)
    default_ports = sorted(parse_ports(DEFAULT_PORTS))
    default_set = set(default_ports)

    asn_desc = ",".join(ASN_LIST)
    print(f"[*] 扫描目标 AS{asn_desc}（{len(ASN_LIST)} 个，主桶 AS{PRIMARY_ASN}）",
          flush=True)

    fetched, failed = count_asn_ips(ASN_LIST)
    prev = int(pb.get("ip_count_seen", 0) or 0)
    fail_ratio = failed / len(ASN_LIST)

    if fetched <= 0:
        ip_count = prev
        src = "历史缓存（本次全部拉取失败）"
    elif failed and fail_ratio >= FETCH_FAIL_ABORT_RATIO and prev > 0:
        # 丢的都是小段时，下面那条"对半砍"护栏挡不住，靠失败占比兜
        ip_count = prev
        src = (f"历史缓存（{failed}/{len(ASN_LIST)} 个 ASN 失败，"
               f"本次 {fetched:,} 不可信）")
    elif prev > 0 and fetched < prev * 0.5:
        ip_count = prev
        src = f"历史缓存（本次仅 {fetched:,}，不足历史 {prev:,} 的一半）"
    elif failed == 0:
        ip_count = fetched
        src = "实时拉取"
        pb["ip_count_seen"] = fetched
    else:
        # 部分失败时不写缓存：否则偏低的值被固化成"历史"，下轮的对半砍
        # 护栏就以它为基准，一路越滑越低
        ip_count = fetched
        src = f"实时拉取（{failed} 个 ASN 失败，本次不更新缓存）"
    if ip_count <= 0:
        ip_count = 80000
        src = "兜底估值"
    print(f"[*] IP 数: {ip_count:,}（{src}）", flush=True)

    ema = float(pb.get("throughput_ema", 0) or 0)
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
    if total_ports > raw_total:
        print(f"[!] 配额被下限提到 {total_ports}（预算只够 {raw_total}），"
              f"本轮可能超时，靠扫描器的时间闸门兜", flush=True)

    pool = [p for p in pool_map if p not in default_set]
    extra_quota = max(0, total_ports - len(default_ports))

    def ls(p):
        return int(pool_map[p]["last_scanned"])

    def cnt(p):
        return int(pool_map[p]["count"])

    unscanned = sorted((p for p in pool if ls(p) == 0),
                       key=lambda p: (-cnt(p), p))
    scanned = sorted((p for p in pool if ls(p) > 0),
                     key=lambda p: (ls(p), -cnt(p), p))

    if unscanned:
        selected = sorted(unscanned[:extra_quota])
        phase = "覆盖中"
    elif scanned:
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

    pb["pending_selected"] = selected
    save_state(STATE_FILE, st)

    cycle = math.ceil(len(pool) / max(1, extra_quota)) if extra_quota > 0 else 1
    interval = interval_for_cycle(cycle)
    last_scan_ts = int(pb.get("last_scan_ts", 0) or 0)
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

    print(f"[*] 合并档案 {len(pool_map)} 端口（可轮转 {len(pool)}，"
          f"未扫 {len(unscanned)}，已扫 {len(scanned)}）", flush=True)
    print(f"[*] 阶段={phase} | 本轮: 默认 {len(default_ports)} + 新扫 {new_sel} "
          f"+ 复扫 {rescan_sel} = {len(merged)} 端口"
          f"（待覆盖剩余 {remaining_unscanned}）", flush=True)
    print(f"[*] 轮转一圈 {cycle} 轮 → 间隔 {interval} 天 | {reason} "
          f"→ SHOULD_RUN={should_run}", flush=True)
    print(f"[*] 预计 {ip_count * len(merged):,} 目标 / 约 {est_min:.0f} 分钟", flush=True)

    write_env({
        "SHOULD_RUN": "true" if should_run else "false",
        # finalize 继承这个值当 ASN，保证两处列表永远一致
        "SCAN_TARGET": asn_desc,
        "MERGED_PORTS": merged_str,
        "MERGED_PORTS_COUNT": len(merged),
        "POOL_COUNT": len(pool_map),
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
