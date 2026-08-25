#!/usr/bin/env python3
"""
批量查询 ASN 的 IPv4 规模，估算扫描耗时，给出分层建议。

读 collect_dmit_ports.py 产出的 survey_asns.json（每个 ASN 的命中条数、
去重端口数、标签），补上 IP 数后算出：
    总目标数 = IP 数 × 端口数
    masscan 耗时 ≈ 目标数 / 100,000   （rate 5000pps、retries 2 → 约 10 万目标/分钟）
    asyncio 耗时 ≈ 目标数 / 35,000    （实测值）
再按单轮预算把 ASN 分成三层：能一轮扫完的、要独立线的、必须断点续扫的。
"""
import ipaddress
import json
import os
import time
import urllib.request

SURVEY_FILE = os.environ.get("SURVEY_FILE", "survey_asns.json")
REPORT_FILE = os.environ.get("REPORT_FILE", "asn_ip_report.txt")
ASN_EXTRA = os.environ.get("ASN_EXTRA", "")

BUDGET_MIN = float(os.environ.get("SCAN_BUDGET_MIN", "170"))
THR_MASSCAN = float(os.environ.get("THR_MASSCAN", "100000"))
THR_ASYNCIO = float(os.environ.get("THR_ASYNCIO", "35000"))
SLEEP_BETWEEN = float(os.environ.get("SLEEP_BETWEEN", "0.4"))

FETCH_TIMEOUT = 20
UA = {"User-Agent": "Mozilla/5.0"}


def _ripe(asn):
    url = (f"https://stat.ripe.net/data/announced-prefixes/data.json"
           f"?resource=AS{asn}")
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
        data = json.loads(r.read().decode())
    return [p["prefix"] for p in data.get("data", {}).get("prefixes", [])
            if p.get("prefix") and ":" not in p["prefix"]]


def _bgpview(asn):
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
        data = json.loads(r.read().decode())
    return [p["prefix"] for p in
            data.get("data", {}).get("ipv4_prefixes", []) if p.get("prefix")]


def count_ips(asn):
    """返回 (可用主机数, 前缀数, 数据源)。失败返回 (0, 0, "fail")。"""
    prefixes, src = [], "fail"
    for fn, label in ((_ripe, "RIPE"), (_bgpview, "bgpview")):
        try:
            prefixes = fn(asn)
            if prefixes:
                src = label
                break
        except Exception:
            continue
    if not prefixes:
        return 0, 0, src

    nets = []
    for c in prefixes:
        try:
            n = ipaddress.ip_network(c, strict=False)
            if n.version == 4:
                nets.append(n)
        except Exception:
            continue
    if not nets:
        return 0, len(prefixes), src

    total = 0
    # collapse 掉重叠前缀，否则 /15 和 /16 同时宣告会重复计数
    for net in ipaddress.collapse_addresses(nets):
        n = net.num_addresses
        total += n if net.prefixlen >= 31 else max(0, n - 2)
    return total, len(prefixes), src


def tier(est_min):
    if est_min <= 0:
        return "?"
    if est_min <= 30:
        return "长尾(可合并)"
    if est_min <= BUDGET_MIN:
        return "独立线"
    return "需断点续扫"


def main():
    rows = {}
    if os.path.exists(SURVEY_FILE):
        with open(SURVEY_FILE, encoding="utf-8") as f:
            rows = json.load(f)
        print(f"[*] 读入 {SURVEY_FILE}：{len(rows)} 个 ASN", flush=True)
    else:
        print(f"[!] 找不到 {SURVEY_FILE}，只查 ASN_EXTRA", flush=True)

    for x in (ASN_EXTRA or "").replace(" ", "").split(","):
        a = x.upper().replace("AS", "")
        if a.isdigit() and a not in rows:
            rows[a] = {"hits": 0, "ports": 0, "label": "(手动补充)"}

    if not rows:
        print("[-] 没有待查 ASN", flush=True)
        return

    out = []
    for i, (asn, info) in enumerate(
            sorted(rows.items(), key=lambda kv: -int(kv[1].get("hits", 0))), 1):
        ips, npfx, src = count_ips(asn)
        ports = int(info.get("ports", 0) or 0)
        targets = ips * ports
        est_m = targets / THR_MASSCAN if targets else 0
        est_a = targets / THR_ASYNCIO if targets else 0
        out.append({
            "asn": asn,
            "label": info.get("label", ""),
            "hits": int(info.get("hits", 0) or 0),
            "ports": ports,
            "ips": ips,
            "prefixes": npfx,
            "src": src,
            "targets": targets,
            "est_masscan": est_m,
            "est_asyncio": est_a,
            "tier": tier(est_m),
        })
        print(f"  [{i}/{len(rows)}] AS{asn:<8} IP={ips:>12,} "
              f"端口={ports:<4} → {est_m:>6.0f} 分钟(masscan)  {info.get('label','')}",
              flush=True)
        time.sleep(SLEEP_BETWEEN)

    lines = []
    lines.append(f"{'ASN':<9}{'条数':>6}{'端口':>6}{'IPv4':>14}"
                 f"{'目标数':>14}{'masscan':>9}{'asyncio':>9}  {'层级':<14}标签")
    lines.append("-" * 118)
    for r in out:
        lines.append(
            f"AS{r['asn']:<7}{r['hits']:>6}{r['ports']:>6}{r['ips']:>14,}"
            f"{r['targets']:>14,}{r['est_masscan']:>8.0f}m{r['est_asyncio']:>8.0f}m"
            f"  {r['tier']:<14}{r['label']}")

    fail = [r["asn"] for r in out if r["ips"] <= 0]
    tot_ips = sum(r["ips"] for r in out)
    lines.append("-" * 118)
    lines.append(f"合计 {len(out)} 个 ASN | IPv4 总量 {tot_ips:,}")
    for t in ("需断点续扫", "独立线", "长尾(可合并)", "?"):
        grp = [r for r in out if r["tier"] == t]
        if not grp:
            continue
        tot = sum(r["est_masscan"] for r in grp)
        lines.append(f"  {t:<14} {len(grp):>3} 个 | masscan 合计 {tot:>6.0f} 分钟")
    if fail:
        lines.append(f"  查询失败: {', '.join('AS' + a for a in fail)}")

    text = "\n".join(lines)
    print("\n" + text, flush=True)
    with open(REPORT_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(text + "\n")
    with open("asn_ip_report.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[OK] 已写出 {REPORT_FILE} 和 asn_ip_report.json", flush=True)


if __name__ == "__main__":
    main()
