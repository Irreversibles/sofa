#!/usr/bin/env python3
"""
把 CSV 里的端口导入 dmit_ports_state.json 的指定 ASN 桶（CI 版，参数走环境变量）。

严格对齐两个 collect 脚本的写法：
  字段  {"count","first_seen","last_seen","last_scanned"} 四个都写
  口径  整个文件里同一端口只记 +1（一次"发布事件"），不按行数累加 ——
        一个 CSV 可能几百行都是 443，按行加会让频次压过 bot 消息
        （那边一条消息 +1），build 的 (-count, port) 排序就失真了
  建桶  走 get_bucket，结构与 build_dmit_ports.py 一致

已存在的端口只 count+1、刷 last_seen，绝不动 last_scanned —— 不会把扫过的
端口重置成未扫、打乱轮转进度。

日志只输出端口，不输出任何 IP（CSV 在私库，但 Actions 日志登录可见）。

环境变量：
    CSV_FILE        CSV 路径
    ASN             写入哪个桶，如 906
    STATE_FILE      默认 dmit_ports_state.json
    PORT_COL        端口列号（从1开始），0=自动识别
    REQUIRE         行过滤 "列名或列号:文本"，如 "ASN组织:DMIT"
    NEW_AS_RESCAN   1=新端口 last_scanned 置 1（进复扫队列，不阻塞覆盖进度）
    APPLY           1=写入，否则只打印
"""
import csv
import io
import math
import os
import sys

from port_state import load_state, save_state, now_ts, get_bucket

STATE_FILE = os.environ.get("STATE_FILE", "dmit_ports_state.json")
CSV_FILE = os.environ.get("CSV_FILE", "").strip()
ASN = os.environ.get("ASN", "").strip().upper().replace("AS", "")
PORT_COL = int(os.environ.get("PORT_COL", "0") or 0)
REQUIRE = os.environ.get("REQUIRE", "").strip()
NEW_AS_RESCAN = os.environ.get("NEW_AS_RESCAN", "0") == "1"
APPLY = os.environ.get("APPLY", "0") == "1"
QUOTA = int(os.environ.get("ROTATE_QUOTA", "3") or 3)


def decode_file(path):
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin1", errors="ignore")


def ports_in_csv(text):
    """返回 (端口集合, 总行数, 跳过行数)。列定位同 collect_csv_ports。"""
    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        return set(), 0, 0

    idx = 1
    for i, cell in enumerate(header):
        c = (cell or "").strip().lower()
        if "端口" in (cell or "") or c == "port":
            idx = i
            break
    if PORT_COL:
        idx = PORT_COL - 1
    print(f"[*] 表头 {len(header)} 列 | 端口列 = 第 {idx + 1} 列 "
          f"({header[idx] if idx < len(header) else '?'})", flush=True)

    req_i, req_v = None, ""
    if REQUIRE and ":" in REQUIRE:
        name, req_v = REQUIRE.split(":", 1)
        name, req_v = name.strip(), req_v.strip().lower()
        if name.isdigit():
            req_i = int(name) - 1
        else:
            for i, cell in enumerate(header):
                if name.lower() in (cell or "").strip().lower():
                    req_i = i
                    break
        if req_i is None:
            print(f"[!] REQUIRE 的列 {name!r} 未找到，不做行过滤", flush=True)
        else:
            print(f"[*] 行过滤：第 {req_i + 1} 列 ({header[req_i]}) "
                  f"含 {req_v!r}", flush=True)

    out, total, skipped = set(), 0, 0
    for row in reader:
        total += 1
        if req_i is not None:
            if req_i >= len(row) or req_v not in str(row[req_i]).lower():
                skipped += 1
                continue
        if idx >= len(row):
            skipped += 1
            continue
        v = str(row[idx]).strip().rsplit(":", 1)[-1]
        if not v.isdigit():
            skipped += 1
            continue
        p = int(v)
        if 1 <= p <= 65535:
            out.add(p)
        else:
            skipped += 1
    return out, total, skipped


def main():
    if not ASN.isdigit():
        print(f"[-] ASN 不合法: {os.environ.get('ASN')!r}", flush=True)
        return 1
    if not CSV_FILE or not os.path.exists(CSV_FILE):
        print(f"[-] 找不到 CSV: {CSV_FILE!r}", flush=True)
        return 1
    if not os.path.exists(STATE_FILE):
        print(f"[-] 找不到 {STATE_FILE}（私库里没拉到？）", flush=True)
        return 1

    ports, total, skipped = ports_in_csv(decode_file(CSV_FILE))
    if not ports:
        print(f"[-] 没解析到端口（{total} 行，跳过 {skipped}）。"
              f"用 PORT_COL 指定列号。", flush=True)
        return 1
    print(f"[+] {total} 行 → {len(ports)} 个唯一端口"
          f"{f'，跳过 {skipped} 行' if skipped else ''}", flush=True)

    st = load_state(STATE_FILE)
    b = get_bucket(st, ASN, f"AS{ASN}")
    old_n = len(b["ports"])
    ts = now_ts()
    ls_new = 1 if NEW_AS_RESCAN else 0

    added, bumped = [], 0
    for p in sorted(ports):
        key = str(p)
        rec = b["ports"].get(key)
        if rec is None:
            b["ports"][key] = {"count": 1, "first_seen": ts,
                               "last_seen": ts, "last_scanned": ls_new}
            added.append(p)
        else:
            rec["count"] = int(rec.get("count", 1) or 1) + 1
            rec["last_seen"] = ts
            bumped += 1

    unscanned = sum(1 for r in b["ports"].values()
                    if int(r.get("last_scanned", 0) or 0) == 0)
    print(f"\n[*] 桶 AS{ASN}: {old_n} → {len(b['ports'])} 个端口", flush=True)
    print(f"      新增 {len(added)} | 已有端口 count+1 {bumped}", flush=True)
    if added:
        print(f"      新增示例 {added[:20]}"
              f"{' ...' if len(added) > 20 else ''}", flush=True)
    print(f"      新端口 last_scanned={ls_new}"
          f"（{'进复扫队列' if ls_new else '进未扫队列'}）", flush=True)

    rounds = math.ceil(unscanned / max(1, QUOTA))
    print(f"\n[*] 桶内未扫端口 {unscanned} 个，按每轮 {QUOTA} 个算，"
          f"约 {rounds} 轮覆盖一遍", flush=True)
    if ls_new == 0 and rounds > 30:
        print(f"[!] 轮数偏多。build 是严格覆盖优先：接下来 {rounds} 轮都在扫"
              f"这批新端口，已验证有货的高 count 端口在此期间不会复扫。"
              f"考虑改用 NEW_AS_RESCAN=1。", flush=True)

    if not APPLY:
        print(f"\n[*] APPLY 未开启，未写入。", flush=True)
        return 0

    save_state(STATE_FILE, st)
    print(f"\n[OK] 已写入 {STATE_FILE}", flush=True)

    env = os.environ.get("GITHUB_ENV")
    if env:
        with open(env, "a", encoding="utf-8") as f:
            f.write(f"IMPORT_ADDED={len(added)}\n")
            f.write(f"IMPORT_BUMPED={bumped}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())