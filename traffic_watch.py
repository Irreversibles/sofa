#!/usr/bin/env python3
"""
拉取公开仓库的访问统计，追加成长期历史，异常时报警。

GitHub Traffic API 只保留 14 天，且只给聚合数字 —— 独立访客/克隆者是
去重计数，不含用户名、不含 IP。所以这里能回答"有没有人在盯"，
回答不了"是谁"。存成历史是为了绕过 14 天窗口，看出趋势。

报警三条（任一触发即报）：
  - 独立克隆者 ≥ CLONE_ALERT：路人只浏览，克隆意味着想留一份
  - 独立访客较前 7 天均值翻 RATIO 倍：突然被传播
  - 热门路径命中敏感文件（workflow / 脚本）：在读实现，不是路过

需要对目标仓库有 push 权限的 token（classic PAT 的 repo scope 即可）。
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

TOKEN = os.environ["GH_TOKEN"]
REPO = os.environ.get("WATCH_REPO", "")           # 形如 owner/name
HISTORY = os.environ.get("HISTORY_FILE", "traffic/traffic_history.json")

CLONE_ALERT = int(os.environ.get("CLONE_ALERT", "3"))
VIEW_RATIO = float(os.environ.get("VIEW_RATIO", "2.0"))
VIEW_MIN = int(os.environ.get("VIEW_MIN", "5"))    # 低于此数不谈倍数，避免 1→2 报警
BASELINE_DAYS = int(os.environ.get("BASELINE_DAYS", "7"))

# 命中即报警：说明访客在读实现细节
SENSITIVE_RE = re.compile(r"(\.github/workflows/|\.py$|\.yml$|\.yaml$)")

API = "https://api.github.com"


def get(path):
    req = urllib.request.Request(
        f"{API}/repos/{REPO}/{path}",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "traffic-watch",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def load_history():
    try:
        with open(HISTORY, "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict) and "days" in d:
            return d
    except Exception:
        pass
    return {"repo": REPO, "days": {}, "paths": {}, "referrers": {}}


def save_history(h):
    os.makedirs(os.path.dirname(HISTORY) or ".", exist_ok=True)
    tmp = HISTORY + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(h, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp, HISTORY)


def main():
    if not REPO:
        print("[-] WATCH_REPO 未设置", flush=True)
        return 1

    try:
        views = get("traffic/views")
        clones = get("traffic/clones")
        paths = get("traffic/popular/paths")
        refs = get("traffic/popular/referrers")
    except urllib.error.HTTPError as e:
        # 403 通常是 token 没有 push 权限；404 是仓库名写错
        print(f"[-] Traffic API 失败: HTTP {e.code} —— "
              f"{'token 权限不足（需 push）' if e.code == 403 else '检查仓库名'}",
              flush=True)
        return 1
    except Exception as e:
        print(f"[-] Traffic API 失败: {type(e).__name__}", flush=True)
        return 1

    h = load_history()
    days = h["days"]

    # API 返回的每日数据覆盖写入：同一天多次运行时后者更完整
    for d in views.get("views", []):
        key = d["timestamp"][:10]
        days.setdefault(key, {})
        days[key]["views"] = d["count"]
        days[key]["uniques"] = d["uniques"]
    for d in clones.get("clones", []):
        key = d["timestamp"][:10]
        days.setdefault(key, {})
        days[key]["clones"] = d["count"]
        days[key]["clone_uniques"] = d["uniques"]

    # 路径和来源只有 Top 10 快照、无日期，记录累计峰值和最后出现时间
    now = time.strftime("%Y-%m-%d", time.gmtime())
    for p in paths:
        rec = h["paths"].setdefault(p["path"], {})
        rec["max_uniques"] = max(rec.get("max_uniques", 0), p["uniques"])
        rec["last_seen"] = now
    for r in refs:
        rec = h["referrers"].setdefault(r["referrer"], {})
        rec["max_uniques"] = max(rec.get("max_uniques", 0), r["uniques"])
        rec["last_seen"] = now

    save_history(h)

    # ---- 报警判定：只看最近一个有数据的完整日 ----
    keys = sorted(days)
    today = keys[-1] if keys else None
    cur = days.get(today, {}) if today else {}
    cur_uniq = int(cur.get("uniques", 0))
    cur_clone_uniq = int(cur.get("clone_uniques", 0))

    baseline_keys = keys[-(BASELINE_DAYS + 1):-1]
    base_vals = [int(days[k].get("uniques", 0)) for k in baseline_keys]
    baseline = sum(base_vals) / len(base_vals) if base_vals else 0.0

    alerts = []
    if cur_clone_uniq >= CLONE_ALERT:
        alerts.append(f"独立克隆者 {cur_clone_uniq}（阈值 {CLONE_ALERT}）")
    if (cur_uniq >= VIEW_MIN and baseline > 0
            and cur_uniq >= baseline * VIEW_RATIO):
        alerts.append(f"独立访客 {cur_uniq}，为前 {len(base_vals)} 日均值 "
                      f"{baseline:.1f} 的 {cur_uniq/baseline:.1f} 倍")

    hot = [p for p in paths if SENSITIVE_RE.search(p["path"])]
    if hot:
        top = sorted(hot, key=lambda x: -x["uniques"])[:3]
        detail = "、".join(f"{p['path'].split('/')[-1]}({p['uniques']})"
                          for p in top)
        alerts.append(f"敏感路径被访问: {detail}")

    print(f"[*] {REPO} | {today} 浏览 {cur.get('views', 0)} / "
          f"独立访客 {cur_uniq} | 克隆 {cur.get('clones', 0)} / "
          f"独立克隆者 {cur_clone_uniq}", flush=True)
    print(f"[*] 14 日合计: 浏览 {views.get('count', 0)} / "
          f"独立 {views.get('uniques', 0)} | 克隆 {clones.get('count', 0)} / "
          f"独立 {clones.get('uniques', 0)}", flush=True)
    print(f"[*] 历史累计 {len(days)} 天 | 已见路径 {len(h['paths'])} 个 | "
          f"来源 {len(h['referrers'])} 个", flush=True)

    if refs:
        print("[*] 当前来源 Top:", flush=True)
        for r in sorted(refs, key=lambda x: -x["uniques"])[:5]:
            print(f"      {r['referrer']:<28} 独立 {r['uniques']}", flush=True)

    # 写给 workflow 用：有内容就推 TG
    msg = ""
    if alerts:
        msg = ("⚠️ 仓库访问异常%0A" + f"仓库: {REPO}%0A日期: {today}%0A"
               + "%0A".join(f"• {a}" for a in alerts))
        print(f"[!] 触发报警 {len(alerts)} 条", flush=True)
    else:
        print("[OK] 无异常", flush=True)

    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as f:
            f.write(f"TRAFFIC_ALERT={msg}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
