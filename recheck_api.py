import asyncio
import sys
import os
import ipaddress
import time
import urllib.parse

import aiohttp

# ==================== 配置 ====================
CHECK_API = os.getenv("CHECK_API", "").strip()
# 并发 50：check_one 在 sem 内部重试，sleep 期间不释放槽位，
# API 完全无响应时单条最坏占用约 96 秒（30+2+30+4+30）。
# 并发 20 折算每分钟仅 12.5 条，120 分钟上限约 1500 条；50 可支撑约 3750 条。
CONCURRENCY = 50
TIMEOUT = 30                  # 非标端口握手慢，20 偏紧
API_RETRY = 2                 # API 异常时的重试次数
MIN_SURVIVE_RATIO = 0.15      # 存活率过低不覆盖（防API抽风误删）
API_ERROR_ABORT_RATIO = 0.3   # API异常占比超过此值 → 判定故障，整个文件不动

# 存活率保护的最小判定数：只有 1-2 条的文件（RESULT.txt 等）一旦全部失效，
# 存活率 0% 永远低于阈值 → 永不覆盖 → 死条目永久滞留。样本太小时统计
# 不显著，不套用该保护，交给"API异常占比"那道闸把关。
MIN_JUDGED_FOR_RATIO = 10

# 时间闸门：job 级 timeout 会取消整个 job，后续步骤即使标了 always() 也
# 不执行 —— 也就是整轮复验的结果全部丢失。所以必须在脚本内部留出余量，
# 到点就收工：已处理的文件正常写回、正常推送，剩余文件下轮继续。
DEADLINE_MIN = int(os.getenv("RECHECK_DEADLINE_MIN", "100"))
_START = time.monotonic()

SKIP_FILES = {"count.txt", "name.txt", "requirements.txt",
              "ip.txt", "recheck_summary.txt"}

# ==================== 新增：跳过国家配置 ====================
# 这些国家的条目不参与复验、不剔除、不被探测，原样保留。
# 这里用于跳过 CN Alibaba，避免自己扫出的国内IP被误判剔除。
KEEP_COUNTRIES = {"CN"}


def out_of_time():
    return (time.monotonic() - _START) / 60 >= DEADLINE_MIN


def parse_line(line):
    """解析 ip:port#地区 名字。返回 (ip, port, country, name)

    country 保留下来，供 API 异常时原样写回（不刷成 ??，避免 diff 噪音）
    """
    s = line.strip()
    if not s:
        return None
    try:
        addr = s.split("#")[0]
        ip_part, port_part = addr.rsplit(":", 1)
        ipaddress.ip_address(ip_part)
        port = int(port_part)
        country, name = "??", ""
        if "#" in s:
            after = s.split("#", 1)[1].split(None, 1)
            if after:
                country = after[0] or "??"
            name = after[1] if len(after) > 1 else ""
        return (ip_part, port, country, name)
    except Exception:
        return None


async def check_one(session, ip, port, sem):
    """返回 ("ok", country) / ("dead", "??") / ("error", "??")

    关键：区分"API 明确说不通"和"API 自己没答上来"，后者不删除。
    旧版把超时、CF错误页、网络抖动全归为"这个 proxyip 死了"，会误删存活条目。
    """
    async with sem:
        url = f"{CHECK_API}?proxyip={urllib.parse.quote(f'{ip}:{port}')}"
        for attempt in range(API_RETRY + 1):
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=TIMEOUT)
                ) as resp:
                    if resp.status != 200:
                        if attempt < API_RETRY:
                            await asyncio.sleep(2 * (attempt + 1))
                            continue
                        return ("error", "??")
                    ctype = (resp.headers.get("content-type") or "").lower()
                    if "json" not in ctype:
                        # CF 错误页（1027 超额 / 1102 超限）是 text/html，不是 Worker 在应答
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

            # 到这里说明 Worker 正常应答了，success 字段可信
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


def sort_key(line):
    try:
        addr = line.split("#")[0]
        ip_part, port_part = addr.rsplit(":", 1)
        country = line.split("#")[1].split()[0] if "#" in line else "??"
        return (country, ipaddress.ip_address(ip_part), int(port_part))
    except Exception:
        return ("??", ipaddress.ip_address("0.0.0.0"), 0)


def format_line(ip, port, country, name):
    """把条目格式化为 ip:port#country name，去掉尾部多余空格"""
    parts = [f"{ip}:{port}#{country}"]
    if name:
        parts.append(name)
    return " ".join(parts).rstrip()


async def main():
    if len(sys.argv) < 2:
        print("[-] 用法: python recheck_api.py 文件1.txt [文件2.txt ...]", flush=True)
        return
    if not CHECK_API:
        print("[-] CHECK_API 未配置，退出。", flush=True)
        return

    sem = asyncio.Semaphore(CONCURRENCY)
    summary = {}          # stem -> (剔除数, API异常数)
    truncated = False

    print(f"[*] 时间闸门: {DEADLINE_MIN} 分钟（到点收工，剩余文件下轮继续）",
          flush=True)

    async with aiohttp.ClientSession() as session:
        for fname in sys.argv[1:]:
            if out_of_time():
                truncated = True
                print(f"\n[!] 已达 {DEADLINE_MIN} 分钟闸门，剩余文件本轮不处理"
                      f"（已处理的正常写回，下轮继续）", flush=True)
                break

            base = os.path.basename(fname)
            stem = base[:-4] if base.lower().endswith(".txt") else base
            if stem.lower().endswith("-old"):
                print(f"[跳过] 备份文件: {fname}", flush=True)
                continue
            if base in SKIP_FILES:
                continue
            if not os.path.exists(fname):
                print(f"[-] 文件不存在: {fname}", flush=True)
                continue

            items = []
            keep_lines = []   # 需要原样保留的行（CN 等跳过国家 + 无法解析的行）
            with open(fname, "r", encoding="utf-8") as f:
                for line in f:
                    raw = line.strip()
                    if not raw:
                        continue
                    p = parse_line(raw)
                    if p:
                        ip, port, country, name = p
                        if country.upper() in KEEP_COUNTRIES:
                            # 跳过国家：不探测、不剔除、原样保留
                            keep_lines.append(raw)
                            continue
                        items.append((ip, port, country, name))
                    else:
                        # 解析失败的行也原样保留，避免误删
                        keep_lines.append(raw)

            total = len(items)
            skipped = len(keep_lines)
            if total == 0 and skipped:
                print(f"[跳过] {fname} 全部为保留国家/无效行（{skipped} 行），不检测、不改动。", flush=True)
                continue
            if total == 0:
                print(f"[!] {fname} 无有效行，跳过。", flush=True)
                continue

            print(f"\n[*] 复验 {fname}：共 {total} 条待检测"
                  f"（含 {skipped} 条保留国家不入检；并发{CONCURRENCY} "
                  f"超时{TIMEOUT}s 重试{API_RETRY}）...", flush=True)
            results = await asyncio.gather(
                *[check_one(session, ip, port, sem) for ip, port, _, _ in items]
            )

            alive, dead, unknown = [], [], []
            for i, (st, country) in enumerate(results):
                ip, port, old_country, name = items[i]
                if st == "ok":
                    alive.append((ip, port, country, name))
                elif st == "dead":
                    dead.append((ip, port, name))
                else:
                    # API 没答上来 → 原样保留，沿用旧 country，下轮再判
                    unknown.append((ip, port, old_country, name))

            alive_count = len(alive)
            err_ratio = len(unknown) / total
            print(f"[+] {fname}：存活 {alive_count} / 失效 {len(dead)} / "
                  f"API异常 {len(unknown)} / 保留国家 {skipped} "
                  f"（共 {total + skipped}）", flush=True)

            # 保护一：API 异常占比过高 → 整个文件不动
            if err_ratio > API_ERROR_ABORT_RATIO:
                print(f"[!] API 异常占比 {err_ratio*100:.1f}%，疑似 API 故障"
                      f"（超额/1027/Worker异常），跳过 {fname}，不做任何变更。", flush=True)
                summary[stem] = (0, len(unknown))
                continue

            # 保护二：存活率过低 → 不覆盖（分母排除 API 异常的）
            judged = alive_count + len(dead)
            if judged >= MIN_JUDGED_FOR_RATIO and \
                    alive_count / judged < MIN_SURVIVE_RATIO:
                print(f"[!] 存活率低于 {MIN_SURVIVE_RATIO*100:.0f}%，"
                      f"疑似异常，不覆盖 {fname}。", flush=True)
                summary[stem] = (0, len(unknown))
                continue

            removed = len(dead)
            if removed or unknown:
                summary[stem] = (removed, len(unknown))
            if removed > 0:
                # 不逐个列 ip:port —— 公开仓库的 Actions 日志登录可见，
                # 剔除项是"曾经有效过"的 proxyip，参考价值不低，
                # 和扫描线设 MASK_PORT_LOG=1 的意图一致。
                nports = len({p for _, p, _ in dead})
                print(f"  [剔除] {removed} 条，涉及 {nports} 个端口", flush=True)

            out_lines = set(keep_lines)   # CN 及无效行原样写回
            for ip, port, country, name in alive:
                out_lines.add(format_line(ip, port, country, name))
            for ip, port, country, name in unknown:
                out_lines.add(format_line(ip, port, country, name))

            with open(fname, "w", encoding="utf-8", newline="\n") as f:
                for line in sorted(out_lines, key=sort_key):
                    f.write(line + "\n")

            print(f"[+] {fname} 已更新：剔除 {removed} 个失效，"
                  f"保留 {len(out_lines)} 个"
                  f"（含 {skipped} 个保留国家 + {len(unknown)} 个待下轮复验）。", flush=True)

    # 格式 stem:剔除数:API异常数（异常数供发现"常年判不出来"的条目）
    with open("recheck_summary.txt", "w", encoding="utf-8") as f:
        for name, (removed, unk) in summary.items():
            f.write(f"{name}:{removed}:{unk}\n")

    with open("recheck_truncated.txt", "w", encoding="utf-8") as f:
        f.write("1" if truncated else "0")


if __name__ == "__main__":
    asyncio.run(main())
