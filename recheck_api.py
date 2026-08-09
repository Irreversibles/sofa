import asyncio
import sys
import os
import ipaddress
import urllib.parse

import aiohttp

# ==================== 配置 ====================
CHECK_API = "https://check.tigaa.ccwu.cc/check"   # ← 你自建的检测 API
CONCURRENCY = 10           # 并发（自己的API，可以比公共的高一点）
TIMEOUT = 20               # 单个检测超时
MIN_SURVIVE_RATIO = 0.15   # 存活率过低不覆盖（防API抽风误删）


def parse_line(line):
    """解析 ip:port#地区 名字"""
    s = line.strip()
    if not s:
        return None
    try:
        addr = s.split("#")[0]
        ip_part, port_part = addr.rsplit(":", 1)
        ipaddress.ip_address(ip_part)
        port = int(port_part)
        name = ""
        if "#" in s:
            after = s.split("#", 1)[1].split(None, 1)
            name = after[1] if len(after) > 1 else ""
        return (ip_part, port, name)
    except Exception:
        return None


async def check_one(session, ip, port, sem):
    """调用自建 API 检测，返回 (是否有效, 落地国家)"""
    async with sem:
        proxyip = urllib.parse.quote(f"{ip}:{port}")
        url = f"{CHECK_API}?proxyip={proxyip}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as resp:
                data = await resp.json(content_type=None)
                if data.get("success") is True:
                    country = "??"
                    try:
                        country = data["probe_results"]["ipv4"]["exit"]["country"] or "??"
                    except Exception:
                        try:
                            country = data["probe_results"]["ipv6"]["exit"]["country"] or "??"
                        except Exception:
                            pass
                    return (True, country)
                return (False, "??")
        except Exception:
            return (False, "??")


async def main():
    if len(sys.argv) < 2:
        print("[-] 用法: python recheck_api.py 文件1.txt [文件2.txt ...]", flush=True)
        return

    sem = asyncio.Semaphore(CONCURRENCY)

    async with aiohttp.ClientSession() as session:
        for fname in sys.argv[1:]:
            base = os.path.basename(fname)
            if base.lower().replace(".txt", "").endswith("-old"):
                print(f"[跳过] 备份文件: {fname}", flush=True)
                continue
            if base in ("count.txt", "name.txt", "requirements.txt", "ip.txt"):
                continue
            if not os.path.exists(fname):
                print(f"[-] 文件不存在: {fname}", flush=True)
                continue

            items = []
            with open(fname, "r", encoding="utf-8") as f:
                for line in f:
                    p = parse_line(line)
                    if p:
                        items.append(p)

            total = len(items)
            if total == 0:
                print(f"[!] {fname} 无有效行，跳过。", flush=True)
                continue

            print(f"\n[*] 复验 {fname}：共 {total} 条（自建API，并发{CONCURRENCY}）...", flush=True)
            tasks = [check_one(session, ip, port, sem) for ip, port, _ in items]
            results = await asyncio.gather(*tasks)

            alive = []
            for i, (ok, country) in enumerate(results):
                if ok:
                    ip, port, name = items[i]
                    alive.append((ip, port, country, name))

            alive_count = len(alive)
            ratio = alive_count / total if total else 0
            print(f"[+] {fname}：存活 {alive_count}/{total} ({ratio*100:.1f}%)", flush=True)

            if ratio < MIN_SURVIVE_RATIO:
                print(f"[!] 存活率低于 {MIN_SURVIVE_RATIO*100:.0f}%，疑似API异常，不覆盖 {fname}。", flush=True)
                continue

            # 用API返回的真实落地国家更新地区，排序写回
            out_lines = set()
            for ip, port, country, name in alive:
                out_lines.add(f"{ip}:{port}#{country} {name}".rstrip())

            def sort_key(line):
                try:
                    addr = line.split("#")[0]
                    ip_part, port_part = addr.rsplit(":", 1)
                    country = line.split("#")[1].split()[0] if "#" in line else "??"
                    return (country, ipaddress.ip_address(ip_part), int(port_part))
                except Exception:
                    return ("??", ipaddress.ip_address("0.0.0.0"), 0)

            sorted_lines = sorted(out_lines, key=sort_key)
            with open(fname, "w", encoding="utf-8", newline="\n") as f:
                for line in sorted_lines:
                    f.write(line + "\n")

            print(f"[+] {fname} 已更新：剔除 {total - alive_count} 个失效，保留 {alive_count} 个。", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
