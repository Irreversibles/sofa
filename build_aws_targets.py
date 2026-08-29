#!/usr/bin/env python3
"""
按 region 过滤 AWS 官方 IP 段，产出 masscan 目标文件。

AS16509 全球 1.75 亿 IPv4，按 ASN 扫等于把欧美段也一起扫了。AWS 官方发布
ip-ranges.json（含 region 字段），按 region 取段能把目标缩一个数量级，
且这份数据比 BGP 前缀准 —— region 归属是 AWS 自己标的。

只取 service=="EC2"：客户虚拟机所在的段，跑 CF 反代的就在这里。
AMAZON 是包含一切的超集（S3/CloudFront/API Gateway 等托管服务都在内），
扫了纯浪费；CLOUDFRONT 是 CDN 边缘，本身不是 proxyip 后端。

环境变量：
    AWS_REGIONS   逗号分隔，默认 ap-east-1,ap-northeast-1,ap-northeast-3,
                  ap-southeast-1（香港/东京/大阪/新加坡）
    AWS_SERVICE   默认 EC2
    OUT_FILE      默认 aws_targets.txt
    MAX_IPS       非 0 时超出就按段顺序截断，防止 AWS 扩容后意外超预算
"""
import ipaddress
import json
import os
import sys
import urllib.request

URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
REGIONS = [r.strip() for r in os.environ.get(
    "AWS_REGIONS",
    "ap-east-1,ap-northeast-1,ap-northeast-3,ap-southeast-1"
).split(",") if r.strip()]
SERVICE = os.environ.get("AWS_SERVICE", "EC2").upper()
OUT_FILE = os.environ.get("OUT_FILE", "aws_targets.txt")
MAX_IPS = int(os.environ.get("MAX_IPS", "0") or 0)
FETCH_TIMEOUT = int(os.environ.get("FETCH_TIMEOUT", "30"))


def main():
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
            data = json.loads(r.read().decode())
    except Exception as e:
        print(f"[-] 拉取 ip-ranges.json 失败: {type(e).__name__}: {e}", flush=True)
        sys.exit(1)

    print(f"[*] createDate={data.get('createDate')} "
          f"syncToken={data.get('syncToken')}", flush=True)

    want = set(REGIONS)
    per_region = {}
    nets = []
    for item in data.get("prefixes", []):
        if (item.get("service") or "").upper() != SERVICE:
            continue
        region = item.get("region") or ""
        if region not in want:
            continue
        try:
            n = ipaddress.ip_network(item.get("ip_prefix") or "", strict=False)
        except ValueError:
            continue
        if n.version != 4:
            continue
        nets.append(n)
        per_region.setdefault(region, []).append(n)

    if not nets:
        print(f"[-] service={SERVICE} regions={REGIONS} 未匹配到任何段。"
              f"region code 拼错？", flush=True)
        sys.exit(1)

    print(f"[*] service={SERVICE} | 命中 {len(nets)} 个前缀", flush=True)
    for region in sorted(per_region):
        rn = list(ipaddress.collapse_addresses(per_region[region]))
        print(f"      {region:<18}{len(rn):>5} 段  "
              f"{sum(x.num_addresses for x in rn):>12,} IP", flush=True)
    missing = want - set(per_region)
    if missing:
        print(f"[!] 这些 region 没匹配到段: {sorted(missing)}", flush=True)

    collapsed = sorted(ipaddress.collapse_addresses(nets))
    total = sum(n.num_addresses for n in collapsed)
    print(f"[*] 全局 collapse: {len(nets)} → {len(collapsed)} 段 | "
          f"合计 {total:,} IP", flush=True)

    out = collapsed
    if MAX_IPS and total > MAX_IPS:
        out, acc = [], 0
        for n in collapsed:
            if acc + n.num_addresses > MAX_IPS:
                break
            out.append(n)
            acc += n.num_addresses
        print(f"[!] 超过 MAX_IPS={MAX_IPS:,}，截断到 {len(out)} 段 / "
              f"{acc:,} IP", flush=True)
        total = acc

    with open(OUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        for n in out:
            f.write(str(n) + "\n")
    print(f"[OK] 已写出 {OUT_FILE}（{len(out)} 段 / {total:,} IP）", flush=True)

    env = os.environ.get("GITHUB_ENV")
    if env:
        with open(env, "a", encoding="utf-8") as f:
            f.write(f"AWS_TARGET_IPS={total}\n")
            f.write(f"AWS_TARGET_SEGS={len(out)}\n")


if __name__ == "__main__":
    main()
