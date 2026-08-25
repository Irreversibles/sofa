#!/usr/bin/env python3
"""
从 DanFeng 频道的 CSV 附件采集高位端口，按文件名里的 AS 号归入对应桶。

只处理文件名能提取出 AS 号的（如 AS149440_EVOXTSDNBHDASAP_20260811.csv）。
Aliyun.csv 这类只有商家名的、Global-proxyip-443.csv 这类跨 ASN 合集，
一律跳过 —— 后者端口维度也没信息量（全文件只有 443 或 8443，本来就每轮必扫）。

CSV 表头形如：IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度
没有 ASN 列，所以服务商归属只能靠文件名。

频次口径：每个文件里同一端口只记 +1（一次"发布事件"），不按行数累加。
    一个 CSV 可能几百行都是 443，按行加会让频次信号被 CSV 压过 bot 消息
    （那边一条消息 +1），排序失真。

已处理的文件按 message_id 记在 state.csv_seen_ids，不会重复下载。

模式：
    DRY_RUN=1   只列文件清单（名字/大小/日期/能否提取AS号），不下载不写 state
"""
import csv
import io
import os
import re
import asyncio
from collections import Counter, defaultdict

from telethon import TelegramClient
from telethon.tl.types import InputMessagesFilterDocument

from port_state import load_state, save_state, now_ts, get_bucket

TG_API_ID = int(os.environ["TG_API_ID"])
TG_API_HASH = os.environ["TG_API_HASH"]
TG_SESSION_B64 = os.environ.get("TG_SESSION_B64", "")
# CSV 在频道，bot 文本消息在群，是两个不同实体
TG_FILE_CHAT = os.environ["TG_FILE_CHAT"].strip()

STATE_FILE = os.environ.get("STATE_FILE", "dmit_ports_state.json")
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

FILE_FETCH_LIMIT = int(os.environ.get("FILE_FETCH_LIMIT", "0"))   # 0=不限
MAX_FILE_MB = float(os.environ.get("MAX_FILE_MB", "2"))           # 超过则跳过
MAX_FILES_PER_RUN = int(os.environ.get("MAX_FILES_PER_RUN", "50"))

# 文件名里的 AS 号：要求 AS 紧跟数字，避开日期串（20260811）误匹配
FNAME_ASN_RE = re.compile(r"\bAS(\d{1,10})\b", re.IGNORECASE)

ASN_BLACKLIST = {"13335", "209242"}      # CF 自家，扫了没意义
for x in (os.environ.get("ASN_BLACKLIST_EXTRA", "") or "").replace(" ", "").split(","):
    a = x.upper().replace("AS", "")
    if a.isdigit():
        ASN_BLACKLIST.add(a)


def file_name_of(msg):
    doc = getattr(msg, "document", None)
    if not doc:
        return ""
    for attr in getattr(doc, "attributes", []) or []:
        n = getattr(attr, "file_name", None)
        if n:
            return n
    return ""


def asn_from_name(name):
    m = FNAME_ASN_RE.search(name or "")
    return m.group(1) if m else None


def decode_csv(raw):
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin1", errors="ignore")


def ports_in_csv(raw):
    """返回该文件里出现过的端口集合。表头找『端口』列，找不到退回第 2 列。"""
    text = decode_csv(raw)
    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        return set()

    idx = 1
    for i, cell in enumerate(header):
        c = (cell or "").strip().lower()
        if "端口" in cell or c == "port":
            idx = i
            break

    out = set()
    for row in reader:
        if len(row) <= idx:
            continue
        v = (row[idx] or "").strip()
        if v.isdigit():
            p = int(v)
            if 1 <= p <= 65535:
                out.add(p)
    return out


async def main():
    st = load_state(STATE_FILE)
    seen = set(int(x) for x in (st.get("csv_seen_ids") or []) if str(x).isdigit())

    session_name = "tg_dmit_ports"
    if TG_SESSION_B64:
        import base64
        with open(session_name + ".session", "wb") as f:
            f.write(base64.b64decode(TG_SESSION_B64))

    client = TelegramClient(session_name, TG_API_ID, TG_API_HASH)
    await client.start()

    async def resolve_chat(raw):
        """Telegram ID 体系：频道/超级群的 peer id 需要 -100 前缀，
        纯数字会被当成 user_id（报 PeerUser 找不到）。所以依次尝试
        原值、加 -100 前缀、去 -100 前缀。"""
        cands = []
        s = raw.strip()
        if s.lstrip("-").isdigit():
            n = int(s)
            cands.append(n)
            if n > 0:
                cands.append(int(f"-100{n}"))
            elif s.startswith("-100"):
                cands.append(int(s[4:]))
        else:
            cands.append(s.lstrip("@"))

        last_err = None
        for c in cands:
            try:
                ent = await client.get_entity(c)
                print(f"[*] 解析实体成功: {c}", flush=True)
                return ent
            except Exception as e:
                last_err = e
                print(f"[!] 尝试 {c} 失败: {type(e).__name__}", flush=True)
        raise last_err

    try:
        chat = await resolve_chat(TG_FILE_CHAT)
    except Exception as e:
        print(f"[ERR] 无法解析 TG_FILE_CHAT | {type(e).__name__}: {e}", flush=True)
        print("[HINT] 频道请填 username（如 danfeng2）或带 -100 前缀的 id"
              "（如 -1002764001836）", flush=True)
        await client.disconnect()
        raise

    kwargs = {"filter": InputMessagesFilterDocument,
              "limit": FILE_FETCH_LIMIT if FILE_FETCH_LIMIT > 0 else None}

    listed = []
    async for msg in client.iter_messages(chat, **kwargs):
        name = file_name_of(msg)
        if not name:
            continue
        size_mb = (getattr(msg.document, "size", 0) or 0) / 1048576.0
        listed.append((msg, name, size_mb, asn_from_name(name)))

    print(f"[*] 频道文件消息 {len(listed)} 个", flush=True)
    print(f"[*] 清单（AS号 | 大小 | 日期 | 文件名）：", flush=True)
    usable = []
    for msg, name, size_mb, asn in listed:
        date = msg.date.strftime("%Y-%m-%d") if msg.date else "?"
        if asn is None:
            tag = "  --  跳过(无AS号)"
        elif asn in ASN_BLACKLIST:
            tag = "  --  跳过(黑名单)"
        elif size_mb > MAX_FILE_MB:
            tag = f"  --  跳过(>{MAX_FILE_MB}MB)"
        elif msg.id in seen:
            tag = "  --  已处理过"
        else:
            tag = "  ->  待解析"
            usable.append((msg, name, asn))
        print(f"      {(asn or '-'):<9}{size_mb:>7.2f}MB  {date}  {name}{tag}",
              flush=True)

    print(f"[*] 可解析 {len(usable)} 个（上限 {MAX_FILES_PER_RUN}）", flush=True)

    if DRY_RUN:
        await client.disconnect()
        print("[*] DRY_RUN：未下载、未写入 state", flush=True)
        return

    ts = now_ts()
    new_ports = Counter()
    hit_ports = defaultdict(set)
    done_ids = []

    for msg, name, asn in usable[:MAX_FILES_PER_RUN]:
        try:
            buf = io.BytesIO()
            await client.download_media(msg, file=buf)
            ports = ports_in_csv(buf.getvalue())
        except Exception as e:
            print(f"[!] {name} 处理失败: {type(e).__name__}: {e}", flush=True)
            continue

        if not ports:
            print(f"[!] {name} 未解析到端口，跳过（标记已处理）", flush=True)
            done_ids.append(msg.id)
            continue

        b = get_bucket(st, asn, f"AS{asn}")
        added = 0
        for p in ports:
            rec = b["ports"].get(str(p))
            if rec is None:
                b["ports"][str(p)] = {"count": 1, "first_seen": ts,
                                      "last_seen": ts, "last_scanned": 0}
                added += 1
            else:
                rec["count"] = int(rec.get("count", 1) or 1) + 1
                rec["last_seen"] = ts
        new_ports[asn] += added
        hit_ports[asn] |= ports
        done_ids.append(msg.id)
        print(f"[+] AS{asn:<8} {name}：端口 {len(ports)} 个（新增 {added}）",
              flush=True)

    await client.disconnect()

    seen |= set(done_ids)
    st["csv_seen_ids"] = sorted(seen)
    save_state(STATE_FILE, st)

    print(f"[OK] 处理 {len(done_ids)} 个文件 | 累计已处理 {len(seen)} 个", flush=True)
    for asn in sorted(new_ports, key=lambda a: -new_ports[a]):
        print(f"      AS{asn:<9} 新增 {new_ports[asn]:>4} 端口 "
              f"（本次出现 {len(hit_ports[asn])} 个）", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
