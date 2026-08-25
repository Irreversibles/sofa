#!/usr/bin/env python3
"""
从 TG 群收集所有服务商的高位端口，按 ASN 分组累积成档案。

三重过滤，保证只吃 bot 的 IP 发布消息：
  1) 发送者必须是 @cf_ip_fabu_bot（id 8297124834）—— id 比 username 稳
  2) 内容必须带 #CF优选IP —— 同一 bot 也用 "CF中转IP发布" 标题发
     GitHub 曝光检测报告等非 IP 消息，那些没这个标签
  3) 必须有 IP地址 和 端口 字段 —— 群友带标签的闲聊在此被挡

抓取策略：优先用 Telegram 服务端搜索只拉带标签的消息（省几个数量级流量），
因此默认不限条数、读完整历史。搜索若取不到结果（CJK/话题标签偶有翻车）
自动回退全量遍历 + 本地过滤，不会静默漏数据。

频次是价值信号：同一端口被反复发布说明多个客户在用，命中概率更高，
所以档案记 count，由 build_dmit_ports.py 用来排序。

分桶键取自 ASN编号 字段：能解析出 AS 号就用数字（如 "906"），
只有名字则查别名表，查不到用名字大写做键。
别名表可用 ASN_ALIASES 环境变量扩充："DMIT=906,AWS=16509"

模式：
    DRY_RUN=1       只统计并打印分桶分布，不写 state（首次用它验证）
    FULL_REBUILD=1  游标归零、清空 count 后全量重读，重建真实频次；
                    last_scanned 会被保留，轮转进度不丢
"""
import os
import re
import asyncio
from collections import Counter

from telethon import TelegramClient

from port_state import load_state, save_state, now_ts, get_bucket

TG_API_ID = int(os.environ["TG_API_ID"])
TG_API_HASH = os.environ["TG_API_HASH"]
TG_SOURCE_CHAT = os.environ["TG_SOURCE_CHAT"]
TG_SESSION_B64 = os.environ.get("TG_SESSION_B64", "")

# 0 = 不限条数，读完整历史（配合服务端搜索，成本很低）
TG_FETCH_LIMIT = int(os.environ.get("TG_FETCH_LIMIT", "0"))
# 服务端搜索关键词；置空则直接全量遍历
TG_SEARCH = os.environ.get("TG_SEARCH", "#CF优选IP")
# 只认这个 bot 发的。留空 = 不限发送者，仅靠内容特征过滤。
# 填数字 id（推荐，不会变且无需额外 API 调用）或 username（不带@），逗号分隔
TG_SENDER = os.environ.get("TG_SENDER", "8297124834").strip()

STATE_FILE = os.environ.get("STATE_FILE", "dmit_ports_state.json")
OUT_FILE = os.environ.get("OUT_FILE", "dmit_ports_pool.txt")

DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"
FULL_REBUILD = os.environ.get("FULL_REBUILD", "0") == "1"

TEMPLATE_RE = re.compile(r"#CF优选IP")

IP_RE = re.compile(r"IP地址\s*[:：]\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
PORT_RE = re.compile(r"端口\s*[:：]\s*(\d{1,5})")
ASN_LINE_RE = re.compile(r"ASN编号\s*[:：]\s*(.+)")
AS_NUM_RE = re.compile(r"\bAS\s*(\d{1,10})\b", re.IGNORECASE)

NAME_TO_ASN = {
    "DMIT": "906",
}
for pair in (os.environ.get("ASN_ALIASES", "") or "").split(","):
    if "=" in pair:
        k, v = pair.split("=", 1)
        k = re.sub(r"[^\w]+", "", k).strip().upper()
        v = v.strip().upper().replace("AS", "")
        if k and v:
            NAME_TO_ASN[k] = v


def _slug(s):
    return re.sub(r"[^\w]+", "_", s).strip("_").upper()[:32]


def asn_key_and_label(text):
    """返回 (分桶键, 原始标签)。拿不到 ASN编号 行时返回 (None, "")。"""
    m = ASN_LINE_RE.search(text or "")
    if not m:
        return None, ""
    raw = m.group(1).strip()
    if not raw:
        return None, ""
    label = raw[:60]

    num = AS_NUM_RE.search(raw)
    if num:
        return num.group(1), label

    slug = _slug(raw)
    if not slug:
        return None, label
    # 名字里可能夹着别的词（"DMIT 洛杉矶"），逐个 token 查别名
    for token in slug.split("_"):
        if token in NAME_TO_ASN:
            return NAME_TO_ASN[token], label
    if slug in NAME_TO_ASN:
        return NAME_TO_ASN[slug], label
    return slug, label


def extract(text):
    """返回 (分桶键, 标签, 端口)，任一环节不成立则返回 None。"""
    if not text:
        return None
    text = text.replace("\u200b", "").replace("\ufeff", "")
    if not TEMPLATE_RE.search(text):     # 不是 IP 发布模板 → 直接丢
        return None
    if not IP_RE.search(text):
        return None
    pm = PORT_RE.search(text)
    if not pm:
        return None
    p = int(pm.group(1))
    if not (1 <= p <= 65535):
        return None
    key, label = asn_key_and_label(text)
    if not key:
        return None
    return key, label, p


async def collect_messages(client, chat, min_id):
    """拉取候选消息，返回 (记录列表, 最大消息id, 抓取方式)。

    先试服务端搜索；命中 0 条则回退全量遍历，避免搜索对 CJK/话题标签
    支持不佳时静默漏数据。
    """
    async def _run(search):
        kwargs = {}
        kwargs["limit"] = TG_FETCH_LIMIT if TG_FETCH_LIMIT > 0 else None
        if min_id > 0:
            kwargs["min_id"] = min_id
        if search:
            kwargs["search"] = search

        # 发送者白名单：数字 id 直接比对 sender_id，username 才需要拉 sender
        allow_ids, allow_names = set(), set()
        for tok in (TG_SENDER or "").split(","):
            tok = tok.strip().lstrip("@")
            if not tok:
                continue
            if tok.isdigit():
                allow_ids.add(int(tok))
            else:
                allow_names.add(tok.lower())
        filtering = bool(allow_ids or allow_names)

        rows = []
        newest = min_id
        seen = 0
        skipped = 0
        async for msg in client.iter_messages(chat, **kwargs):
            seen += 1
            if msg.id and msg.id > newest:
                newest = msg.id
            if not msg.message:
                continue

            if filtering:
                sid = getattr(msg, "sender_id", None)
                ok = sid in allow_ids
                if not ok and allow_names:
                    try:
                        sender = await msg.get_sender()
                        uname = (getattr(sender, "username", "") or "").lower()
                        ok = bool(uname) and uname in allow_names
                    except Exception:
                        ok = False
                if not ok:
                    skipped += 1
                    continue

            got = extract(msg.message)
            if got is not None:
                rows.append(got)

        if skipped:
            print(f"[*] 按发送者过滤掉 {skipped} 条（非 bot）", flush=True)
        return rows, newest, seen

    if TG_SEARCH:
        rows, newest, seen = await _run(TG_SEARCH)
        if rows:
            print(f"[*] 服务端搜索「{TG_SEARCH}」：遍历 {seen} 条，"
                  f"命中 {len(rows)} 条", flush=True)
            return rows, newest, f"search:{TG_SEARCH}"
        print(f"[!] 搜索「{TG_SEARCH}」无命中，回退全量遍历", flush=True)

    rows, newest, seen = await _run(None)
    print(f"[*] 全量遍历：读 {seen} 条，命中 {len(rows)} 条", flush=True)
    return rows, newest, "full"


async def main():
    st = load_state(STATE_FILE)

    # 全量重建：保留 last_scanned（扫描进度），清掉频次后重算
    saved_scanned = {}
    if FULL_REBUILD:
        for akey, b in st["asns"].items():
            for pkey, rec in b["ports"].items():
                ls = int(rec.get("last_scanned", 0) or 0)
                if ls:
                    saved_scanned[(akey, pkey)] = ls
            b["ports"] = {}
        st["last_msg_id"] = 0
        print(f"[*] FULL_REBUILD：游标归零，已保留 {len(saved_scanned)} 个端口的"
              f" last_scanned", flush=True)

    last_msg_id = int(st.get("last_msg_id", 0) or 0)

    session_name = "tg_dmit_ports"
    if TG_SESSION_B64:
        import base64
        with open(session_name + ".session", "wb") as f:
            f.write(base64.b64decode(TG_SESSION_B64))

    client = TelegramClient(session_name, TG_API_ID, TG_API_HASH)
    await client.start()

    raw_chat = str(TG_SOURCE_CHAT).strip()
    try:
        chat_ref = int(raw_chat) if raw_chat.lstrip("-").isdigit() else raw_chat
        chat = await client.get_entity(chat_ref)
    except Exception as e:
        me = await client.get_me()
        print(f"[ERR] get_entity failed: {raw_chat} | {type(e).__name__}: {e}")
        print(f"[DIAG] account id={me.id}, username={getattr(me, 'username', None)}")
        await client.disconnect()
        raise

    limit_desc = "不限（完整历史）" if TG_FETCH_LIMIT <= 0 else f"{TG_FETCH_LIMIT:,} 条"
    print(f"[*] 起点 msg_id={last_msg_id} | 抓取上限={limit_desc} | "
          f"发送者白名单={TG_SENDER or '(不限)'}", flush=True)

    rows, newest_msg_id, mode = await collect_messages(client, chat, last_msg_id)
    await client.disconnect()

    ts = now_ts()
    new_ports = 0
    bucket_hits = Counter()
    bucket_labels = {}

    for akey, label, p in rows:
        bucket_hits[akey] += 1
        bucket_labels.setdefault(akey, label)
        if DRY_RUN:
            continue
        b = get_bucket(st, akey, label)
        rec = b["ports"].get(str(p))
        if rec is None:
            b["ports"][str(p)] = {"count": 1, "first_seen": ts,
                                  "last_seen": ts, "last_scanned": 0}
            new_ports += 1
        else:
            rec["count"] = int(rec.get("count", 1) or 1) + 1
            rec["last_seen"] = ts

    print(f"[OK] 抓取方式={mode} | 游标 {last_msg_id} -> {newest_msg_id} | "
          f"发布消息 {len(rows)} 条", flush=True)
    print(f"[OK] 分桶分布（键 | 命中数 | 消息里的原始标签）：", flush=True)
    for akey, n in bucket_hits.most_common():
        flag = "" if akey.isdigit() else "   <-- 没解析出 AS 号，考虑加 ASN_ALIASES"
        print(f"      {akey:<12} {n:>6}  {bucket_labels.get(akey,'')}{flag}",
              flush=True)

    if DRY_RUN:
        print("[*] DRY_RUN：未写入 state", flush=True)
        return

    if FULL_REBUILD and saved_scanned:
        restored = 0
        for (akey, pkey), ls in saved_scanned.items():
            b = st["asns"].get(akey)
            if b and pkey in b["ports"]:
                b["ports"][pkey]["last_scanned"] = ls
                restored += 1
        print(f"[OK] 恢复 last_scanned: {restored}/{len(saved_scanned)}", flush=True)

    st["last_msg_id"] = int(newest_msg_id)
    save_state(STATE_FILE, st)

    # 可读产物：按 ASN 分节列出 端口 频次（build 不依赖它，只读 state）
    with open(OUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        for akey in sorted(st["asns"], key=lambda k: (not k.isdigit(), k)):
            b = st["asns"][akey]
            f.write(f"# AS{akey} {b.get('label','')} ({len(b['ports'])} ports)\n")
            for pkey in sorted(b["ports"], key=lambda x: int(x)):
                f.write(f"{pkey} {b['ports'][pkey].get('count', 1)}\n")

    print(f"[OK] 新端口 {new_ports} 个 | 档案覆盖 {len(st['asns'])} 个 ASN",
          flush=True)
    for akey in sorted(st["asns"], key=lambda k: -len(st["asns"][k]["ports"])):
        b = st["asns"][akey]
        hot = sum(1 for v in b["ports"].values()
                  if int(v.get("count", 1) or 1) >= 5)
        print(f"      AS{akey:<10} {len(b['ports']):>4} 端口"
              f"（频次≥5 的 {hot}）  {b.get('label','')}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
