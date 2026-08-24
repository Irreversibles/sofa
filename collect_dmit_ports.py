#!/usr/bin/env python3
"""
从 TG 群收集 DMIT(AS906) 端口，累积成带频次的端口档案。

频次是价值信号：同一端口被发布多次说明多个客户在用，命中概率更高，
所以档案记 count，由 build_dmit_ports.py 用来做优先级。
"""
import os
import re
import asyncio

from telethon import TelegramClient

from port_state import load_state, save_state, now_ts

TG_API_ID = int(os.environ["TG_API_ID"])
TG_API_HASH = os.environ["TG_API_HASH"]
TG_SOURCE_CHAT = os.environ["TG_SOURCE_CHAT"]        # @group 或 -100xxxx
TG_FETCH_LIMIT = int(os.environ.get("TG_FETCH_LIMIT", "5000"))
TG_SESSION_B64 = os.environ.get("TG_SESSION_B64", "")

STATE_FILE = os.environ.get("STATE_FILE", "dmit_ports_state.json")
OUT_FILE = os.environ.get("OUT_FILE", "dmit_ports_pool.txt")

IP_RE = re.compile(r"IP地址\s*[:：]\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
PORT_RE = re.compile(r"端口\s*[:：]\s*(\d{1,5})")
ASN_RE = re.compile(r"ASN编号\s*[:：]\s*(.+)", re.IGNORECASE)


def is_dmit_message(text: str) -> bool:
    t = (text or "").lower()
    if ("dmit" not in t) and ("as906" not in t):
        return False
    m = ASN_RE.search(text or "")
    if m:
        asn_line = m.group(1).lower()
        if ("dmit" not in asn_line) and ("as906" not in asn_line):
            return False
    return True


def extract_port_from_msg(text: str):
    if not text:
        return None
    text = text.replace("\u200b", "").replace("\ufeff", "")
    if not is_dmit_message(text):
        return None
    if not IP_RE.search(text):
        return None
    m = PORT_RE.search(text)
    if not m:
        return None
    p = int(m.group(1))
    return p if 1 <= p <= 65535 else None


async def main():
    st = load_state(STATE_FILE)
    last_msg_id = int(st.get("last_msg_id", 0) or 0)
    ports = st["ports"]

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

    newest_msg_id = last_msg_id
    new_ports = 0
    hit_msgs = 0
    ts = now_ts()

    kwargs = {"limit": TG_FETCH_LIMIT}
    if last_msg_id > 0:
        kwargs["min_id"] = last_msg_id

    async for msg in client.iter_messages(chat, **kwargs):
        if msg.id and msg.id > newest_msg_id:
            newest_msg_id = msg.id
        if not msg.message:
            continue
        p = extract_port_from_msg(msg.message)
        if p is None:
            continue
        hit_msgs += 1
        key = str(p)
        rec = ports.get(key)
        if rec is None:
            ports[key] = {"count": 1, "first_seen": ts,
                          "last_seen": ts, "last_scanned": 0}
            new_ports += 1
        else:
            rec["count"] = int(rec.get("count", 1) or 1) + 1
            rec["last_seen"] = ts

    await client.disconnect()

    st["last_msg_id"] = int(newest_msg_id)
    save_state(STATE_FILE, st)

    # 可读产物：端口 频次（build 不依赖它，只读 state）
    with open(OUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        for k in sorted(ports, key=lambda x: int(x)):
            f.write(f"{k} {ports[k].get('count', 1)}\n")

    hot = sum(1 for v in ports.values() if int(v.get("count", 1) or 1) >= 5)
    print(f"[OK] last_msg_id: {last_msg_id} -> {newest_msg_id}")
    print(f"[OK] 本次命中消息 {hit_msgs} 条，新端口 {new_ports} 个")
    print(f"[OK] 档案总端口 {len(ports)} 个（其中频次≥5 的 {hot} 个）")


if __name__ == "__main__":
    asyncio.run(main())
