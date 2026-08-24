import os
import re
import json
import asyncio
from telethon import TelegramClient

# ========= 环境变量 =========
TG_API_ID = int(os.environ["TG_API_ID"])
TG_API_HASH = os.environ["TG_API_HASH"]
TG_SOURCE_CHAT = os.environ["TG_SOURCE_CHAT"]  # @group 或 -100xxxx
TG_FETCH_LIMIT = int(os.environ.get("TG_FETCH_LIMIT", "5000"))

# 可选：session base64
TG_SESSION_B64 = os.environ.get("TG_SESSION_B64", "")

STATE_FILE = os.environ.get("STATE_FILE", "dmit_ports_state.json")
OUT_FILE = os.environ.get("OUT_FILE", "dmit_ports_pool.txt")
# ==========================

IP_RE = re.compile(r"IP地址\s*[:：]\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
PORT_RE = re.compile(r"端口\s*[:：]\s*(\d{1,5})")
ASN_RE = re.compile(r"ASN编号\s*[:：]\s*(.+)", re.IGNORECASE)


def load_state():
    if not os.path.exists(STATE_FILE):
        return {"last_msg_id": 0, "ports": []}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "last_msg_id": int(data.get("last_msg_id", 0)),
            "ports": [int(x) for x in data.get("ports", []) if str(x).isdigit()],
        }
    except Exception:
        return {"last_msg_id": 0, "ports": []}


def save_state_atomic(last_msg_id: int, ports: set):
    tmp = STATE_FILE + ".tmp"
    data = {
        "last_msg_id": int(last_msg_id),
        "ports": sorted(list(ports)),
    }
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_FILE)


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
    if 1 <= p <= 65535:
        return p
    return None


async def main():
    st = load_state()
    last_msg_id = st["last_msg_id"]
    port_pool = set(st["ports"])

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
    newly_found = set()

    kwargs = {"limit": TG_FETCH_LIMIT}
    if last_msg_id > 0:
        kwargs["min_id"] = last_msg_id

    async for msg in client.iter_messages(chat, **kwargs):
        if msg.id and msg.id > newest_msg_id:
            newest_msg_id = msg.id
        if not msg.message:
            continue
        p = extract_port_from_msg(msg.message)
        if p is not None:
            if p not in port_pool:
                newly_found.add(p)
            port_pool.add(p)

    await client.disconnect()

    with open(OUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        for p in sorted(port_pool):
            f.write(str(p) + "\n")

    save_state_atomic(newest_msg_id, port_pool)

    print(f"[OK] last_msg_id(old)={last_msg_id}, last_msg_id(new)={newest_msg_id}")
    print(f"[OK] total_ports={len(port_pool)}")
    print(f"[OK] newly_found_count={len(newly_found)}")
    print("[OK] state updated")
    print("[OK] pool updated")


if __name__ == "__main__":
    asyncio.run(main())
