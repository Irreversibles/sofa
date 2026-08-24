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

# 可选：把 session 以 base64 放 secret，免交互登录
TG_SESSION_B64 = os.environ.get("TG_SESSION_B64", "")

STATE_FILE = os.environ.get("STATE_FILE", "dmit_ports_state.json")
OUT_FILE = os.environ.get("OUT_FILE", "dmit_ports_pool.txt")
# ==========================

# 解析规则（按你截图格式）
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


def save_state(last_msg_id: int, ports: set):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {
                "last_msg_id": int(last_msg_id),
                "ports": sorted(list(ports)),
            },
            f,
            ensure_ascii=False,
            indent=2
        )


def is_dmit_message(text: str) -> bool:
    """
    仅识别 DMIT 消息：
    1) 全文有 dmit/as906
    2) 若有 ASN 行，ASN 行里也必须有 dmit/as906
    """
    t = (text or "").lower()
    if ("dmit" not in t) and ("as906" not in t):
        return False

    asn_match = ASN_RE.search(text or "")
    if asn_match:
        asn_line = asn_match.group(1).lower()
        if ("dmit" not in asn_line) and ("as906" not in asn_line):
            return False
    return True


def extract_port_from_msg(text: str):
    if not text:
        return None
    text = text.replace("\u200b", "").replace("\ufeff", "")

    if not is_dmit_message(text):
        return None

    # 你的消息格式里会有 IP 和端口，顺便要求 IP 存在，减少误抓
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
    state = load_state()
    last_msg_id = state["last_msg_id"]
    port_pool = set(state["ports"])

    # 准备 session
    session_name = "tg_dmit_ports"
    if TG_SESSION_B64:
        import base64
        with open(session_name + ".session", "wb") as f:
            f.write(base64.b64decode(TG_SESSION_B64))

    client = TelegramClient(session_name, TG_API_ID, TG_API_HASH)
    await client.start()

    # 关键：-100... 必须按 int 传给 Telethon
    raw_chat = str(TG_SOURCE_CHAT).strip()
    try:
        chat_ref = int(raw_chat) if raw_chat.lstrip("-").isdigit() else raw_chat
        chat = await client.get_entity(chat_ref)
    except Exception as e:
        print(f"[ERR] get_entity 失败: {raw_chat} | {type(e).__name__}: {e}")
        print("[HINT] 若用 chat_id，请填 -100xxxxxxxxxx；并确认 TG_SESSION_B64 对应账号已在该群")
        # 诊断：列出前50个会话
        me = await client.get_me()
        print(f"[DIAG] 当前账号: id={me.id}, username={getattr(me, 'username', None)}")
        print("[DIAG] 最近可见会话(前50):")
        c = 0
        async for d in client.iter_dialogs(limit=50):
            print(f"  id={d.id} name={d.name} username={getattr(d.entity,'username',None)}")
            c += 1
        if c == 0:
            print("  (无会话)")
        await client.disconnect()
        raise

    newest_msg_id = last_msg_id
    newly_found = set()

    # 首次：扫最近 TG_FETCH_LIMIT 条
    # 非首次：只扫 last_msg_id 之后的增量
    kwargs = {"limit": TG_FETCH_LIMIT}
    if last_msg_id > 0:
        kwargs["min_id"] = last_msg_id

    async for msg in client.iter_messages(chat, **kwargs):
        if msg.id and msg.id > newest_msg_id:
            newest_msg_id = msg.id
        if not msg.message:
            continue

        port = extract_port_from_msg(msg.message)
        if port is not None:
            if port not in port_pool:
                newly_found.add(port)
            port_pool.add(port)

    await client.disconnect()

    # 输出端口池（每行一个端口，升序）
    with open(OUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        for p in sorted(port_pool):
            f.write(str(p) + "\n")

    # 保存状态
    save_state(newest_msg_id, port_pool)

    # 方便 Actions 日志看
    print(f"[OK] last_msg_id(old)={last_msg_id}, last_msg_id(new)={newest_msg_id}")
    print(f"[OK] total_ports={len(port_pool)}")
    print(f"[OK] newly_found={sorted(newly_found)}")
    print(f"[OK] state -> {STATE_FILE}")
    print(f"[OK] pool  -> {OUT_FILE}")


if __name__ == "__main__":
    asyncio.run(main())
