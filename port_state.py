#!/usr/bin/env python3
"""
DMIT 端口档案的读写与格式迁移，collect_ 和 build_ 共用。

state 是多方共写的，所以读写都必须是"合并式"——
原样保留其它字段，只更新自己负责的那部分：
    collect_dmit_ports.py → last_msg_id / ports.{count,first_seen,last_seen}
    build_dmit_ports.py   → ports.last_scanned / pending_selected / ip_count_seen
"""
import json
import os
import time

STATE_VERSION = 2


def now_ts():
    return int(time.time())


def _empty():
    return {"version": STATE_VERSION, "last_msg_id": 0, "ports": {}}


def _migrate(data):
    """v1（ports 是扁平 list）→ v2（ports 是带频次的 dict）"""
    ports = data.get("ports")

    if isinstance(ports, list):
        ts = now_ts()
        newp = {}
        for x in ports:
            if str(x).isdigit():
                p = int(x)
                if 1 <= p <= 65535:
                    newp[str(p)] = {"count": 1, "first_seen": ts,
                                    "last_seen": ts, "last_scanned": 0}
        data["ports"] = newp
        # 游标字段废弃：extra_pool 是数值排序的，新端口插进中间会让游标
        # 之后所有下标整体后移，游标指向的端口漂移、部分端口长期轮不到。
        # 改用 last_scanned 排序后，池子怎么增删都不影响覆盖均匀性。
        for k in ("extra_cursor", "last_selected_sig", "extra_pool_count",
                  "extra_selected_count", "adaptive_max_extra"):
            data.pop(k, None)
        print(f"[migrate] v1 -> v2: {len(newp)} 个端口，频次初始化为 1", flush=True)

    elif isinstance(ports, dict):
        fixed = {}
        for k, v in ports.items():
            if not str(k).isdigit():
                continue
            p = int(k)
            if not (1 <= p <= 65535):
                continue
            if isinstance(v, dict):
                fixed[str(p)] = {
                    "count": max(1, int(v.get("count", 1) or 1)),
                    "first_seen": int(v.get("first_seen", 0) or 0),
                    "last_seen": int(v.get("last_seen", 0) or 0),
                    "last_scanned": int(v.get("last_scanned", 0) or 0),
                }
            else:
                fixed[str(p)] = {"count": 1, "first_seen": 0,
                                 "last_seen": 0, "last_scanned": 0}
        data["ports"] = fixed
    else:
        data["ports"] = {}

    data["version"] = STATE_VERSION
    data["last_msg_id"] = int(data.get("last_msg_id", 0) or 0)
    return data


def load_state(path):
    if not os.path.exists(path):
        return _empty()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[WARN] state 读取失败({type(e).__name__})，按空档案处理", flush=True)
        return _empty()
    if not isinstance(data, dict):
        return _empty()
    return _migrate(data)


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp, path)
