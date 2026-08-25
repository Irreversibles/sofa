#!/usr/bin/env python3
"""
TG 端口档案的读写与格式迁移，collect_ 和 build_ 共用。

v3 起按 ASN 分组：一个 state 文件容纳多家服务商的端口档案。
    {"version":3, "last_msg_id":N, "asns":{"906":{...}, "16509":{...}}}
每个 ASN 桶自带 ports / pending_selected / last_scan_ts / throughput_ema
/ ip_count_seen —— 这些都是按服务商独立的（IP 数、网络状况、轮转进度都不同）。
last_msg_id 是全局的，因为只有一个 TG 群、一个游标。

state 多方共写，读写必须"合并式"：原样保留其它字段，只更新自己负责的：
    collect_dmit_ports.py → last_msg_id / asns.*.ports.{count,first_seen,last_seen}
    build_dmit_ports.py   → asns.<ASN>.{ports.last_scanned, pending_selected,
                                        last_scan_ts, throughput_ema, ip_count_seen}
"""
import json
import os
import time

STATE_VERSION = 3


def now_ts():
    return int(time.time())


def _empty():
    return {"version": STATE_VERSION, "last_msg_id": 0, "asns": {}}


def blank_asn(label=""):
    return {
        "label": label,
        "ports": {},
        "pending_selected": [],
        "last_scan_ts": 0,
        "throughput_ema": 0,
        "ip_count_seen": 0,
    }


def _fix_ports(ports):
    """把任意形态的 ports 规整成 {"端口": {count,first_seen,last_seen,last_scanned}}"""
    fixed = {}
    if isinstance(ports, list):
        ts = now_ts()
        for x in ports:
            if str(x).isdigit():
                p = int(x)
                if 1 <= p <= 65535:
                    fixed[str(p)] = {"count": 1, "first_seen": ts,
                                     "last_seen": ts, "last_scanned": 0}
        return fixed
    if not isinstance(ports, dict):
        return fixed
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
    return fixed


def _fix_bucket(raw, label_fallback=""):
    if not isinstance(raw, dict):
        return blank_asn(label_fallback)
    b = blank_asn(str(raw.get("label", label_fallback) or label_fallback))
    b["ports"] = _fix_ports(raw.get("ports"))
    b["pending_selected"] = [int(x) for x in (raw.get("pending_selected") or [])
                             if str(x).isdigit()]
    b["last_scan_ts"] = int(raw.get("last_scan_ts", 0) or 0)
    try:
        b["throughput_ema"] = float(raw.get("throughput_ema", 0) or 0)
    except (TypeError, ValueError):
        b["throughput_ema"] = 0
    b["ip_count_seen"] = int(raw.get("ip_count_seen", 0) or 0)
    return b


def _migrate(data):
    """v1（ports 是 list）/ v2（ports 是 dict）→ v3（按 ASN 分组）"""
    if "asns" not in data:
        # 旧档案只采集过 AS906，整体归到 906 桶
        bucket = _fix_bucket({
            "label": "DMIT",
            "ports": data.get("ports"),
            "pending_selected": data.get("pending_selected"),
            "last_scan_ts": data.get("last_scan_ts"),
            "throughput_ema": data.get("throughput_ema"),
            "ip_count_seen": data.get("ip_count_seen"),
        }, "DMIT")
        out = {
            "version": STATE_VERSION,
            "last_msg_id": int(data.get("last_msg_id", 0) or 0),
            "asns": {"906": bucket},
        }
        print(f"[migrate] -> v3: 旧档案 {len(bucket['ports'])} 个端口归入 AS906",
              flush=True)
        return out

    asns = data.get("asns")
    fixed = {}
    if isinstance(asns, dict):
        for k, v in asns.items():
            key = str(k).strip().upper().replace("AS", "") if str(k).strip() else ""
            if not key:
                continue
            fixed[key] = _fix_bucket(v)
    data["asns"] = fixed
    data["version"] = STATE_VERSION
    data["last_msg_id"] = int(data.get("last_msg_id", 0) or 0)
    # 清掉 v2 残留的顶层字段（已并入 906 桶）
    for k in ("ports", "pending_selected", "last_scan_ts",
              "throughput_ema", "ip_count_seen"):
        data.pop(k, None)
    return data


def get_bucket(state, asn_key, label=""):
    """取（不存在则建）某 ASN 的桶。asn_key 会被规整成纯数字或大写名。"""
    key = str(asn_key).strip().upper()
    if key.startswith("AS"):
        key = key[2:]
    if not key:
        raise ValueError("asn_key 不能为空")
    b = state["asns"].get(key)
    if b is None:
        b = blank_asn(label)
        state["asns"][key] = b
    elif label and not b.get("label"):
        b["label"] = label
    return b


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
