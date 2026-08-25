#!/usr/bin/env python3
"""查看端口档案 state 的摘要；--check-low 时列出各 ASN 的低位端口，
用来发现"把延迟/速度数值误当端口"这类解析脏数据。"""
import json
import sys


def main():
    if len(sys.argv) < 2:
        print("用法: inspect_state.py <state.json> [--check-low]")
        return
    path = sys.argv[1]
    check_low = "--check-low" in sys.argv[2:]

    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except Exception as e:
        print(f"[!] 读取失败: {type(e).__name__}: {e}")
        return

    asns = d.get("asns")
    if not asns:
        # 旧格式
        ports = d.get("ports") or {}
        print(f"[*] 旧格式档案: {len(ports)} 端口（将迁移到 v3）")
        return

    print(f"[*] v3 档案: {len(asns)} 个 ASN | last_msg_id={d.get('last_msg_id')}"
          f" | csv_seen={len(d.get('csv_seen_ids') or [])}")
    for k in sorted(asns, key=lambda x: -len(asns[x].get("ports", {})))[:10]:
        b = asns[k]
        ports = sorted(int(p) for p in b.get("ports", {}))
        rng = f"{ports[0]}-{ports[-1]}" if ports else "空"
        print(f"      AS{k:<10} {len(ports):>4} 端口 | 范围 {rng} | "
              f"{b.get('label','')}")

    if check_low:
        print("\n===== 低位端口(<1024)检查 =====")
        any_low = False
        for k in sorted(asns):
            ports = sorted(int(p) for p in asns[k].get("ports", {}))
            low = [p for p in ports if p < 1024]
            if low:
                any_low = True
                print(f"AS{k}: {low}")
        if not any_low:
            print("无低位端口，池子干净")
        else:
            print("\n[!] 出现低位端口。443/587/993 等是正常服务端口；"
                  "若见到 144/171/53 这类，可能是延迟值被误当端口，需排查。")


if __name__ == "__main__":
    main()
