import re
import socket
import ssl
import tempfile
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

import geoip2.database


# ========================= 扫描配置 =========================

TIMEOUT = 2.0
MAX_WORKERS = 200

# 要检测的端口，按顺序依次尝试，命中即停
PORTS = [443, 2053, 2083, 2087, 2096, 8443]

# 第一步 TLS 探测时使用的 SNI
TLS_DOMAIN = "www.cloudflare.com"

# 第二步 TLS 握手的 SNI，以及 HTTP 请求的 Host
HTTP_DOMAIN = "crypto.cloudflare.com"

# 第三步使用自己托管在 Cloudflare 上的域名验证证书
CUSTOM_DOMAIN = "zeroo.ccwu.cc"

# 输入文件、GeoIP 数据库
IP_FILE = "ip.txt"
GEOIP_DB = "GeoLite2-Country.mmdb"


# ========================= GeoIP =========================

try:
    geo_reader = geoip2.database.Reader(GEOIP_DB)
except Exception:
    geo_reader = None
    print("[警告] 未找到 GeoIP 数据库，地区将显示为 ??", flush=True)


def get_country(ip):
    """返回 IP 的两位国家代码，如 HK / JP / US；查不到返回 ??。"""
    if geo_reader is None:
        return "??"
    try:
        return geo_reader.country(ip).country.iso_code or "??"
    except Exception:
        return "??"


# ========================= 读取 IP =========================


def load_ip_list(file_path: str):
    """读取 ip.txt。
    第一行若为 # 注释，作为输出文件名和名字标签（如 # DMIT）。
    其余行为 IP 或 CIDR 网段，网段自动展开成单个 IP。
    返回 (ip_list, output_name)。
    """
    output_name = "bestip"
    ip_list = []

    with open(file_path, "r", encoding="utf-8") as file:
        for i, line in enumerate(file):
            stripped = line.strip()

            if i == 0 and stripped.startswith("#"):
                name = stripped.lstrip("#").strip()
                if name:
                    output_name = name
                continue

            item = line.split("#", 1)[0].strip()
            if not item:
                continue

            if "/" in item:
                try:
                    net = ipaddress.ip_network(item, strict=False)
                    ip_list.extend(str(ip) for ip in net.hosts())
                except ValueError:
                    print(f"[警告] 无效网段，已跳过: {item}", flush=True)
            else:
                ip_list.append(item)

    return ip_list, output_name


# ========================= TLS 连接 =========================


def create_tls_connection(ip, server_name, port, timeout=TIMEOUT):
    """连接 IP:port 并完成 TLS 握手。"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        tls_sock = context.wrap_socket(sock, server_hostname=server_name)
    except Exception:
        sock.close()
        raise

    tls_sock.settimeout(timeout)
    return tls_sock


def check_tls(ip, port):
    """第一步：检查 www.cloudflare.com 的证书。"""
    try:
        with create_tls_connection(ip, TLS_DOMAIN, port) as tls_sock:
            certificate = tls_sock.getpeercert(binary_form=True)
            return bool(certificate and b"cloudflare" in certificate.lower())
    except (OSError, ssl.SSLError):
        return False


def check_http_301(ip, port):
    """第二步：crypto.cloudflare.com 严格检查 301。"""
    try:
        with create_tls_connection(ip, HTTP_DOMAIN, port) as tls_sock:
            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {HTTP_DOMAIN}\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)

            response = b""
            while b"\r\n" not in response and len(response) < 8192:
                chunk = tls_sock.recv(1024)
                if not chunk:
                    break
                response += chunk

            status_line = response.decode("ascii", errors="ignore").split(
                "\r\n", 1
            )[0]
            match = re.match(r"HTTP/\d\.\d\s+(\d{3})(?:\s|$)", status_line)
            return bool(match and match.group(1) == "301")
    except (OSError, ssl.SSLError):
        return False


def certificate_matches_custom_domain(tls_sock):
    """检查证书 CN 或 SAN 是否包含自定义域名。"""
    certificate = tls_sock.getpeercert(binary_form=True)
    if not certificate:
        return False

    certificate_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".pem", encoding="ascii", delete=False,
    )
    try:
        certificate_file.write(ssl.DER_cert_to_PEM_cert(certificate))
        certificate_file.close()
        decoded = ssl._ssl._test_decode_cert(certificate_file.name)
    finally:
        os.unlink(certificate_file.name)

    names = {
        value.lower()
        for name, value in decoded.get("subjectAltName", ())
        if name == "DNS"
    }
    names.update(
        value.lower()
        for group in decoded.get("subject", ())
        for name, value in group
        if name == "commonName"
    )
    return CUSTOM_DOMAIN.lower() in names


def check_custom_domain(ip, port):
    """第三步：自定义域名 SNI，确认证书包含该域名。"""
    try:
        with create_tls_connection(ip, CUSTOM_DOMAIN, port) as tls_sock:
            return certificate_matches_custom_domain(tls_sock)
    except (OSError, ssl.SSLError, ValueError):
        return False


# ========================= 单个 IP 检测 =========================


def probe_ip(ip):
    """依次尝试各端口，第一个通过三步验证的端口即返回 (国家, 'ip:port')，否则 None。"""
    for port in PORTS:
        if (
            check_tls(ip, port)
            and check_http_301(ip, port)
            and check_custom_domain(ip, port)
        ):
            country = get_country(ip)
            return (country, f"{ip}:{port}")
    return None


def scan(ip_list):
    """并发扫描所有 IP，返回 [(国家, 'ip:port'), ...]。"""
    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(probe_ip, ip): ip for ip in ip_list}

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
                    country, addr = result
                    print(f"[OK] 有效节点: {addr}#{country}", flush=True)
            except Exception:
                pass

    return results


# ========================= 保存结果 =========================


def save_best_ips(results, output_name, file_path):
    """按地区分组排序保存，格式：ip:port#地区 名字。"""
    # 先按 (国家, ip:port) 排序 -> 同地区聚在一起
    unique = sorted(set(results), key=lambda x: (x[0], x[1]))
    with open(file_path, "w", encoding="utf-8", newline="\n") as file:
        for country, addr in unique:
            file.write(f"{addr}#{country} {output_name}\n")


# ========================= 主流程 =========================


def main():
    ip_list, output_name = load_ip_list(IP_FILE)

    out_file = f"{output_name}.txt"

    print(
        f"开始扫描 {len(ip_list)} 个 IP，端口: {PORTS}，"
        f"结果将保存到 {out_file}\n",
        flush=True,
    )

    results = scan(ip_list)
    print(f"\n扫描完成，得到 {len(results)} 个有效节点。", flush=True)

    save_best_ips(results, output_name, out_file)
    print(f"已保存到 {out_file}。", flush=True)


if __name__ == "__main__":
    main()
