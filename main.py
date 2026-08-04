import re
import socket
import ssl
import tempfile
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


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

# 输入、输出文件
IP_FILE = "ip.txt"
BESTIP_FILE = "bestip.txt"


def load_ip_list(file_path: str) -> list[str]:
    """从文件读取 IP 或 CIDR 网段；网段自动展开成单个 IP。忽略空行和 # 注释。"""
    with open(file_path, "r", encoding="utf-8") as file:
        ip_list = []
        for line in file:
            item = line.split("#", 1)[0].strip()
            if not item:
                continue
            if "/" in item:
                # CIDR 网段，展开成一个个 IP
                try:
                    net = ipaddress.ip_network(item, strict=False)
                    ip_list.extend(str(ip) for ip in net.hosts())
                except ValueError:
                    print(f"[警告] 无效网段，已跳过: {item}", flush=True)
            else:
                ip_list.append(item)
        return ip_list


def create_tls_connection(
    ip: str,
    server_name: str,
    port: int,
    timeout: float = TIMEOUT,
) -> ssl.SSLSocket:
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


# ========================= 第一步：TCP + TLS 探测 =========================


def check_tls(ip: str, port: int) -> bool:
    """通过 TCP + TLS 探测 IP:port，并检查 www.cloudflare.com 的证书。"""
    try:
        with create_tls_connection(ip, TLS_DOMAIN, port) as tls_sock:
            certificate = tls_sock.getpeercert(binary_form=True)
            return bool(certificate and b"cloudflare" in certificate.lower())
    except (OSError, ssl.SSLError):
        return False


# ========================= 第二步：HTTP 301 验证 =========================


def check_http_301(ip: str, port: int) -> bool:
    """使用 crypto.cloudflare.com 作为 TLS SNI 和 HTTP Host，严格检查 301。"""
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


# ========================= 第三步：自定义域名证书验证 =========================


def certificate_matches_custom_domain(tls_sock: ssl.SSLSocket) -> bool:
    """检查 TLS 返回证书的 CN 或 SAN 是否包含自定义域名。"""
    certificate = tls_sock.getpeercert(binary_form=True)
    if not certificate:
        return False

    certificate_file = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".pem",
        encoding="ascii",
        delete=False,
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


def check_custom_domain(ip: str, port: int) -> bool:
    """使用自定义域名作为 TLS SNI，确认返回证书包含该域名。"""
    try:
        with create_tls_connection(ip, CUSTOM_DOMAIN, port) as tls_sock:
            return certificate_matches_custom_domain(tls_sock)
    except (OSError, ssl.SSLError, ValueError):
        return False


# ========================= 单个 IP 检测：多端口，命中即停 =========================


def probe_ip(ip: str) -> str | None:
    """依次尝试各端口，第一个通过三步验证的端口即返回 'ip:port'，否则 None。"""
    for port in PORTS:
        if (
            check_tls(ip, port)
            and check_http_301(ip, port)
            and check_custom_domain(ip, port)
        ):
            return f"{ip}:{port}"
    return None


def scan(ip_list: list[str]) -> list[str]:
    """并发扫描所有 IP，返回通过验证的 'ip:port' 列表。"""
    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(probe_ip, ip): ip
            for ip in ip_list
        }

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
                    print(f"[OK] 有效节点: {result}", flush=True)
            except Exception:
                pass

    return results


# ========================= 保存结果 =========================


def save_best_ips(results: list[str], file_path: str) -> None:
    """将有效 ip:port 保存到 bestip.txt，每行一个并覆盖旧结果。"""
    unique = sorted(set(results))
    with open(file_path, "w", encoding="utf-8", newline="\n") as file:
        for item in unique:
            file.write(f"{item}\n")


# ========================= 主流程 =========================


def main() -> None:
    ip_list = load_ip_list(IP_FILE)
    print(f"开始扫描 {len(ip_list)} 个 IP，端口: {PORTS}\n", flush=True)

    results = scan(ip_list)
    print(f"\n扫描完成，得到 {len(results)} 个有效节点。", flush=True)

    save_best_ips(results, BESTIP_FILE)
    print(f"已保存到 {BESTIP_FILE}。", flush=True)


if __name__ == "__main__":
    main()
