#!/usr/bin/env python3
"""Small same-origin text fetcher for the protected account vault."""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urljoin, urlsplit


HOST = "0.0.0.0"
PORT = 8080
TIMEOUT_SECONDS = 8
MAX_URL_LENGTH = 4096
MAX_BODY_BYTES = 1024 * 1024
MAX_REDIRECTS = 3
REDIRECT_CODES = {301, 302, 303, 307, 308}


class ProxyError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def _public_ip(hostname: str, port: int) -> str:
    try:
        addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise ProxyError("目标域名无法解析", 502) from error

    for _, _, _, _, sockaddr in addresses:
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if address.is_global:
            return str(address)

    raise ProxyError("目标地址不是公网地址", 400)


def validate_target(raw_url: str):
    if not raw_url or len(raw_url) > MAX_URL_LENGTH:
        raise ProxyError("取码链接无效或过长", 400)

    try:
        target = urlsplit(raw_url)
        port = target.port
    except ValueError as error:
        raise ProxyError("取码链接格式无效", 400) from error

    if target.scheme not in {"http", "https"} or not target.hostname:
        raise ProxyError("只允许读取 HTTP 或 HTTPS 链接", 400)
    if target.username is not None or target.password is not None:
        raise ProxyError("取码链接不能包含账号认证信息", 400)
    if port is not None and port not in {80, 443}:
        raise ProxyError("取码链接端口不被允许", 400)

    hostname = target.hostname.rstrip(".")
    resolved_port = port or (443 if target.scheme == "https" else 80)
    resolved_ip = _public_ip(hostname, resolved_port)
    return target, hostname.encode("idna").decode("ascii"), resolved_ip, resolved_port


class FixedIPHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, ip: str, port: int):
        super().__init__(host, port, timeout=TIMEOUT_SECONDS)
        self.fixed_ip = ip

    def connect(self):
        self.sock = socket.create_connection((self.fixed_ip, self.port), self.timeout)


class FixedIPHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str, port: int):
        super().__init__(host, port, timeout=TIMEOUT_SECONDS, context=ssl.create_default_context())
        self.fixed_ip = ip

    def connect(self):
        raw_socket = socket.create_connection((self.fixed_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def _decode_body(body: bytes, content_type: str) -> str:
    charset_match = re.search(r"charset\s*=\s*[\"']?([\w.-]+)", content_type, re.I)
    charset = charset_match.group(1) if charset_match else "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def fetch_once(raw_url: str):
    target, hostname, resolved_ip, port = validate_target(raw_url)
    path = target.path or "/"
    if target.query:
        path += "?" + target.query

    host_header = hostname
    if ":" in hostname:
        host_header = f"[{hostname}]"
    if (target.scheme == "http" and port != 80) or (target.scheme == "https" and port != 443):
        host_header += f":{port}"

    connection = (
        FixedIPHTTPSConnection(hostname, resolved_ip, port)
        if target.scheme == "https"
        else FixedIPHTTPConnection(hostname, resolved_ip, port)
    )
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Accept": "text/plain, text/*;q=0.9, */*;q=0.1",
                "Accept-Encoding": "identity",
                "Connection": "close",
                "Host": host_header,
                "User-Agent": "AppleIDVault/1.0",
            },
        )
        response = connection.getresponse()
        if response.status in REDIRECT_CODES:
            location = response.getheader("Location")
            if not location:
                raise ProxyError("目标跳转缺少地址", 502)
            return None, urljoin(raw_url, location)
        if response.status < 200 or response.status >= 300:
            raise ProxyError(f"目标返回 HTTP {response.status}", 502)

        body = response.read(MAX_BODY_BYTES + 1)
        if len(body) > MAX_BODY_BYTES:
            raise ProxyError("目标响应内容过大", 502)
        return _decode_body(body, response.getheader("Content-Type", "")), None
    except ProxyError:
        raise
    except (OSError, http.client.HTTPException, ssl.SSLError) as error:
        raise ProxyError("目标链接读取失败", 502) from error
    finally:
        connection.close()


def fetch_text(raw_url: str) -> str:
    current_url = raw_url
    for _ in range(MAX_REDIRECTS + 1):
        text, redirect_url = fetch_once(current_url)
        if redirect_url is None:
            return text
        current_url = redirect_url
    raise ProxyError("目标跳转次数过多", 502)


class FetchHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_GET(self):  # noqa: N802 - stdlib handler API
        request = urlsplit(self.path)
        if request.path != "/fetch":
            self.send_error(404)
            return

        values = parse_qs(request.query, keep_blank_values=True).get("url", [])
        if len(values) != 1:
            self.send_error(400, "missing url")
            return

        try:
            body = fetch_text(values[0]).encode("utf-8")
        except ProxyError as error:
            message = str(error).encode("utf-8")
            self.send_response(error.status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            self.wfile.write(message)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def self_test():
    try:
        validate_target("http://127.0.0.1/code")
    except ProxyError as error:
        assert error.status == 400
    else:
        raise AssertionError("private address was accepted")

    try:
        validate_target("ftp://example.com/code")
    except ProxyError as error:
        assert error.status == 400
    else:
        raise AssertionError("non-http scheme was accepted")
    print("fetch-proxy self-check: ok")


def serve():
    server = ThreadingHTTPServer((HOST, PORT), FetchHandler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        serve()
