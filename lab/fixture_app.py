#!/usr/bin/env python3
"""Loopback-only fixture for ScopeGuard validation tests.

This is not a general-purpose vulnerable application. It binds to a loopback
address and reflects a redirect parameter or returns a synthetic marker.
It does not fetch URLs and it does not contain real secrets.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

MARKER = "SG_FIXTURE_DEBUG_TOKEN"
SERVER = "scopeguard-fixture"


class LabServer(ThreadingHTTPServer):
    def __init__(self, mode: str, host: str, port: int) -> None:
        self.mode = mode
        self.request_count = 0
        super().__init__((host, port), Handler)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        self.server.request_count += 1
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            body = f"ok host={self.headers.get('Host', '')}".encode()
            self._send(200, body)
            return
        if parsed.path == "/redirect":
            self._redirect(parse_qs(parsed.query).get("next", [""])[0])
            return
        if parsed.path == "/redirect-decoy":
            nxt = parse_qs(parsed.query).get("next", [""])[0]
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in nxt):
                self._send(400, b"rejected")
                return
            self._location(302, f"https://example.invalid/login?next={nxt}")
            return
        if parsed.path == "/debug":
            self._debug()
            return
        self._send(404, b"not found")

    def _redirect(self, nxt: str) -> None:
        if self.server.mode == "vulnerable" and nxt:
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in nxt):
                self._send(400, b"rejected")
                return
            self._location(302, nxt)
            return
        self._location(302, "/home")

    def _debug(self) -> None:
        if self.server.mode == "vulnerable":
            body = json.dumps(
                {
                    "component": "fixture",
                    "marker": MARKER,
                    "purpose": "synthetic",
                }
            ).encode()
            self._send(200, body, content_type="application/json")
            return
        self._send(404, b"not found")

    def _location(self, status: int, location: str) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self._common_headers()
        self.end_headers()

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str = "text/plain",
        extra: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self._common_headers()
        self.end_headers()
        self.wfile.write(body)

    def _common_headers(self) -> None:
        self.send_header("Server", SERVER)
        self.send_header("X-Echo-Host", self.headers.get("Host", ""))
        if self.server.mode == "hardened":
            self.send_header("X-Content-Type-Options", "nosniff")

    def send_response(self, code: int, message: str | None = None) -> None:
        """Skip the library's default Server banner so the fixture sets its own."""
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


def serve(mode: str, host: str, port: int) -> LabServer:
    address = ipaddress.ip_address(host)
    if not address.is_loopback:
        raise SystemExit(f"fixture refuses non-loopback bind address {host}")
    return LabServer(mode, host, port)


def main() -> None:
    parser = argparse.ArgumentParser(description="Loopback fixture for ScopeGuard tests")
    parser.add_argument("--mode", choices=("vulnerable", "hardened"), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = serve(args.mode, args.host, args.port)
    bound_host, bound_port = server.server_address[:2]
    print(f"listening on http://{bound_host}:{bound_port} mode={args.mode}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
