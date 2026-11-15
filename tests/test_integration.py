"""Loopback integration: pinning, redirects, and TLS verification labels."""

import contextlib
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from scopeguard.config import parse_config
from scopeguard.http_client import PinnedClient, redact_headers
from scopeguard.rate_limit import RateLimiter
from scopeguard.recon.tls import inspect_tls
from scopeguard.runner import run_assessment
from scopeguard.scope import ScopeEnforcer, validate_scope_consistency
from tests.conftest import base_config


def test_header_redaction_drops_cookie_values() -> None:
    import httpx

    headers = httpx.Headers({"Set-Cookie": "session=secret", "Server": "lab"})
    cleaned = redact_headers(headers)
    assert cleaned["set-cookie"] == "<redacted>"
    assert "secret" not in str(cleaned)
    assert cleaned["server"] == "lab"


def test_pinned_host_header_and_ignored_proxy(lab, monkeypatch: pytest.MonkeyPatch) -> None:
    server = lab("vulnerable")
    port = server.server_address[1]
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    config = parse_config(
        base_config(
            recon=["http"],
            hosts=[
                {
                    "host": "fixture.invalid",
                    "scheme": "http",
                    "ports": [port],
                    "addresses": ["127.0.0.1"],
                }
            ],
        )
    )
    validate_scope_consistency(config)
    client = PinnedClient(
        ScopeEnforcer(config),
        timeout=2,
        rate_limiter=RateLimiter(20),
        resolver=lambda host, port: ["127.0.0.1"],
    )
    exchange = client.get(f"http://fixture.invalid:{port}/health")
    assert exchange.status_code == 200
    assert exchange.pinned_address == "127.0.0.1"
    assert exchange.headers["x-echo-host"] == f"fixture.invalid:{port}"
    assert server.request_count == 1


def test_redirect_is_not_followed(lab) -> None:
    server = lab("vulnerable")
    port = server.server_address[1]
    config = parse_config(
        base_config(
            recon=[],
            checks=["open_redirect"],
            hosts=[{"host": "127.0.0.1", "scheme": "http", "ports": [port]}],
            open_redirect={
                "parameter": "next",
                "canary_url": "https://scopeguard.invalid/sg-canary",
                "endpoints": [f"http://127.0.0.1:{port}/redirect"],
            },
        )
    )
    assessment = run_assessment(config)
    finding = assessment.findings[0]
    assert finding.status.value == "confirmed"
    assert finding.evidence["redirects_followed"] == 0
    assert server.request_count == 1


def test_decoy_redirect_is_not_confirmed(lab) -> None:
    server = lab("vulnerable")
    port = server.server_address[1]
    config = parse_config(
        base_config(
            recon=[],
            checks=["open_redirect"],
            hosts=[{"host": "127.0.0.1", "scheme": "http", "ports": [port]}],
            open_redirect={
                "parameter": "next",
                "canary_url": "https://scopeguard.invalid/sg-canary",
                "endpoints": [f"http://127.0.0.1:{port}/redirect-decoy"],
            },
        )
    )
    assessment = run_assessment(config)
    assert assessment.findings[0].status.value == "not_vulnerable"


def test_tls_failure_is_not_reported_as_success(tmp_path: Path) -> None:
    cert, key = _cert(tmp_path, san="IP:127.0.0.1")
    port = _serve_tls(cert, key)
    failed = inspect_tls(address="127.0.0.1", port=port, server_hostname="127.0.0.1", timeout=3)
    assert failed["verification"] == "failed"
    assert failed["unverified_capture"] is True
    assert "passed" not in str(failed["verification"])
    trusted = inspect_tls(
        address="127.0.0.1",
        port=port,
        server_hostname="127.0.0.1",
        timeout=3,
        cafile=str(cert),
    )
    assert trusted["verification"] == "passed"
    assert trusted["hostname_validation"] == "passed"
    assert trusted["unverified_capture"] is False
    assert str(trusted["tls_version"]).startswith("TLS")


def test_tls_hostname_mismatch_fails(tmp_path: Path) -> None:
    cert, key = _cert(tmp_path, san="DNS:example.invalid")
    port = _serve_tls(cert, key)
    result = inspect_tls(
        address="127.0.0.1",
        port=port,
        server_hostname="127.0.0.1",
        timeout=3,
        cafile=str(cert),
    )
    assert result["verification"] == "failed"
    assert result["hostname_validation"] == "failed"


def _cert(tmp_path: Path, *, san: str) -> tuple[Path, Path]:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
            "-nodes",
            "-subj",
            "/CN=scopeguard-test",
            "-addext",
            f"subjectAltName={san}",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def _serve_tls(cert: Path, key: Path) -> int:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    sock.settimeout(0.5)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def accept() -> None:
        while not stop.is_set():
            try:
                conn, _addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                tls = context.wrap_socket(conn, server_side=True)
                tls.settimeout(1)
                with contextlib.suppress(Exception):
                    tls.recv(64)
                tls.close()
            except Exception:
                with contextlib.suppress(Exception):
                    conn.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    return port
