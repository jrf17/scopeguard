"""TLS inspection. Verification stays enabled on the recorded result."""

from __future__ import annotations

import hashlib
import socket
import ssl
import subprocess
from collections.abc import Callable

from scopeguard.config import AssessmentConfig
from scopeguard.errors import NetworkError
from scopeguard.models import Observation
from scopeguard.normalize import normalize_host
from scopeguard.records import make_observation
from scopeguard.resolve import system_resolver
from scopeguard.scope import ScopeEnforcer


def collect_tls(
    config: AssessmentConfig,
    enforcer: ScopeEnforcer,
    *,
    resolver: Callable[[str, int], list[str]] | None = None,
    clock: Callable[[], str],
    cafile: str | None = None,
) -> list[Observation]:
    resolve = resolver or system_resolver
    targets = [entry for entry in config.hosts if entry.scheme == "https"]
    if not targets:
        return [
            make_observation(
                prefix="TLS",
                module="tls",
                target="-",
                status="ok",
                summary="No HTTPS hosts were configured. TLS inspection made no connections.",
                data={"targets": []},
                timestamp=clock(),
            )
        ]
    observations: list[Observation] = []
    for entry in targets:
        host = normalize_host(entry.host)
        for port in entry.ports:
            target = f"https://{host}:{port}"
            auth = enforcer.authorize_destination(host=host, port=port, scheme="https", path="/")
            if not auth.allowed or auth.pin is None:
                observations.append(
                    _obs(
                        target,
                        "scope_violation",
                        f"TLS inspection not started: {auth.reason}",
                        clock,
                        {
                            "verification": "not_attempted",
                            "reason": auth.reason,
                        },
                    )
                )
                continue
            pin = auth.pin
            if not pin.ready:
                try:
                    resolved = resolve(host, port)
                except NetworkError as exc:
                    observations.append(
                        _obs(
                            target,
                            "error",
                            f"TLS inspection did not resolve {host}: {exc}",
                            clock,
                            {
                                "verification": "not_attempted",
                                "error": str(exc),
                            },
                        )
                    )
                    continue
                pinned = enforcer.pin_resolution(host, port, "https", resolved)
                if not pinned.allowed or pinned.pin is None:
                    observations.append(
                        _obs(
                            target,
                            "scope_violation",
                            f"TLS inspection refused: {pinned.reason}",
                            clock,
                            {
                                "verification": "not_attempted",
                                "reason": pinned.reason,
                            },
                        )
                    )
                    continue
                pin = pinned.pin
            data = inspect_tls(
                address=pin.address,
                port=port,
                server_hostname=host,
                timeout=config.limits.timeout_seconds,
                cafile=cafile,
            )
            status = "ok" if data["verification"] == "passed" else "error"
            if data["verification"] == "passed":
                summary = (
                    f"TLS verification passed for {host}:{port} "
                    f"({data.get('tls_version') or 'unknown version'})."
                )
            else:
                summary = (
                    f"TLS verification failed for {host}:{port}: {data.get('verification_error')}. "
                    "An unverified certificate capture is not a trusted result."
                )
            observations.append(_obs(target, status, summary, clock, data))
    return observations


def inspect_tls(
    *,
    address: str,
    port: int,
    server_hostname: str,
    timeout: float,
    cafile: str | None = None,
) -> dict[str, object]:
    """Handshake with verification enabled. On failure, optionally capture the cert."""
    context = ssl.create_default_context(cafile=cafile)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        with (
            socket.create_connection((address, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=server_hostname) as tls,
        ):
            cert = tls.getpeercert() or {}
            return {
                "verification": "passed",
                "verification_error": None,
                "tls_version": tls.version(),
                "subject": _format_name(cert.get("subject")),
                "issuer": _format_name(cert.get("issuer")),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "hostname_validation": "passed",
                "unverified_capture": False,
                "cert_sha256": None,
                "pinned_address": address,
                "server_hostname": server_hostname,
            }
    except ssl.SSLCertVerificationError as exc:
        captured = _capture_unverified(address, port, server_hostname, timeout)
        text = str(exc).lower()
        hostname_failed = "hostname" in text or "mismatch" in text
        data: dict[str, object] = {
            "verification": "failed",
            "verification_error": str(exc),
            "hostname_validation": "failed" if hostname_failed else "not_checked",
            "unverified_capture": captured is not None,
            "pinned_address": address,
            "server_hostname": server_hostname,
        }
        if captured:
            data.update(captured)
        else:
            data.update(
                {
                    "tls_version": None,
                    "subject": None,
                    "issuer": None,
                    "not_before": None,
                    "not_after": None,
                    "cert_sha256": None,
                }
            )
        return data
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        return {
            "verification": "failed",
            "verification_error": str(exc),
            "tls_version": None,
            "subject": None,
            "issuer": None,
            "not_before": None,
            "not_after": None,
            "hostname_validation": "not_checked",
            "unverified_capture": False,
            "cert_sha256": None,
            "pinned_address": address,
            "server_hostname": server_hostname,
        }


def _capture_unverified(
    address: str,
    port: int,
    server_hostname: str,
    timeout: float,
) -> dict[str, object] | None:
    """Second connection used only to label an already-failed verification."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((address, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=server_hostname) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
            version = tls.version()
    except (TimeoutError, OSError, ssl.SSLError):
        return None
    if not der:
        return None
    parsed = _openssl_text(der)
    return {
        "tls_version": version,
        "subject": None if parsed is None else parsed.get("subject"),
        "issuer": None if parsed is None else parsed.get("issuer"),
        "not_before": None if parsed is None else parsed.get("not_before"),
        "not_after": None if parsed is None else parsed.get("not_after"),
        "cert_sha256": hashlib.sha256(der).hexdigest(),
    }


def _openssl_text(der: bytes) -> dict[str, str] | None:
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-dates"],
            input=der,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    fields: dict[str, str] = {}
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        if line.startswith("subject="):
            fields["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            fields["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            fields["not_before"] = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            fields["not_after"] = line.split("=", 1)[1].strip()
    return fields or None


def _format_name(value: object) -> str | None:
    if not value:
        return None
    parts: list[str] = []
    for group in value:  # type: ignore[union-attr]
        for key, item in group:
            parts.append(f"{key}={item}")
    return ", ".join(parts) if parts else None


def _obs(
    target: str,
    status: str,
    summary: str,
    clock: Callable[[], str],
    data: dict[str, object],
) -> Observation:
    return make_observation(
        prefix="TLS",
        module="tls",
        target=target,
        status=status,
        summary=summary,
        data=data,
        timestamp=clock(),
    )
