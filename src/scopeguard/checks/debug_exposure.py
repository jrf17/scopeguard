"""Debug-endpoint validation against one synthetic marker.

Confirmation requires HTTP 2xx and the exact marker. The check does not search
for real credentials and does not guess endpoint paths.
"""

from __future__ import annotations

from collections.abc import Callable

from scopeguard.config import AssessmentConfig
from scopeguard.errors import NetworkError, ScopeViolation
from scopeguard.http_client import Exchange, PinnedClient
from scopeguard.models import Finding, Severity, ValidationStatus
from scopeguard.normalize import parse_http_url
from scopeguard.records import (
    ERROR_RATIONALE,
    NEGATIVE_RATIONALE,
    SCOPE_RATIONALE,
    make_finding,
)

CHECK = "debug_exposure"
PREFIX = "DBG"
EXPECTED = "The endpoint is absent, or its response does not contain the synthetic marker."
REMEDIATION = (
    "Remove debug and configuration endpoints from deployed builds. If a diagnostic "
    "endpoint must exist, require authentication, bind it to a management network, "
    "and do not return configuration or secrets."
)
SEVERITY_RATIONALE = (
    "Rated medium because the endpoint returned the configured synthetic marker with "
    "HTTP 2xx and no authentication challenge. It is not rated high or critical: "
    "ScopeGuard does not use the exposed data, and the marker is not a real secret."
)


def check_debug_exposure(
    config: AssessmentConfig,
    client: PinnedClient,
    *,
    clock: Callable[[], str],
) -> list[Finding]:
    settings = config.debug_exposure
    if settings is None:
        return []
    findings: list[Finding] = []
    for endpoint in settings.endpoints:
        try:
            exchange = client.get(endpoint)
        except ScopeViolation as exc:
            findings.append(_skipped(endpoint, str(exc), ValidationStatus.SCOPE_VIOLATION, clock()))
            continue
        except NetworkError as exc:
            findings.append(_skipped(endpoint, str(exc), ValidationStatus.ERROR, clock()))
            continue
        findings.append(_judge(endpoint, settings.marker, exchange, clock()))
    return findings


def marker_window(text: str, marker: str, radius: int = 60) -> str:
    index = text.find(marker)
    if index < 0:
        return ""
    start = max(0, index - radius)
    end = min(len(text), index + len(marker) + radius)
    return text[start:end]


def _judge(endpoint: str, marker: str, exchange: Exchange, timestamp: str) -> Finding:
    header_hits = [name for name, value in exchange.headers.items() if marker in value]
    body_hit = marker in exchange.body
    found = bool(header_hits or body_hit)
    success = 200 <= exchange.status_code <= 299
    if success and found:
        status = ValidationStatus.CONFIRMED
        severity = Severity.MEDIUM
        rationale = SEVERITY_RATIONALE
        observed = f"HTTP {exchange.status_code} contained the configured synthetic marker."
    elif found:
        status = ValidationStatus.INCONCLUSIVE
        severity = Severity.INFO
        rationale = (
            "The marker was present, but the status was not HTTP 2xx, so the check "
            "was not confirmed."
        )
        observed = f"HTTP {exchange.status_code} contained the marker without a 2xx status."
    else:
        status = ValidationStatus.NOT_VULNERABLE
        severity = Severity.INFO
        rationale = NEGATIVE_RATIONALE
        observed = f"HTTP {exchange.status_code} did not contain the configured marker."
    parsed = parse_http_url(endpoint)
    return make_finding(
        prefix=PREFIX,
        check=CHECK,
        target=parsed.origin,
        endpoint=endpoint,
        status=status,
        severity=severity,
        severity_rationale=rationale,
        observed=observed,
        expected=EXPECTED,
        evidence={
            "status_code": exchange.status_code,
            "marker_configured": marker,
            "marker_found": found,
            "marker_in_body": body_hit,
            "marker_headers": header_hits,
            "body_window": marker_window(exchange.body, marker) if body_hit else "",
            "redirects_followed": exchange.redirects_followed,
            "pinned_address": exchange.pinned_address,
            "elapsed_ms": exchange.elapsed_ms,
            "match": "exact substring of the configured synthetic marker",
        },
        reproduction=[
            "Confirm the endpoint is explicitly listed in the assessment file.",
            f"Send a GET request to {endpoint}.",
            "Confirm the response is HTTP 2xx and contains the configured SG_ marker.",
            "Do not replace the marker with a real secret.",
        ],
        remediation=REMEDIATION,
        timestamp=timestamp,
    )


def _skipped(endpoint: str, reason: str, status: ValidationStatus, timestamp: str) -> Finding:
    rationale = SCOPE_RATIONALE if status is ValidationStatus.SCOPE_VIOLATION else ERROR_RATIONALE
    return make_finding(
        prefix=PREFIX,
        check=CHECK,
        target=endpoint,
        endpoint=endpoint,
        status=status,
        severity=Severity.INFO,
        severity_rationale=rationale,
        observed=reason,
        expected=EXPECTED,
        evidence={"error": reason, "redirects_followed": 0},
        reproduction=[
            "Confirm the endpoint is explicitly listed in the assessment file.",
            f"The check did not complete: {reason}",
        ],
        remediation=REMEDIATION,
        timestamp=timestamp,
    )
