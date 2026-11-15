"""Open-redirect validation against one configured canary.

The check does not follow redirects and does not request the canary host.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from scopeguard.config import AssessmentConfig
from scopeguard.errors import NetworkError, ScopeViolation
from scopeguard.http_client import Exchange, PinnedClient
from scopeguard.models import Finding, Severity, ValidationStatus
from scopeguard.normalize import NormalizationError, ParsedURL, parse_http_url
from scopeguard.records import (
    ERROR_RATIONALE,
    NEGATIVE_RATIONALE,
    SCOPE_RATIONALE,
    make_finding,
)

CHECK = "open_redirect"
PREFIX = "OR"
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
EXPECTED = (
    "The application ignores absolute and protocol-relative redirect targets and "
    "either redirects to a fixed relative path or rejects the request."
)
REMEDIATION = (
    "Allow only relative, same-origin paths. Reject absolute URLs, protocol-relative "
    "URLs, and backslash variants. Prefer a fixed destination, or an allowlist of "
    "internal paths, over reflecting the redirect parameter."
)
SEVERITY_RATIONALE = (
    "Rated low because the check demonstrated an attacker-controlled Location header. "
    "It did not demonstrate token theft or account takeover, and the canary was not requested. "
    "Impact depends on how much the authorized host is trusted in phishing or login flows."
)


class LocationVerdict:
    def __init__(self, kind: str, reason: str) -> None:
        self.kind = kind
        self.reason = reason


def build_probe(endpoint: str, parameter: str, canary_url: str) -> str:
    parts = urlsplit(endpoint)
    pairs = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key != parameter
    ]
    pairs.append((parameter, canary_url))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))


def classify_location(
    location: str | None,
    *,
    canary: ParsedURL,
    request: ParsedURL,
) -> LocationVerdict:
    if location is None or location == "":
        return LocationVerdict("absent", "no Location header")
    if len(location) > 2048:
        return LocationVerdict("unparseable", "Location header exceeds 2048 characters")
    if any(ord(ch) <= 32 or ord(ch) == 127 for ch in location) or "\\" in location:
        return LocationVerdict(
            "unparseable", "Location contains whitespace, a control character, or a backslash"
        )
    if location.startswith("//"):
        return _classify_protocol_relative(location, canary=canary, request=request)
    scheme_token = location.split(":", 1)[0]
    if (
        ":" in location
        and "/" not in scheme_token
        and not location.startswith("/")
        and scheme_token.lower() not in {"http", "https"}
    ):
        return LocationVerdict("non_http", f"Location scheme {scheme_token!r} is not http(s)")
    if "://" not in location:
        return LocationVerdict("relative", "Location is relative and is not the absolute canary")
    try:
        parsed = parse_http_url(location)
    except NormalizationError as exc:
        return LocationVerdict("unparseable", str(exc))
    return _compare(parsed, canary, absolute=True)


def check_open_redirect(
    config: AssessmentConfig,
    client: PinnedClient,
    *,
    clock: Callable[[], str],
) -> list[Finding]:
    settings = config.open_redirect
    if settings is None:
        return []
    canary = parse_http_url(settings.canary_url)
    findings: list[Finding] = []
    for endpoint in settings.endpoints:
        probe = build_probe(endpoint, settings.parameter, settings.canary_url)
        request = parse_http_url(probe)
        try:
            exchange = client.get(probe)
        except ScopeViolation as exc:
            findings.append(
                _skipped(endpoint, probe, str(exc), ValidationStatus.SCOPE_VIOLATION, clock())
            )
            continue
        except NetworkError as exc:
            findings.append(_skipped(endpoint, probe, str(exc), ValidationStatus.ERROR, clock()))
            continue
        findings.append(_judge(endpoint, probe, request, canary, exchange, clock()))
    return findings


def _classify_protocol_relative(
    location: str,
    *,
    canary: ParsedURL,
    request: ParsedURL,
) -> LocationVerdict:
    try:
        parsed = parse_http_url(f"{request.scheme}:{location}")
    except NormalizationError as exc:
        return LocationVerdict(
            "unparseable", f"protocol-relative Location could not be parsed: {exc}"
        )
    if parsed.host == canary.host and _path_eq(parsed.path, canary.path):
        return LocationVerdict(
            "canary", "protocol-relative Location matches the canary host and path"
        )
    if parsed.host == canary.host:
        return LocationVerdict("partial", "protocol-relative Location matches the canary host only")
    return LocationVerdict("other", "protocol-relative Location does not match the canary")


def _compare(parsed: ParsedURL, canary: ParsedURL, *, absolute: bool) -> LocationVerdict:
    del absolute
    if parsed.host != canary.host:
        return LocationVerdict("other", "Location host does not match the canary")
    if (
        parsed.scheme == canary.scheme
        and parsed.port == canary.port
        and _path_eq(parsed.path, canary.path)
    ):
        return LocationVerdict("canary", "Location matches the canary scheme, host, port, and path")
    return LocationVerdict(
        "partial", "Location host matches the canary but the rest of the URL does not"
    )


def _path_eq(left: str, right: str) -> bool:
    return left.rstrip("/") == right.rstrip("/")


def _judge(
    endpoint: str,
    probe: str,
    request: ParsedURL,
    canary: ParsedURL,
    exchange: Exchange,
    timestamp: str,
) -> Finding:
    locations = exchange.location_values
    if len(locations) > 1:
        verdict = LocationVerdict("unparseable", "multiple Location headers")
        location = locations[0]
    else:
        location = locations[0] if locations else None
        verdict = classify_location(location, canary=canary, request=request)
    is_redirect = exchange.status_code in REDIRECT_STATUSES
    if is_redirect and verdict.kind == "canary":
        status = ValidationStatus.CONFIRMED
        severity = Severity.LOW
        rationale = SEVERITY_RATIONALE
        observed = f"HTTP {exchange.status_code} Location matches the configured canary."
    elif is_redirect and verdict.kind in {"partial", "unparseable", "non_http"}:
        status = ValidationStatus.INCONCLUSIVE
        severity = Severity.INFO
        rationale = "The redirect was ambiguous, so it was not confirmed and not treated as safe."
        observed = f"HTTP {exchange.status_code} with an ambiguous Location ({verdict.reason})."
    elif not is_redirect and verdict.kind == "canary":
        status = ValidationStatus.INCONCLUSIVE
        severity = Severity.INFO
        rationale = "The canary appeared without a redirect status, so the check was not confirmed."
        observed = f"HTTP {exchange.status_code} was not a redirect status."
    else:
        status = ValidationStatus.NOT_VULNERABLE
        severity = Severity.INFO
        rationale = NEGATIVE_RATIONALE
        observed = f"HTTP {exchange.status_code} did not redirect to the canary ({verdict.reason})."
    return make_finding(
        prefix=PREFIX,
        check=CHECK,
        target=request.origin,
        endpoint=endpoint,
        status=status,
        severity=severity,
        severity_rationale=rationale,
        observed=observed,
        expected=EXPECTED,
        evidence={
            "probe_url": probe,
            "status_code": exchange.status_code,
            "location": location,
            "location_count": len(locations),
            "location_class": verdict.kind,
            "location_reason": verdict.reason,
            "redirects_followed": exchange.redirects_followed,
            "pinned_address": exchange.pinned_address,
            "elapsed_ms": exchange.elapsed_ms,
        },
        reproduction=_reproduction(probe),
        remediation=REMEDIATION,
        timestamp=timestamp,
    )


def _skipped(
    endpoint: str, probe: str, reason: str, status: ValidationStatus, timestamp: str
) -> Finding:
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
        evidence={"probe_url": probe, "error": reason, "redirects_followed": 0},
        reproduction=_reproduction(probe),
        remediation=REMEDIATION,
        timestamp=timestamp,
    )


def _reproduction(probe: str) -> list[str]:
    return [
        "Confirm the endpoint is explicitly listed in the assessment file.",
        f"Send a GET request to {probe} and do not follow redirects.",
        "Compare a single Location header to the configured canary URL.",
        "Do not request the canary host. It is outside scope on purpose.",
    ]
