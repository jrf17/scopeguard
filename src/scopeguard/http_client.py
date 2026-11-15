"""Pinned HTTP client.

httpx is given an IP URL, so it does not resolve the original name. The Host
header and TLS SNI keep that name. Each request uses a new client so a
connection pool cannot reuse a socket for a different host. Environment
proxies are disabled.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlunsplit

import httpx

from scopeguard import __version__
from scopeguard.errors import NetworkError, ScopeViolation
from scopeguard.normalize import ParsedURL, host_header, parse_http_url
from scopeguard.rate_limit import RateLimiter
from scopeguard.resolve import system_resolver
from scopeguard.scope import Pin, ScopeEnforcer

MAX_BODY = 65_536
MAX_HEADER_VALUE = 300
MAX_HEADERS = 40
_REDACT = frozenset({"set-cookie", "cookie", "authorization", "proxy-authorization"})
USER_AGENT = f"scopeguard/{__version__} (+authorized-assessment)"


@dataclass(frozen=True)
class Exchange:
    url: str
    pinned_address: str
    status_code: int
    headers: dict[str, str]
    body: str
    body_truncated: bool = False
    elapsed_ms: float = 0.0
    location_values: tuple[str, ...] = ()
    redirects_followed: int = 0


Sender = Callable[..., Exchange]


@dataclass
class PinnedClient:
    enforcer: ScopeEnforcer
    timeout: float
    rate_limiter: RateLimiter
    resolver: Callable[[str, int], list[str]] = field(default=system_resolver)
    sender: Sender = field(default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.sender is None:
            self.sender = httpx_sender

    def get(self, url: str) -> Exchange:
        try:
            parsed = parse_http_url(url)
        except ValueError as exc:
            raise ScopeViolation(str(exc), target=url) from exc
        auth = self.enforcer.authorize_url(parsed.canonical)
        if not auth.allowed or auth.pin is None:
            raise ScopeViolation(auth.reason, target=parsed.canonical)
        pin = auth.pin
        if not pin.ready:
            self.rate_limiter.wait()
            pin = self._resolve(pin, parsed)
        else:
            self.rate_limiter.wait()
        return self.sender(pin, parsed, timeout=self.timeout)

    def _resolve(self, pin: Pin, parsed: ParsedURL) -> Pin:
        try:
            resolved = self.resolver(pin.host, pin.port)
        except NetworkError:
            raise
        except Exception as exc:
            raise NetworkError(f"dns resolution failed: {exc}", target=parsed.canonical) from exc
        pinned = self.enforcer.pin_resolution(pin.host, pin.port, pin.scheme, resolved)
        if not pinned.allowed or pinned.pin is None or not pinned.pin.ready:
            raise ScopeViolation(pinned.reason, target=parsed.canonical)
        return pinned.pin


def httpx_sender(pin: Pin, parsed: ParsedURL, *, timeout: float) -> Exchange:
    if not pin.ready:
        raise ScopeViolation(
            "refusing to connect without a pinned address", target=parsed.canonical
        )
    pinned_url = _pinned_url(pin, parsed)
    headers = {
        "Host": host_header(parsed),
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    }
    extensions: dict[str, str] = {}
    if parsed.scheme == "https":
        extensions["sni_hostname"] = parsed.host
    started = time.perf_counter()
    try:
        with (
            httpx.Client(
                timeout=httpx.Timeout(timeout),
                follow_redirects=False,
                verify=True,
                trust_env=False,
            ) as client,
            client.stream(
                "GET",
                pinned_url,
                headers=headers,
                extensions=extensions,
                follow_redirects=False,
            ) as response,
        ):
            body, truncated = _read_limited(response)
            status = response.status_code
            resp_headers = redact_headers(response.headers)
            locations = tuple(response.headers.get_list("location"))
    except httpx.TimeoutException as exc:
        raise NetworkError(f"timeout after {timeout}s", target=parsed.canonical) from exc
    except httpx.HTTPError as exc:
        raise NetworkError(str(exc), target=parsed.canonical) from exc
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    return Exchange(
        url=parsed.canonical,
        pinned_address=pin.address,
        status_code=status,
        headers=resp_headers,
        body=body,
        body_truncated=truncated,
        elapsed_ms=elapsed_ms,
        location_values=locations,
        redirects_followed=0,
    )


def redact_headers(headers: httpx.Headers) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for index, (name, value) in enumerate(headers.items()):
        if index >= MAX_HEADERS:
            break
        key = name.lower()
        if key in _REDACT:
            cleaned[key] = "<redacted>"
        else:
            cleaned[key] = value[:MAX_HEADER_VALUE]
    return cleaned


def _pinned_url(pin: Pin, parsed: ParsedURL) -> str:
    host = f"[{pin.address}]" if ":" in pin.address else pin.address
    return urlunsplit((parsed.scheme, f"{host}:{parsed.port}", parsed.path, parsed.query, ""))


def _read_limited(response: httpx.Response) -> tuple[str, bool]:
    chunks: list[bytes] = []
    total = 0
    truncated = False
    for chunk in response.iter_bytes():
        if total >= MAX_BODY:
            truncated = True
            break
        remaining = MAX_BODY - total
        piece = chunk[:remaining]
        chunks.append(piece)
        total += len(piece)
        if len(chunk) > remaining:
            truncated = True
            break
    return b"".join(chunks).decode("utf-8", errors="replace"), truncated
