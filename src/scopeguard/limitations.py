"""Statements included in every report. Do not claim more than this."""

from __future__ import annotations

LIMITATIONS: tuple[str, ...] = (
    "ScopeGuard contacts only destinations that are explicit in the assessment file and that pass a connection-time scope check.",
    "A hostname is not authorized merely because it resolved once. Every address returned at connection time must be in that hostname's address pin set, or the connection is refused.",
    "The HTTP client connects to the pinned address and does not resolve the name again. This is not a kernel firewall, and it does not constrain other programs on the host.",
    "Redirects are recorded and never followed. An out-of-scope Location is not requested.",
    "Environment proxies are ignored so a proxy cannot move a pinned request to another destination.",
    "Open-redirect validation sends one configured canary to one configured parameter on explicit endpoints. It does not crawl and it does not try encoding bypasses.",
    "The canary host must be under the .invalid TLD and outside scope. ScopeGuard does not request the canary.",
    "Debug-exposure confirmation requires HTTP 2xx plus an exact synthetic marker. It is not a judgment that a page is a debug console, and the check does not search for real secrets.",
    "Cookie, Authorization, and Proxy-Authorization header values are redacted before they are stored. A marker that appears only in those headers is not detected.",
    "Missing security headers and server banners are observations. They are not confirmed vulnerabilities.",
    "TLS inspection keeps certificate verification enabled on the recorded result. A certificate captured after verification failure is labeled unverified.",
    "There is no default target. An empty, wildcard, or CIDR scope is a configuration error.",
    "Link-local addresses, including cloud metadata addresses, are never scanned. IPv4-mapped IPv6 addresses are classified as the embedded IPv4 address.",
)
