"""Normalization for hosts, paths, and absolute HTTP URLs.

Fail closed. A value that is ambiguous to parsers is rejected rather than
rewritten into a destination the operator did not name.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit, urlunsplit

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)
_HEX = re.compile(r"^[0-9A-Fa-f]{2}$")
_NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+)$")
_UNSPECIFIED_V4 = ipaddress.ip_network("0.0.0.0/8")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class NormalizationError(ValueError):
    """A host, path, or URL is not acceptable as an assessment destination."""


def _looks_like_ip_literal(value: str) -> bool:
    """True for dotted or hex forms that must not fall through as hostnames."""
    if ":" in value or value.lower().startswith("0x"):
        return True
    if value.isdigit():
        return True
    labels = value.split(".")
    return len(labels) > 1 and all(_NUMERIC_LABEL.match(label) for label in labels)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def normalize_host(value: str) -> str:
    """Return a canonical host or IP. IPv4-mapped IPv6 becomes the IPv4 address."""
    if not isinstance(value, str):
        raise NormalizationError("host must be a string")
    host = value.strip()
    if host.startswith("[") and host.endswith("]") and len(host) > 2:
        host = host[1:-1]
    if not host:
        raise NormalizationError("host is empty")
    if any(ord(ch) <= 32 or ord(ch) == 127 or ch in "\\/#?@" for ch in host):
        raise NormalizationError("host contains whitespace or a forbidden character")
    if "%" in host:
        raise NormalizationError("ipv6 zone identifiers are not permitted")
    try:
        parsed: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(host)
    except ValueError:
        parsed = None
    if parsed is not None:
        mapped = getattr(parsed, "ipv4_mapped", None)
        if mapped is not None:
            parsed = mapped
        return str(parsed)
    if _looks_like_ip_literal(host):
        raise NormalizationError(f"{value!r} is not a valid ip address")
    lowered = host[:-1] if host.endswith(".") else host
    lowered = lowered.lower()
    if not lowered or lowered.endswith("."):
        raise NormalizationError("host is empty")
    try:
        ascii_host = lowered.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NormalizationError("host is not valid unicode") from exc
    if not _HOSTNAME.match(ascii_host):
        raise NormalizationError(f"{value!r} is not a valid hostname or ip address")
    return ascii_host


def address_kind(address: str) -> str:
    """Classify a normalized IP.

    Link-local is reported separately from private. Python treats 169.254.0.0/16
    as private as well as link-local, and loopback as private. Callers must use
    this order so ``allow_private`` cannot authorize metadata or loopback.
    """
    ip = ipaddress.ip_address(address)
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if ip.version == 4 and (ip in _UNSPECIFIED_V4 or ip in _CGNAT):
        return "rejected"
    if ip.is_unspecified or ip.is_multicast:
        return "rejected"
    if ip.is_link_local:
        return "link_local"
    if ip.is_loopback:
        return "loopback"
    if ip.is_reserved:
        return "rejected"
    if ip.is_private:
        return "private"
    if ip.is_global:
        return "public"
    return "rejected"


def policy_rejection(
    address: str,
    *,
    allow_loopback: bool,
    allow_private: bool,
    allow_public: bool,
) -> str | None:
    """Return a refusal reason, or None when the address class is permitted."""
    kind = address_kind(address)
    if kind == "link_local":
        return f"{address} is link-local, which includes cloud metadata, and is never scanned"
    if kind == "rejected":
        return (
            f"{address} is unspecified, multicast, shared, reserved, or otherwise "
            "not a permitted address class and is never scanned"
        )
    if kind == "loopback" and not allow_loopback:
        return f"{address} is loopback and allow_loopback is false"
    if kind == "private" and not allow_private:
        return f"{address} is a private address and allow_private is false"
    if kind == "public" and not allow_public:
        return f"{address} is a public address and allow_public is false"
    if kind not in {"loopback", "private", "public"}:
        return f"{address} is not a permitted address class"
    return None


def normalize_path(path: str) -> str:
    """Canonicalize an absolute path. Reject traversal and encoded separators."""
    if not isinstance(path, str) or path == "":
        raise NormalizationError("path must be an absolute path")
    if not path.startswith("/"):
        raise NormalizationError("path must start with '/'")
    if any(ord(ch) <= 32 or ord(ch) == 127 or ch == "\\" for ch in path):
        raise NormalizationError("path contains whitespace, a control character, or a backslash")
    trailing = path.endswith("/") and path != "/"
    out: list[str] = []
    for segment in path.split("/"):
        if segment in {"", "."}:
            continue
        decoded = _decode_segment(segment)
        if decoded in {"", "."}:
            continue
        if decoded == "..":
            if not out:
                raise NormalizationError("path escapes the root")
            out.pop()
            continue
        if (
            "/" in decoded
            or "\\" in decoded
            or any(ord(ch) <= 32 or ord(ch) == 127 for ch in decoded)
        ):
            raise NormalizationError("path segment is not safe")
        out.append(decoded)
    normalized = "/" + "/".join(out)
    if trailing and normalized != "/":
        normalized += "/"
    return normalized


def path_allowed(path: str, prefixes: list[str] | tuple[str, ...]) -> bool:
    """True when ``path`` equals a prefix or is a child of one.

    A trailing slash does not change the prefix. ``/redirect`` does not match
    ``/redirect-decoy``.
    """
    normalized = normalize_path(path).rstrip("/") or "/"
    for prefix in prefixes:
        pref = normalize_path(prefix).rstrip("/") or "/"
        if pref == "/" or normalized == pref or normalized.startswith(pref + "/"):
            return True
    return False


def _decode_segment(segment: str) -> str:
    if "%" not in segment:
        return segment
    for piece in segment.split("%")[1:]:
        if len(piece) < 2 or _HEX.match(piece[:2]) is None:
            raise NormalizationError("path contains a malformed percent-escape")
    decoded = unquote(segment)
    if "%" in decoded:
        raise NormalizationError("nested percent-encoding is not permitted")
    return decoded


@dataclass(frozen=True)
class ParsedURL:
    scheme: str
    host: str
    port: int
    path: str
    query: str

    @property
    def canonical(self) -> str:
        return urlunsplit(
            (self.scheme, f"{self.display_host}:{self.port}", self.path, self.query, "")
        )

    @property
    def display_host(self) -> str:
        if ":" in self.host:
            return f"[{self.host}]"
        return self.host

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.display_host}:{self.port}"

    @property
    def request_target(self) -> str:
        if self.query:
            return f"{self.path}?{self.query}"
        return self.path


def parse_http_url(url: str) -> ParsedURL:
    """Parse an absolute http(s) URL. Reject userinfo, fragments, and tricks."""
    if not isinstance(url, str) or url == "":
        raise NormalizationError("url must be a non-empty string")
    if any(ord(ch) <= 32 or ord(ch) == 127 or ch == "\\" for ch in url):
        raise NormalizationError("url contains whitespace, a control character, or a backslash")
    if url.startswith("//"):
        raise NormalizationError("protocol-relative urls are not assessment targets")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise NormalizationError(f"scheme {scheme!r} is not permitted")
    if parts.username is not None or parts.password is not None:
        raise NormalizationError("url userinfo is not permitted")
    if parts.fragment:
        raise NormalizationError("url fragments are not permitted")
    if parts.hostname is None:
        raise NormalizationError("url is missing a host")
    host = normalize_host(parts.hostname)
    try:
        port = parts.port
    except ValueError as exc:
        raise NormalizationError("url port is invalid") from exc
    if port is None:
        port = 443 if scheme == "https" else 80
    path = normalize_path(parts.path or "/")
    if any(ord(ch) <= 32 or ord(ch) == 127 or ch == "\\" for ch in parts.query):
        raise NormalizationError("query contains a forbidden character")
    return ParsedURL(scheme, host, port, path, parts.query)


def host_header(parsed: ParsedURL) -> str:
    """Host header value for the original name, not the pinned address."""
    default = 443 if parsed.scheme == "https" else 80
    if parsed.port == default:
        return parsed.display_host
    return f"{parsed.display_host}:{parsed.port}"
