"""Authorization boundary for every destination ScopeGuard contacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scopeguard.config import AssessmentConfig, parse_config, read_config_data
from scopeguard.errors import ConfigError
from scopeguard.normalize import (
    ParsedURL,
    is_ip,
    normalize_host,
    parse_http_url,
    path_allowed,
    policy_rejection,
)


@dataclass(frozen=True)
class Pin:
    host: str
    port: int
    address: str
    scheme: str

    @property
    def ready(self) -> bool:
        return self.address != ""


@dataclass(frozen=True)
class Authorization:
    allowed: bool
    reason: str
    pin: Pin | None = None


class ScopeEnforcer:
    """Match destinations against the explicit host, port, scheme, and path list."""

    def __init__(self, config: AssessmentConfig) -> None:
        self.config = config
        self._entries: list[tuple[str, object]] = []
        for entry in config.hosts:
            host = normalize_host(entry.host)
            pins = frozenset(normalize_host(item) for item in entry.addresses)
            if is_ip(host) and not pins:
                pins = frozenset({host})
            self._entries.append((host, entry, pins))  # type: ignore[arg-type]
        self._prefixes = tuple(config.path_prefixes)

    def authorize_url(self, url: str) -> Authorization:
        parsed = parse_http_url(url)
        return self.authorize_destination(
            host=parsed.host,
            port=parsed.port,
            scheme=parsed.scheme,
            path=parsed.path,
        )

    def authorize_destination(
        self,
        *,
        host: str,
        port: int,
        scheme: str,
        path: str = "/",
    ) -> Authorization:
        norm_host = normalize_host(host)
        if scheme not in {"http", "https"}:
            return Authorization(False, f"scheme {scheme!r} is not permitted")
        if not path_allowed(path, self._prefixes):
            return Authorization(False, f"path {path!r} is outside permitted prefixes")
        matched = self._match(norm_host, port, scheme)
        if matched is None:
            return Authorization(
                False, f"{norm_host}:{port} ({scheme}) is not an authorized destination"
            )
        _host, _entry, pins = matched
        if is_ip(norm_host):
            reason = self._address_reason(norm_host)
            if reason:
                return Authorization(False, reason)
            return Authorization(
                True,
                "authorized ip destination",
                Pin(host=norm_host, port=port, address=norm_host, scheme=scheme),
            )
        return Authorization(
            True,
            "authorized hostname; address pin required before connect",
            Pin(host=norm_host, port=port, address="", scheme=scheme),
        )

    def pin_resolution(
        self,
        host: str,
        port: int,
        scheme: str,
        resolved: list[str],
    ) -> Authorization:
        """Accept a connection only when every answer is pinned and policy-safe.

        A mixed answer, even one that includes the expected address, is refused.
        That is the DNS-change control. It is not a kernel-level guarantee.
        """
        norm_host = normalize_host(host)
        matched = self._match(norm_host, port, scheme)
        if matched is None:
            return Authorization(
                False, f"{norm_host}:{port} ({scheme}) is not an authorized destination"
            )
        _host, _entry, pins = matched
        if not resolved:
            return Authorization(False, f"{norm_host} did not resolve to any address")
        normalized: list[str] = []
        for raw in resolved:
            try:
                address = normalize_host(raw)
            except ValueError as exc:
                return Authorization(False, f"resolver returned an unusable address: {exc}")
            if not is_ip(address):
                return Authorization(False, f"resolver returned non-ip {address!r}")
            reason = self._address_reason(address)
            if reason:
                return Authorization(False, reason)
            normalized.append(address)
        unexpected = [item for item in normalized if item not in pins]
        if unexpected:
            listed = ", ".join(sorted(pins)) or "(empty)"
            found = ", ".join(unexpected)
            return Authorization(
                False,
                f"{norm_host} resolved to {found}, outside the configured address pin set ({listed})",
            )
        return Authorization(
            True,
            "resolution matched the address pin set",
            Pin(host=norm_host, port=port, address=normalized[0], scheme=scheme),
        )

    def _match(
        self, host: str, port: int, scheme: str
    ) -> tuple[str, object, frozenset[str]] | None:
        for entry_host, entry, pins in self._entries:  # type: ignore[misc]
            if entry_host == host and entry.scheme == scheme and port in entry.ports:  # type: ignore[attr-defined]
                return entry_host, entry, pins
        return None

    def _address_reason(self, address: str) -> str | None:
        return policy_rejection(
            address,
            allow_loopback=self.config.allow_loopback,
            allow_private=self.config.allow_private,
            allow_public=self.config.allow_public,
        )


def validate_scope_consistency(config: AssessmentConfig) -> None:
    """Refuse a file that would authorize an unsafe or contradictory destination."""
    enforcer = ScopeEnforcer(config)
    flags = {
        "allow_loopback": config.allow_loopback,
        "allow_private": config.allow_private,
        "allow_public": config.allow_public,
    }
    needs_root = "http" in config.recon or "tls" in config.recon
    if needs_root and not path_allowed("/", config.path_prefixes):
        raise ConfigError(
            "http and tls recon request '/'; add '/' to path_prefixes or disable them"
        )
    for entry in config.hosts:
        host = normalize_host(entry.host)
        if is_ip(host):
            reason = policy_rejection(host, **flags)
            if reason:
                raise ConfigError(reason)
        for raw in entry.addresses:
            address = normalize_host(raw)
            reason = policy_rejection(address, **flags)
            if reason:
                raise ConfigError(reason)
        for port in entry.ports:
            if needs_root:
                auth = enforcer.authorize_destination(
                    host=host, port=port, scheme=entry.scheme, path="/"
                )
                if not auth.allowed:
                    raise ConfigError(auth.reason)
    if config.open_redirect is not None:
        _require_out_of_scope_canary(enforcer, config.open_redirect.canary_url)
        for endpoint in config.open_redirect.endpoints:
            _require_in_scope(enforcer, endpoint, "open redirect endpoint")
    if config.debug_exposure is not None:
        for endpoint in config.debug_exposure.endpoints:
            _require_in_scope(enforcer, endpoint, "debug exposure endpoint")


def load_assessment(path: Path) -> AssessmentConfig:
    config = parse_config(read_config_data(path))
    validate_scope_consistency(config)
    return config


def _require_in_scope(enforcer: ScopeEnforcer, url: str, label: str) -> ParsedURL:
    try:
        auth = enforcer.authorize_url(url)
    except ValueError as exc:
        raise ConfigError(f"{label} is not a usable url: {exc}") from exc
    if not auth.allowed:
        raise ConfigError(f"{label} is not in scope: {auth.reason}")
    return parse_http_url(url)


def _require_out_of_scope_canary(enforcer: ScopeEnforcer, url: str) -> None:
    try:
        auth = enforcer.authorize_url(url)
    except ValueError as exc:
        raise ConfigError(f"canary url is not usable: {exc}") from exc
    if auth.allowed:
        raise ConfigError(
            "open redirect canary is inside the assessment scope; "
            "refusing an in-scope test destination"
        )
