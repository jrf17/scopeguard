"""Recon modules do not promote observations into vulnerabilities."""

from scopeguard.config import parse_config
from scopeguard.http_client import Exchange, PinnedClient
from scopeguard.rate_limit import RateLimiter
from scopeguard.recon.dns import collect_dns
from scopeguard.recon.http import collect_http
from scopeguard.scope import ScopeEnforcer, validate_scope_consistency
from tests.conftest import base_config, clock


def test_dns_mismatch_is_a_scope_violation_not_a_target() -> None:
    config = parse_config(
        base_config(
            recon=["dns"],
            hosts=[
                {
                    "host": "app.lab.internal",
                    "scheme": "http",
                    "ports": [8080],
                    "addresses": ["127.0.0.1"],
                }
            ],
        )
    )
    validate_scope_consistency(config)
    observations = collect_dns(
        config,
        ScopeEnforcer(config),
        resolver=lambda host, port: ["8.8.8.8"],
        clock=clock(),
    )
    assert observations[0].status == "scope_violation"
    assert observations[0].data["matched"] is False


def test_dns_failure_is_recorded() -> None:
    from scopeguard.errors import NetworkError

    config = parse_config(
        base_config(
            recon=["dns"],
            hosts=[
                {
                    "host": "missing.lab.internal",
                    "scheme": "http",
                    "ports": [8080],
                    "addresses": ["127.0.0.1"],
                }
            ],
        )
    )
    validate_scope_consistency(config)

    def resolver(host: str, port: int) -> list[str]:
        raise NetworkError("nodename nor servname", target=host)

    observations = collect_dns(config, ScopeEnforcer(config), resolver=resolver, clock=clock())
    assert observations[0].status == "error"


def test_http_missing_header_is_informational() -> None:
    config = parse_config(base_config(recon=["http"]))
    validate_scope_consistency(config)

    def sender(pin, parsed, *, timeout: float) -> Exchange:
        del pin, parsed, timeout
        return Exchange(
            url="http://127.0.0.1:8765/",
            pinned_address="127.0.0.1",
            status_code=200,
            headers={"server": "lab"},
            body="ok",
            location_values=(),
            redirects_followed=0,
        )

    client = PinnedClient(
        ScopeEnforcer(config),
        timeout=1,
        rate_limiter=RateLimiter(50),
        sender=sender,
    )
    observations = collect_http(config, client, clock=clock())
    assert observations[0].status == "ok"
    assert "not a vulnerability" in observations[0].summary
    assert "x-content-type-options" in observations[0].data["security_headers_missing"]
    assert observations[0].data["redirects_followed"] == 0


def test_http_does_not_follow_redirect() -> None:
    config = parse_config(base_config(recon=["http"]))
    validate_scope_consistency(config)
    calls: list[str] = []

    def sender(pin, parsed, *, timeout: float) -> Exchange:
        del pin, timeout
        calls.append(parsed.canonical)
        return Exchange(
            url=parsed.canonical,
            pinned_address="127.0.0.1",
            status_code=302,
            headers={},
            body="",
            location_values=("http://8.8.8.8/secret",),
            redirects_followed=0,
        )

    client = PinnedClient(
        ScopeEnforcer(config), timeout=1, rate_limiter=RateLimiter(50), sender=sender
    )
    observations = collect_http(config, client, clock=clock())
    assert calls == ["http://127.0.0.1:8765/"]
    assert observations[0].data["location"] == ["http://8.8.8.8/secret"]
    assert observations[0].data["redirects_followed"] == 0
