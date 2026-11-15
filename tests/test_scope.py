"""Connection-time authorization."""

from scopeguard.config import parse_config
from scopeguard.errors import ScopeViolation
from scopeguard.http_client import PinnedClient
from scopeguard.rate_limit import RateLimiter
from scopeguard.scope import ScopeEnforcer, validate_scope_consistency
from tests.conftest import base_config


def _enforcer(**overrides: object) -> ScopeEnforcer:
    config = parse_config(base_config(**overrides))
    validate_scope_consistency(config)
    return ScopeEnforcer(config)


def test_listed_loopback_is_authorized() -> None:
    decision = _enforcer().authorize_url("http://127.0.0.1:8765/debug")
    assert decision.allowed
    assert decision.pin is not None
    assert decision.pin.address == "127.0.0.1"


def test_unlisted_port_host_and_path_are_refused() -> None:
    enforcer = _enforcer(
        path_prefixes=["/debug"],
        recon=[],
        checks=["debug_exposure"],
        debug_exposure={
            "marker": "SG_FIXTURE_DEBUG_TOKEN",
            "endpoints": ["http://127.0.0.1:8765/debug"],
        },
    )
    assert not enforcer.authorize_url("http://127.0.0.1:80/debug").allowed
    assert not enforcer.authorize_url("http://127.0.0.2:8765/debug").allowed
    assert not enforcer.authorize_url("http://127.0.0.1:8765/admin").allowed


def test_unexpected_dns_answer_refuses_before_connect() -> None:
    enforcer = _enforcer(
        hosts=[
            {
                "host": "app.lab.internal",
                "scheme": "http",
                "ports": [8080],
                "addresses": ["127.0.0.1"],
            }
        ]
    )
    mixed = enforcer.pin_resolution("app.lab.internal", 8080, "http", ["127.0.0.1", "8.8.8.8"])
    assert not mixed.allowed
    changed = enforcer.pin_resolution("app.lab.internal", 8080, "http", ["8.8.8.8"])
    assert not changed.allowed
    calls: list[object] = []

    def sender(*args: object, **kwargs: object) -> object:
        calls.append(args)
        raise AssertionError("sender must not be called")

    client = PinnedClient(
        enforcer,
        timeout=1,
        rate_limiter=RateLimiter(50),
        resolver=lambda host, port: ["8.8.8.8"],
        sender=sender,
    )
    with pytest_raises():
        client.get("http://app.lab.internal:8080/")
    assert calls == []


def test_matching_pin_uses_the_pinned_address() -> None:
    enforcer = _enforcer(
        hosts=[
            {
                "host": "fixture.invalid",
                "scheme": "http",
                "ports": [8765],
                "addresses": ["127.0.0.1"],
            }
        ]
    )
    seen: list[str] = []

    def sender(pin, parsed, *, timeout: float):  # type: ignore[no-untyped-def]
        del parsed, timeout
        seen.append(pin.address)
        from scopeguard.http_client import Exchange

        return Exchange(
            url="http://fixture.invalid:8765/",
            pinned_address=pin.address,
            status_code=200,
            headers={},
            body="ok",
        )

    client = PinnedClient(
        enforcer,
        timeout=1,
        rate_limiter=RateLimiter(50),
        resolver=lambda host, port: ["127.0.0.1"],
        sender=sender,
    )
    exchange = client.get("http://fixture.invalid:8765/health")
    assert seen == ["127.0.0.1"]
    assert exchange.pinned_address == "127.0.0.1"


def test_ip_target_does_not_call_resolver() -> None:
    def resolver(host: str, port: int) -> list[str]:
        raise AssertionError(f"resolver called for {host}:{port}")

    client = PinnedClient(
        _enforcer(),
        timeout=1,
        rate_limiter=RateLimiter(50),
        resolver=resolver,
        sender=lambda pin, parsed, timeout: (_ for _ in ()).throw(AssertionError("no send")),
    )
    try:
        client.get("http://8.8.8.8/")
    except ScopeViolation:
        return
    raise AssertionError("expected a scope violation")


def pytest_raises():
    import pytest

    return pytest.raises(ScopeViolation)
