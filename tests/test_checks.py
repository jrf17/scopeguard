"""Open redirect and debug-exposure decisions."""

from scopeguard.checks.debug_exposure import check_debug_exposure, marker_window
from scopeguard.checks.open_redirect import build_probe, check_open_redirect, classify_location
from scopeguard.config import parse_config
from scopeguard.errors import NetworkError
from scopeguard.http_client import Exchange
from scopeguard.models import ValidationStatus
from scopeguard.normalize import parse_http_url
from tests.conftest import base_config, clock

CANARY = "https://scopeguard.invalid/sg-canary"
ENDPOINT = "http://127.0.0.1:8765/redirect"


class FakeClient:
    def __init__(self, exchange: Exchange | None = None, error: Exception | None = None) -> None:
        self.exchange = exchange
        self.error = error
        self.urls: list[str] = []

    def get(self, url: str) -> Exchange:
        self.urls.append(url)
        if self.error:
            raise self.error
        assert self.exchange is not None
        return self.exchange


def _redirect_config() -> object:
    return parse_config(
        base_config(
            recon=[],
            checks=["open_redirect"],
            open_redirect={
                "parameter": "next",
                "canary_url": CANARY,
                "endpoints": [ENDPOINT],
            },
        )
    )


def _debug_config() -> object:
    return parse_config(
        base_config(
            recon=[],
            checks=["debug_exposure"],
            debug_exposure={
                "marker": "SG_FIXTURE_DEBUG_TOKEN",
                "endpoints": ["http://127.0.0.1:8765/debug"],
            },
        )
    )


def _exchange(
    status: int, location: str | None = None, body: str = "", headers: dict[str, str] | None = None
) -> Exchange:
    values = () if location is None else (location,)
    return Exchange(
        url=ENDPOINT,
        pinned_address="127.0.0.1",
        status_code=status,
        headers=headers or {},
        body=body,
        location_values=values,
        redirects_followed=0,
    )


def test_probe_stays_on_the_authorized_host() -> None:
    probe = build_probe(f"{ENDPOINT}?next=https://evil.example/x", "next", CANARY)
    parsed = parse_http_url(probe)
    assert parsed.host == "127.0.0.1"
    assert parsed.path == "/redirect"
    assert "scopeguard.invalid" in probe
    assert "evil.example" not in probe


def test_confirmed_only_when_location_is_the_canary() -> None:
    canary = parse_http_url(CANARY)
    request = parse_http_url(ENDPOINT)
    assert classify_location(CANARY, canary=canary, request=request).kind == "canary"
    assert (
        classify_location("//scopeguard.invalid/sg-canary", canary=canary, request=request).kind
        == "canary"
    )
    assert classify_location("/home", canary=canary, request=request).kind == "relative"
    echoed = f"https://example.invalid/login?next={CANARY}"
    assert classify_location(echoed, canary=canary, request=request).kind == "other"
    suffix = "https://scopeguard.invalid.evil.example/sg-canary"
    assert classify_location(suffix, canary=canary, request=request).kind == "other"
    assert (
        classify_location("javascript:alert(1)", canary=canary, request=request).kind == "non_http"
    )
    assert (
        classify_location(
            "https://user:pass@scopeguard.invalid/sg-canary", canary=canary, request=request
        ).kind
        == "unparseable"
    )


def test_open_redirect_true_positive_and_false_positives() -> None:
    config = _redirect_config()
    confirmed = check_open_redirect(config, FakeClient(_exchange(302, CANARY)), clock=clock())
    assert confirmed[0].status is ValidationStatus.CONFIRMED
    assert confirmed[0].severity.value == "low"
    assert confirmed[0].evidence["redirects_followed"] == 0
    assert "critical" not in confirmed[0].severity_rationale.lower()

    relative = check_open_redirect(config, FakeClient(_exchange(302, "/home")), clock=clock())
    assert relative[0].status is ValidationStatus.NOT_VULNERABLE

    query_echo = check_open_redirect(
        config,
        FakeClient(_exchange(302, f"https://example.invalid/login?next={CANARY}")),
        clock=clock(),
    )
    assert query_echo[0].status is ValidationStatus.NOT_VULNERABLE

    body_only = check_open_redirect(config, FakeClient(_exchange(200, body=CANARY)), clock=clock())
    assert body_only[0].status is not ValidationStatus.CONFIRMED


def test_open_redirect_does_not_request_twice() -> None:
    client = FakeClient(_exchange(302, CANARY))
    check_open_redirect(_redirect_config(), client, clock=clock())
    assert len(client.urls) == 1


def test_open_redirect_network_error_is_not_a_finding() -> None:
    result = check_open_redirect(
        _redirect_config(),
        FakeClient(error=NetworkError("timed out", target=ENDPOINT)),
        clock=clock(),
    )
    assert result[0].status is ValidationStatus.ERROR
    assert result[0].severity.value == "info"


def test_debug_true_positive_requires_marker_and_success() -> None:
    config = _debug_config()
    body = "A" * 400 + "SG_FIXTURE_DEBUG_TOKEN" + "B" * 50
    confirmed = check_debug_exposure(config, FakeClient(_exchange(200, body=body)), clock=clock())
    assert confirmed[0].status is ValidationStatus.CONFIRMED
    assert confirmed[0].severity.value == "medium"
    assert "SG_FIXTURE_DEBUG_TOKEN" in confirmed[0].evidence["body_window"]
    assert len(confirmed[0].evidence["body_window"]) < 200
    assert confirmed[0].severity.value != "critical"

    benign = check_debug_exposure(config, FakeClient(_exchange(200, body="ok")), clock=clock())
    assert benign[0].status is ValidationStatus.NOT_VULNERABLE

    missing = check_debug_exposure(
        config, FakeClient(_exchange(404, body="not found")), clock=clock()
    )
    assert missing[0].status is ValidationStatus.NOT_VULNERABLE

    leaked_error = check_debug_exposure(
        config,
        FakeClient(_exchange(500, body="SG_FIXTURE_DEBUG_TOKEN")),
        clock=clock(),
    )
    assert leaked_error[0].status is ValidationStatus.INCONCLUSIVE


def test_marker_window_is_local() -> None:
    text = ("x" * 500) + "SG_FIXTURE_DEBUG_TOKEN"
    window = marker_window(text, "SG_FIXTURE_DEBUG_TOKEN")
    assert window.startswith("x")
    assert len(window) < 120
