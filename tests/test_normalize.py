"""Host, path, and URL normalization."""

import pytest

from scopeguard.normalize import (
    NormalizationError,
    address_kind,
    normalize_host,
    normalize_path,
    parse_http_url,
    path_allowed,
    policy_rejection,
)


def test_hostname_case_and_trailing_dot() -> None:
    assert normalize_host("LocalHost.") == "localhost"
    assert normalize_host("Café.Example") == "xn--caf-dma.example"


def test_ipv4_mapped_collapses_to_ipv4() -> None:
    assert normalize_host("::ffff:8.8.8.8") == "8.8.8.8"
    assert normalize_host("::ffff:127.0.0.1") == "127.0.0.1"


def test_rejects_ambiguous_hosts() -> None:
    for value in ("*", "*.example.com", "10.0.0.0/8", "127.0.0.1:80", "host/path", "fe80::1%eth0"):
        with pytest.raises(NormalizationError):
            normalize_host(value)


def test_rejects_octal_and_decimal_ip_tricks() -> None:
    for value in ("0177.0.0.1", "0x7f.0.0.1", "2130706433"):
        with pytest.raises(NormalizationError):
            normalize_host(value)


def test_path_normalization_and_traversal() -> None:
    assert normalize_path("/a/./b/../c") == "/a/c"
    assert normalize_path("/redirect/") == "/redirect/"
    with pytest.raises(NormalizationError):
        normalize_path("/../etc/passwd")
    with pytest.raises(NormalizationError):
        normalize_path("/foo/%2e%2e/%2e%2e/etc")
    with pytest.raises(NormalizationError):
        normalize_path("/foo/%2fbar")
    with pytest.raises(NormalizationError):
        normalize_path("/foo\\bar")
    with pytest.raises(NormalizationError):
        normalize_path("relative")


def test_path_prefix_does_not_match_neighbor() -> None:
    assert path_allowed("/redirect", ["/redirect"])
    assert path_allowed("/redirect/next", ["/redirect"])
    assert not path_allowed("/redirect-decoy", ["/redirect"])
    assert path_allowed("/debug", ["/"])


def test_url_rejects_userinfo_fragment_and_backslash() -> None:
    with pytest.raises(NormalizationError):
        parse_http_url("http://user:pass@127.0.0.1/debug")
    with pytest.raises(NormalizationError):
        parse_http_url("http://127.0.0.1/debug#frag")
    with pytest.raises(NormalizationError):
        parse_http_url("http://127.0.0.1/foo\\bar")
    with pytest.raises(NormalizationError):
        parse_http_url("javascript:alert(1)")
    with pytest.raises(NormalizationError):
        parse_http_url("//127.0.0.1/debug")


def test_url_canonical_includes_port() -> None:
    parsed = parse_http_url("http://127.0.0.1/debug")
    assert parsed.port == 80
    assert parsed.canonical == "http://127.0.0.1:80/debug"


def test_address_classes_used_by_policy() -> None:
    assert address_kind("127.0.0.1") == "loopback"
    assert address_kind("::1") == "loopback"
    assert address_kind("10.1.1.1") == "private"
    assert address_kind("8.8.8.8") == "public"
    assert address_kind("169.254.169.254") == "link_local"
    assert address_kind("::ffff:8.8.8.8") == "public"
    assert address_kind("0.0.0.0") == "rejected"
    assert address_kind("224.0.0.1") == "rejected"
    assert address_kind("100.64.0.1") == "rejected"


def test_link_local_stays_denied_when_private_is_allowed() -> None:
    reason = policy_rejection(
        "169.254.169.254",
        allow_loopback=True,
        allow_private=True,
        allow_public=True,
    )
    assert reason is not None
    assert "never scanned" in reason


def test_mapped_public_requires_allow_public() -> None:
    reason = policy_rejection(
        "8.8.8.8",
        allow_loopback=True,
        allow_private=True,
        allow_public=False,
    )
    assert reason is not None
    assert "public" in reason
