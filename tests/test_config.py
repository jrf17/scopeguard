"""Assessment file parsing and fail-closed validation."""

from pathlib import Path

import pytest

from scopeguard.config import parse_config, parse_yaml
from scopeguard.errors import ConfigError
from scopeguard.scope import load_assessment, validate_scope_consistency
from tests.conftest import ROOT, base_config


def test_example_file_is_valid() -> None:
    config = load_assessment(ROOT / "examples" / "scope.local.yaml")
    assert config.name == "local-fixture"
    assert config.allow_public is False
    assert config.open_redirect is not None
    assert config.open_redirect.canary_url.endswith("/sg-canary")


def test_missing_hosts_rejected() -> None:
    data = base_config()
    data.pop("hosts")
    with pytest.raises(ConfigError):
        parse_config(data)


def test_wildcard_and_cidr_hosts_rejected() -> None:
    for host in ("*.example.com", "10.0.0.0/8", ""):
        data = base_config(hosts=[{"host": host, "scheme": "http", "ports": [80]}])
        with pytest.raises(ConfigError):
            parse_config(data)


def test_public_ip_requires_explicit_flag() -> None:
    data = base_config(hosts=[{"host": "8.8.8.8", "scheme": "https", "ports": [443]}])
    config = parse_config(data)
    with pytest.raises(ConfigError, match="public"):
        validate_scope_consistency(config)


def test_metadata_ip_rejected_even_with_private_allowed() -> None:
    data = base_config(
        allow_private=True,
        hosts=[{"host": "169.254.169.254", "scheme": "http", "ports": [80]}],
    )
    config = parse_config(data)
    with pytest.raises(ConfigError, match="never scanned"):
        validate_scope_consistency(config)


def test_mapped_public_ip_is_not_treated_as_loopback() -> None:
    data = base_config(hosts=[{"host": "::ffff:8.8.8.8", "scheme": "https", "ports": [443]}])
    config = parse_config(data)
    with pytest.raises(ConfigError, match="public"):
        validate_scope_consistency(config)


def test_hostname_without_pin_rejected() -> None:
    data = base_config(hosts=[{"host": "app.lab.internal", "scheme": "http", "ports": [8080]}])
    with pytest.raises(ConfigError, match="address pin"):
        parse_config(data)


def test_endpoint_outside_scope_rejected(tmp_path: Path) -> None:
    data = base_config(
        checks=["debug_exposure"],
        recon=[],
        debug_exposure={
            "marker": "SG_FIXTURE_DEBUG_TOKEN",
            "endpoints": ["http://10.1.1.1:8080/debug"],
        },
    )
    path = tmp_path / "scope.yaml"
    path.write_text(_dump(data), encoding="utf-8")
    with pytest.raises(ConfigError, match="not in scope"):
        load_assessment(path)


def test_canary_inside_scope_rejected(tmp_path: Path) -> None:
    data = base_config(
        checks=["open_redirect"],
        recon=[],
        open_redirect={
            "parameter": "next",
            "canary_url": "https://scopeguard.invalid/sg-canary",
            "endpoints": ["http://127.0.0.1:8765/redirect"],
        },
        hosts=[
            {"host": "127.0.0.1", "scheme": "http", "ports": [8765]},
            {
                "host": "scopeguard.invalid",
                "scheme": "https",
                "ports": [443],
                "addresses": ["127.0.0.1"],
            },
        ],
    )
    path = tmp_path / "scope.yaml"
    path.write_text(_dump(data), encoding="utf-8")
    with pytest.raises(ConfigError, match="inside the assessment scope"):
        load_assessment(path)


def test_marker_must_be_synthetic() -> None:
    data = base_config(
        checks=["debug_exposure"],
        recon=[],
        debug_exposure={"marker": "password123", "endpoints": ["http://127.0.0.1:8765/debug"]},
    )
    with pytest.raises(ConfigError, match="marker"):
        parse_config(data)


def test_duplicate_yaml_key_and_alias_rejected() -> None:
    with pytest.raises(ConfigError, match="duplicate YAML key"):
        parse_yaml("name: one\nname: two\n")
    with pytest.raises(ConfigError, match="aliases"):
        parse_yaml("a: &id 1\nb: *id\n")


def test_empty_module_list_rejected() -> None:
    with pytest.raises(ConfigError, match="at least one"):
        parse_config(base_config(recon=[], checks=[]))


def test_extra_field_rejected() -> None:
    with pytest.raises(ConfigError, match="allow_link_local"):
        parse_config(base_config(allow_link_local=True))


def _dump(data: dict[str, object]) -> str:
    import yaml

    return yaml.safe_dump(data, sort_keys=False)
