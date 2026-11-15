"""CLI exit codes and a loopback scan."""

import json
from pathlib import Path

from typer.testing import CliRunner

from scopeguard.cli import app
from tests.conftest import ROOT

runner = CliRunner()


def test_help_and_missing_command() -> None:
    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0
    assert "scan" in help_result.stdout
    assert "config" in help_result.stdout
    missing = runner.invoke(app, [])
    assert missing.exit_code == 2


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_validate_example_and_reject_metadata(tmp_path: Path) -> None:
    good = runner.invoke(
        app, ["config", "validate", "--config", str(ROOT / "examples" / "scope.local.yaml")]
    )
    assert good.exit_code == 0
    assert "valid" in good.stdout
    assert "allow_public: false" in good.stdout
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "name: bad\nhosts:\n  - host: 169.254.169.254\n    scheme: http\n    ports: [80]\n"
        "path_prefixes: ['/']\nrecon: [http]\nallow_private: true\n",
        encoding="utf-8",
    )
    rejected = runner.invoke(app, ["config", "validate", "--config", str(bad)])
    assert rejected.exit_code == 2
    assert "never scanned" in rejected.stderr + rejected.stdout


def test_scan_vulnerable_and_hardened(lab, tmp_path: Path) -> None:
    vulnerable = lab("vulnerable")
    port = vulnerable.server_address[1]
    config = tmp_path / "scope.yaml"
    config.write_text(_config(port), encoding="utf-8")
    output = tmp_path / "out"
    result = runner.invoke(
        app,
        ["scan", "--config", str(config), "--output", str(output), "--fail-on", "confirmed"],
    )
    assert result.exit_code == 4, result.stdout + result.stderr
    report = json.loads((output / "assessment.json").read_text(encoding="utf-8"))
    confirmed = [item for item in report["findings"] if item["status"] == "confirmed"]
    assert {item["check"] for item in confirmed} == {"open_redirect", "debug_exposure"}
    assert all(item["evidence"]["redirects_followed"] == 0 for item in report["findings"])
    assert "session=" not in (output / "assessment.json").read_text(encoding="utf-8")
    markdown = (output / "assessment.md").read_text(encoding="utf-8")
    assert "Confirmed findings" in markdown
    assert report["limitations"]

    hardened_server = lab("hardened")
    hardened_port = hardened_server.server_address[1]
    hardened_config = tmp_path / "hardened.yaml"
    hardened_config.write_text(_config(hardened_port), encoding="utf-8")
    hardened_out = tmp_path / "hardened"
    hardened = runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(hardened_config),
            "--output",
            str(hardened_out),
            "--fail-on",
            "confirmed",
        ],
    )
    assert hardened.exit_code == 0, hardened.stdout + hardened.stderr
    hardened_report = json.loads((hardened_out / "assessment.json").read_text(encoding="utf-8"))
    assert not [item for item in hardened_report["findings"] if item["status"] == "confirmed"]


def test_report_command_renders_markdown(lab, tmp_path: Path) -> None:
    server = lab("vulnerable")
    config = tmp_path / "scope.yaml"
    config.write_text(_config(server.server_address[1]), encoding="utf-8")
    output = tmp_path / "out"
    scanned = runner.invoke(app, ["scan", "--config", str(config), "--output", str(output)])
    assert scanned.exit_code == 0
    rendered = runner.invoke(app, ["report", "--input", str(output / "assessment.json")])
    assert rendered.exit_code == 0
    assert "ScopeGuard assessment" in rendered.stdout


def test_scan_rejects_bad_fail_on(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(ROOT / "examples" / "scope.local.yaml"),
            "--output",
            str(tmp_path / "out"),
            "--fail-on",
            "high",
        ],
    )
    assert result.exit_code == 2


def _config(port: int) -> str:
    return f"""
name: cli-test
allow_loopback: true
allow_private: false
allow_public: false
hosts:
  - host: 127.0.0.1
    scheme: http
    ports: [{port}]
path_prefixes: ["/"]
limits:
  timeout_seconds: 3
  concurrency: 1
  rate_limit_rps: 20
recon: [http]
checks: [open_redirect, debug_exposure]
open_redirect:
  parameter: next
  canary_url: https://scopeguard.invalid/sg-canary
  endpoints:
    - http://127.0.0.1:{port}/redirect
debug_exposure:
  marker: SG_FIXTURE_DEBUG_TOKEN
  endpoints:
    - http://127.0.0.1:{port}/debug
output:
  formats: [json, markdown]
"""
