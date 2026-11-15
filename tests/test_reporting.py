"""Report rendering does not inflate results."""

from scopeguard.models import Assessment, Finding, Observation, Severity, ValidationStatus
from scopeguard.reporting.json_report import dump_assessment, load_assessment_result
from scopeguard.reporting.markdown_report import render_markdown


def _assessment() -> Assessment:
    return Assessment(
        version="0.1.0",
        name="sample",
        started_at="2026-01-01T00:00:01Z",
        finished_at="2026-01-01T00:00:02Z",
        limitations=["ScopeGuard contacts only explicit destinations."],
        metadata={"python": "3.14"},
        observations=[
            Observation(
                id="SG-HTTP-1",
                module="http",
                target="http://127.0.0.1:8765/",
                status="ok",
                summary="Security-header presence is informational and is not a vulnerability finding.",
                data={
                    "security_headers_missing": ["content-security-policy"],
                    "set-cookie": "<redacted>",
                },
                timestamp="2026-01-01T00:00:01Z",
            )
        ],
        findings=[
            Finding(
                id="SG-OR-1",
                target="http://127.0.0.1:8765",
                endpoint="http://127.0.0.1:8765/redirect",
                check="open_redirect",
                status=ValidationStatus.CONFIRMED,
                severity=Severity.LOW,
                severity_rationale="Rated low because only a Location header was demonstrated.",
                observed="Location matched the canary.",
                expected="Fixed relative redirect.",
                evidence={"redirects_followed": 0, "set-cookie": "<redacted>"},
                reproduction=["Do not request the canary."],
                remediation="Allow only relative paths.",
                timestamp="2026-01-01T00:00:02Z",
            ),
            Finding(
                id="SG-DBG-1",
                target="http://127.0.0.1:8765",
                endpoint="http://127.0.0.1:8765/debug",
                check="debug_exposure",
                status=ValidationStatus.NOT_VULNERABLE,
                severity=Severity.INFO,
                severity_rationale="No vulnerable condition was confirmed.",
                observed="Marker absent.",
                expected="Marker absent.",
                evidence={"marker_found": False},
                reproduction=["Request the authorized endpoint."],
                remediation="Remove debug endpoints.",
                timestamp="2026-01-01T00:00:02Z",
            ),
        ],
    )


def test_markdown_separates_results_and_does_not_inflate() -> None:
    rendered = render_markdown(_assessment())
    assert "## Confirmed findings" in rendered
    assert "## Negative results" in rendered
    assert "## Informational observations" in rendered
    assert "## Inconclusive checks" in rendered
    assert "## Failed checks" in rendered
    confirmed, _, rest = rendered.partition("## Negative results")
    assert "open_redirect" in confirmed
    assert "debug_exposure" not in confirmed
    assert "content-security-policy" not in confirmed
    assert "not a vulnerability" in rest or "not confirmed vulnerabilities" in rendered


def test_json_round_trip_redacts_cookie_value(tmp_path) -> None:
    path = tmp_path / "assessment.json"
    path.write_text(dump_assessment(_assessment()), encoding="utf-8")
    loaded = load_assessment_result(path)
    text = path.read_text(encoding="utf-8")
    assert "session=secret" not in text
    assert loaded.findings[0].evidence["set-cookie"] == "<redacted>"
    assert loaded.schema_version == 1
