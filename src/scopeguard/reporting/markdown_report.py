"""Markdown report for a security engineer and a technical client."""

from __future__ import annotations

from collections import Counter

from scopeguard.models import Assessment, Finding, Observation

_STATUS_HEADINGS = (
    ("confirmed", "Confirmed findings"),
    ("inconclusive", "Inconclusive checks"),
    ("error", "Failed checks"),
    ("scope_violation", "Scope violations"),
    ("not_vulnerable", "Negative results"),
    ("informational", "Informational findings"),
)


def render_markdown(assessment: Assessment) -> str:
    counts = Counter(item.status.value for item in assessment.findings)
    lines = [
        f"# ScopeGuard assessment: {assessment.name}",
        "",
        f"Tool: {assessment.tool} {assessment.version}",
        f"Started: {assessment.started_at}",
        f"Finished: {assessment.finished_at}",
        "",
        "## Summary",
        "",
        f"- Confirmed findings: {counts.get('confirmed', 0)}",
        f"- Inconclusive checks: {counts.get('inconclusive', 0)}",
        f"- Failed checks: {counts.get('error', 0)}",
        f"- Scope violations: {counts.get('scope_violation', 0)}",
        f"- Negative results: {counts.get('not_vulnerable', 0)}",
        f"- Informational observations: {len(assessment.observations)}",
        "",
        "Confirmed findings are the only results that passed the check's evidence bar. "
        "Missing headers, banners, and negative results are not vulnerabilities.",
        "",
    ]
    for status, heading in _STATUS_HEADINGS:
        selected = [item for item in assessment.findings if item.status.value == status]
        lines.extend(_finding_section(heading, selected))
    lines.extend(_observation_section(assessment.observations))
    lines.extend(["## Limitations", ""])
    for item in assessment.limitations:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def _finding_section(heading: str, findings: list[Finding]) -> list[str]:
    lines = [f"## {heading}", ""]
    if not findings:
        lines.extend(["None.", ""])
        return lines
    for finding in findings:
        lines.extend(
            [
                f"### {finding.check} — {finding.endpoint}",
                "",
                f"- Identifier: {finding.id}",
                f"- Target: {finding.target}",
                f"- Status: {finding.status.value}",
                f"- Severity: {finding.severity.value}",
                "",
                "What happened",
                "",
                finding.observed,
                "",
                "Expected secure behavior",
                "",
                finding.expected,
                "",
                "Why this rating",
                "",
                finding.severity_rationale,
                "",
                "What to do",
                "",
                finding.remediation,
                "",
                "How to reproduce",
                "",
            ]
        )
        for step in finding.reproduction:
            lines.append(f"- {step}")
        lines.extend(["", "Evidence", "", "```text"])
        for key, value in finding.evidence.items():
            lines.append(f"{key}: {_fence_safe(value)}")
        lines.extend(["```", ""])
    return lines


def _observation_section(observations: list[Observation]) -> list[str]:
    lines = ["## Informational observations", ""]
    if not observations:
        lines.extend(["None.", ""])
        return lines
    lines.append("These are collection results. They are not confirmed vulnerabilities.")
    lines.append("")
    for item in observations:
        lines.extend(
            [
                f"### {item.module} — {item.target}",
                "",
                f"- Identifier: {item.id}",
                f"- Status: {item.status}",
                "",
                item.summary,
                "",
                "```text",
            ]
        )
        for key, value in item.data.items():
            lines.append(f"{key}: {_fence_safe(value)}")
        lines.extend(["```", ""])
    return lines


def _fence_safe(value: object) -> str:
    text = str(value).replace("```", "'''")
    return text.replace("\n", " ")
