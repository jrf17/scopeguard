"""Shared finding and observation constructors."""

from __future__ import annotations

from typing import Any

from scopeguard.models import Finding, Observation, Severity, ValidationStatus, stable_id

NEGATIVE_RATIONALE = (
    "No vulnerable condition was confirmed. Severity is informational because "
    "this is not a vulnerability finding."
)
ERROR_RATIONALE = "The check did not complete, so there is no vulnerability result to rate."
SCOPE_RATIONALE = (
    "The destination was not contacted. A skipped check is not a vulnerability finding."
)


def make_finding(
    *,
    prefix: str,
    check: str,
    target: str,
    endpoint: str,
    status: ValidationStatus,
    severity: Severity,
    severity_rationale: str,
    observed: str,
    expected: str,
    evidence: dict[str, Any],
    reproduction: list[str],
    remediation: str,
    timestamp: str,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    return Finding(
        id=stable_id(prefix, check, endpoint),
        target=target,
        endpoint=endpoint,
        check=check,
        status=status,
        severity=severity,
        severity_rationale=severity_rationale,
        observed=observed,
        expected=expected,
        evidence=evidence,
        reproduction=reproduction,
        remediation=remediation,
        timestamp=timestamp,
        metadata=metadata or {},
    )


def make_observation(
    *,
    prefix: str,
    module: str,
    target: str,
    status: str,
    summary: str,
    data: dict[str, Any],
    timestamp: str,
) -> Observation:
    return Observation(
        id=stable_id(prefix, module, target, status, summary),
        module=module,
        target=target,
        status=status,
        summary=summary,
        data=data,
        timestamp=timestamp,
    )
