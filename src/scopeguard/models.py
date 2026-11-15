"""Assessment results. Observations are not findings."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ValidationStatus(StrEnum):
    CONFIRMED = "confirmed"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"
    INFORMATIONAL = "informational"
    ERROR = "error"
    SCOPE_VIOLATION = "scope_violation"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    target: str
    endpoint: str
    check: str
    status: ValidationStatus
    severity: Severity
    severity_rationale: str
    observed: str
    expected: str
    evidence: dict[str, Any]
    reproduction: list[str]
    remediation: str
    timestamp: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    module: str
    target: str
    status: str
    summary: str
    data: dict[str, Any]
    timestamp: str


class Assessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    tool: str = "scopeguard"
    version: str
    name: str
    started_at: str
    finished_at: str
    limitations: list[str]
    metadata: dict[str, Any]
    observations: list[Observation]
    findings: list[Finding]


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:10]
    return f"SG-{prefix}-{digest}"
