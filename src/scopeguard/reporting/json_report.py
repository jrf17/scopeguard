"""JSON report serialization."""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from scopeguard.errors import ConfigError
from scopeguard.models import Assessment


def dump_assessment(assessment: Assessment) -> str:
    return assessment.model_dump_json(indent=2) + "\n"


def load_assessment_result(path: Path) -> Assessment:
    text = Path(path).read_text(encoding="utf-8")
    try:
        return Assessment.model_validate_json(text)
    except ValidationError as exc:
        raise ConfigError(f"assessment file is not a ScopeGuard report: {exc}") from exc
