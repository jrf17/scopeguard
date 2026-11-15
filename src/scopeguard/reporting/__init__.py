"""Write assessment reports."""

from __future__ import annotations

from pathlib import Path

from scopeguard.models import Assessment
from scopeguard.reporting.json_report import dump_assessment
from scopeguard.reporting.markdown_report import render_markdown


def write_reports(assessment: Assessment, directory: Path, formats: list[str]) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if "json" in formats:
        path = directory / "assessment.json"
        _atomic(path, dump_assessment(assessment))
        written.append(path)
    if "markdown" in formats:
        path = directory / "assessment.md"
        _atomic(path, render_markdown(assessment))
        written.append(path)
    return written


def _atomic(path: Path, text: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)
