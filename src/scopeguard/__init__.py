"""Scope-aware reconnaissance and validation for authorized assessments."""

__version__ = "0.1.0"


def main() -> None:
    """Console entry point."""
    from scopeguard.cli import app

    app()
