"""Run the modules named in an assessment file. No implicit targets."""

from __future__ import annotations

import platform
from collections.abc import Callable
from typing import Any

from scopeguard import __version__
from scopeguard.checks.debug_exposure import check_debug_exposure
from scopeguard.checks.open_redirect import check_open_redirect
from scopeguard.config import AssessmentConfig
from scopeguard.http_client import PinnedClient
from scopeguard.limitations import LIMITATIONS
from scopeguard.models import Assessment, utc_now
from scopeguard.rate_limit import RateLimiter
from scopeguard.recon.dns import collect_dns
from scopeguard.recon.http import collect_http
from scopeguard.recon.tls import collect_tls
from scopeguard.resolve import system_resolver
from scopeguard.scope import ScopeEnforcer, validate_scope_consistency


def run_assessment(
    config: AssessmentConfig,
    *,
    resolver: Callable[[str, int], list[str]] | None = None,
    sender: Any = None,
    clock: Callable[[], str] | None = None,
    cafile: str | None = None,
) -> Assessment:
    validate_scope_consistency(config)
    now = clock or utc_now
    started = now()
    enforcer = ScopeEnforcer(config)
    client = PinnedClient(
        enforcer,
        timeout=config.limits.timeout_seconds,
        rate_limiter=RateLimiter(config.limits.rate_limit_rps),
        resolver=resolver or system_resolver,
        sender=sender,
    )
    observations = []
    findings = []
    if "dns" in config.recon:
        observations.extend(collect_dns(config, enforcer, resolver=resolver, clock=now))
    if "http" in config.recon:
        observations.extend(collect_http(config, client, clock=now))
    if "tls" in config.recon:
        observations.extend(
            collect_tls(config, enforcer, resolver=resolver, clock=now, cafile=cafile)
        )
    if "open_redirect" in config.checks:
        findings.extend(check_open_redirect(config, client, clock=now))
    if "debug_exposure" in config.checks:
        findings.extend(check_debug_exposure(config, client, clock=now))
    observations.sort(key=lambda item: item.id)
    findings.sort(key=lambda item: item.id)
    return Assessment(
        version=__version__,
        name=config.name,
        started_at=started,
        finished_at=now(),
        limitations=list(LIMITATIONS),
        metadata={
            "python": platform.python_version(),
            "timeout_seconds": config.limits.timeout_seconds,
            "concurrency": config.limits.concurrency,
            "rate_limit_rps": config.limits.rate_limit_rps,
            "recon": list(config.recon),
            "checks": list(config.checks),
            "allow_loopback": config.allow_loopback,
            "allow_private": config.allow_private,
            "allow_public": config.allow_public,
        },
        observations=observations,
        findings=findings,
    )
