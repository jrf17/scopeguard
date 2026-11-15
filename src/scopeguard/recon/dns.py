"""DNS recon. Reports addresses; does not connect."""

from collections.abc import Callable

from scopeguard.config import AssessmentConfig
from scopeguard.errors import NetworkError
from scopeguard.models import Observation
from scopeguard.normalize import is_ip, normalize_host
from scopeguard.records import make_observation
from scopeguard.resolve import system_resolver
from scopeguard.scope import ScopeEnforcer


def collect_dns(
    config: AssessmentConfig,
    enforcer: ScopeEnforcer,
    *,
    resolver: Callable[[str, int], list[str]] | None = None,
    clock: Callable[[], str],
) -> list[Observation]:
    resolve = resolver or system_resolver
    hostnames = [entry for entry in config.hosts if not is_ip(normalize_host(entry.host))]
    if not hostnames:
        return [
            make_observation(
                prefix="DNS",
                module="dns",
                target="-",
                status="ok",
                summary="No hostnames were configured. DNS recon made no queries.",
                data={"hostnames": []},
                timestamp=clock(),
            )
        ]
    observations: list[Observation] = []
    for entry in hostnames:
        host = normalize_host(entry.host)
        port = entry.ports[0]
        pins = sorted(normalize_host(item) for item in entry.addresses)
        try:
            resolved = resolve(host, port)
        except NetworkError as exc:
            observations.append(
                make_observation(
                    prefix="DNS",
                    module="dns",
                    target=host,
                    status="error",
                    summary=f"DNS resolution failed for {host}: {exc}",
                    data={"hostname": host, "error": str(exc), "pin_set": pins},
                    timestamp=clock(),
                )
            )
            continue
        decision = enforcer.pin_resolution(host, port, entry.scheme, resolved)
        status = "ok" if decision.allowed else "scope_violation"
        summary = (
            f"{host} resolved to {', '.join(resolved)} and matched the address pin set."
            if decision.allowed
            else f"DNS answer for {host} was refused: {decision.reason}"
        )
        observations.append(
            make_observation(
                prefix="DNS",
                module="dns",
                target=host,
                status=status,
                summary=summary,
                data={
                    "hostname": host,
                    "resolved": resolved,
                    "pin_set": pins,
                    "matched": decision.allowed,
                    "reason": decision.reason,
                },
                timestamp=clock(),
            )
        )
    return observations
