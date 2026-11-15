"""HTTP metadata collection. Not a crawler, and not a vulnerability check."""

from __future__ import annotations

from collections.abc import Callable

from scopeguard.config import AssessmentConfig
from scopeguard.errors import NetworkError, ScopeViolation
from scopeguard.http_client import PinnedClient
from scopeguard.models import Observation
from scopeguard.normalize import normalize_host
from scopeguard.records import make_observation

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


def recon_root_urls(config: AssessmentConfig) -> list[str]:
    urls: list[str] = []
    for entry in config.hosts:
        host = normalize_host(entry.host)
        display = f"[{host}]" if ":" in host else host
        for port in entry.ports:
            urls.append(f"{entry.scheme}://{display}:{port}/")
    return urls


def collect_http(
    config: AssessmentConfig,
    client: PinnedClient,
    *,
    clock: Callable[[], str],
) -> list[Observation]:
    from scopeguard.concurrent import run_concurrent

    def one(url: str) -> Observation:
        try:
            exchange = client.get(url)
        except ScopeViolation as exc:
            return make_observation(
                prefix="HTTP",
                module="http",
                target=url,
                status="scope_violation",
                summary=f"HTTP request not sent: {exc}",
                data={"error": str(exc), "redirects_followed": 0},
                timestamp=clock(),
            )
        except NetworkError as exc:
            return make_observation(
                prefix="HTTP",
                module="http",
                target=url,
                status="error",
                summary=f"HTTP request failed: {exc}",
                data={"error": str(exc), "redirects_followed": 0},
                timestamp=clock(),
            )
        present = {
            name: exchange.headers[name] for name in SECURITY_HEADERS if name in exchange.headers
        }
        missing = [name for name in SECURITY_HEADERS if name not in exchange.headers]
        location = list(exchange.location_values)
        return make_observation(
            prefix="HTTP",
            module="http",
            target=url,
            status="ok",
            summary=(
                f"HTTP {exchange.status_code} from {url} in {exchange.elapsed_ms} ms. "
                "Security-header presence is informational and is not a vulnerability finding."
            ),
            data={
                "status_code": exchange.status_code,
                "elapsed_ms": exchange.elapsed_ms,
                "pinned_address": exchange.pinned_address,
                "server": exchange.headers.get("server"),
                "security_headers_present": present,
                "security_headers_missing": missing,
                "location": location,
                "redirects_followed": exchange.redirects_followed,
                "body_prefix": exchange.body[:200],
                "body_truncated": exchange.body_truncated,
            },
            timestamp=clock(),
        )

    urls = recon_root_urls(config)
    return run_concurrent(
        [lambda url=url: one(url) for url in urls], concurrency=config.limits.concurrency
    )
