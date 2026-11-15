Captured from `scopeguard scan --config examples/scope.local.yaml` against `lab/fixture_app.py --mode vulnerable` on loopback. This is fixture output, not a finding against a production system.

# ScopeGuard assessment: local-fixture

Tool: scopeguard 0.1.0
Started: 2026-11-15T01:08:27Z
Finished: 2026-11-15T01:08:28Z

## Summary

- Confirmed findings: 2
- Inconclusive checks: 0
- Failed checks: 0
- Scope violations: 0
- Negative results: 0
- Informational observations: 3

Confirmed findings are the only results that passed the check's evidence bar. Missing headers, banners, and negative results are not vulnerabilities.

## Confirmed findings

### debug_exposure — http://127.0.0.1:8765/debug

- Identifier: SG-DBG-5868e6729e
- Target: http://127.0.0.1:8765
- Status: confirmed
- Severity: medium

What happened

HTTP 200 contained the configured synthetic marker.

Expected secure behavior

The endpoint is absent, or its response does not contain the synthetic marker.

Why this rating

Rated medium because the endpoint returned the configured synthetic marker with HTTP 2xx and no authentication challenge. It is not rated high or critical: ScopeGuard does not use the exposed data, and the marker is not a real secret.

What to do

Remove debug and configuration endpoints from deployed builds. If a diagnostic endpoint must exist, require authentication, bind it to a management network, and do not return configuration or secrets.

How to reproduce

- Confirm the endpoint is explicitly listed in the assessment file.
- Send a GET request to http://127.0.0.1:8765/debug.
- Confirm the response is HTTP 2xx and contains the configured SG_ marker.
- Do not replace the marker with a real secret.

Evidence

```text
status_code: 200
marker_configured: SG_FIXTURE_DEBUG_TOKEN
marker_found: True
marker_in_body: True
marker_headers: []
body_window: {"component": "fixture", "marker": "SG_FIXTURE_DEBUG_TOKEN", "purpose": "synthetic"}
redirects_followed: 0
pinned_address: 127.0.0.1
elapsed_ms: 5.98
match: exact substring of the configured synthetic marker
```

### open_redirect — http://127.0.0.1:8765/redirect

- Identifier: SG-OR-70824d99ab
- Target: http://127.0.0.1:8765
- Status: confirmed
- Severity: low

What happened

HTTP 302 Location matches the configured canary.

Expected secure behavior

The application ignores absolute and protocol-relative redirect targets and either redirects to a fixed relative path or rejects the request.

Why this rating

Rated low because the check demonstrated an attacker-controlled Location header. It did not demonstrate token theft or account takeover, and the canary was not requested. Impact depends on how much the authorized host is trusted in phishing or login flows.

What to do

Allow only relative, same-origin paths. Reject absolute URLs, protocol-relative URLs, and backslash variants. Prefer a fixed destination, or an allowlist of internal paths, over reflecting the redirect parameter.

How to reproduce

- Confirm the endpoint is explicitly listed in the assessment file.
- Send a GET request to http://127.0.0.1:8765/redirect?next=https%3A%2F%2Fscopeguard.invalid%3A443%2Fsg-canary and do not follow redirects.
- Compare a single Location header to the configured canary URL.
- Do not request the canary host. It is outside scope on purpose.

Evidence

```text
probe_url: http://127.0.0.1:8765/redirect?next=https%3A%2F%2Fscopeguard.invalid%3A443%2Fsg-canary
status_code: 302
location: https://scopeguard.invalid:443/sg-canary
location_count: 1
location_class: canary
location_reason: Location matches the canary scheme, host, port, and path
redirects_followed: 0
pinned_address: 127.0.0.1
elapsed_ms: 6.43
```

## Inconclusive checks

None.

## Failed checks

None.

## Scope violations

None.

## Negative results

None.

## Informational findings

None.

## Informational observations

These are collection results. They are not confirmed vulnerabilities.

### dns — localhost

- Identifier: SG-DNS-e6282b83d4
- Status: ok

localhost resolved to 127.0.0.1 and matched the address pin set.

```text
hostname: localhost
resolved: ['127.0.0.1']
pin_set: ['127.0.0.1']
matched: True
reason: resolution matched the address pin set
```

### http — http://127.0.0.1:8765/

- Identifier: SG-HTTP-11249bc10d
- Status: ok

HTTP 404 from http://127.0.0.1:8765/ in 23.0 ms. Security-header presence is informational and is not a vulnerability finding.

```text
status_code: 404
elapsed_ms: 23.0
pinned_address: 127.0.0.1
server: scopeguard-fixture
security_headers_present: {}
security_headers_missing: ['strict-transport-security', 'content-security-policy', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy']
location: []
redirects_followed: 0
body_prefix: not found
body_truncated: False
```

### http — http://localhost:8765/

- Identifier: SG-HTTP-165999f52f
- Status: ok

HTTP 404 from http://localhost:8765/ in 6.19 ms. Security-header presence is informational and is not a vulnerability finding.

```text
status_code: 404
elapsed_ms: 6.19
pinned_address: 127.0.0.1
server: scopeguard-fixture
security_headers_present: {}
security_headers_missing: ['strict-transport-security', 'content-security-policy', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy']
location: []
redirects_followed: 0
body_prefix: not found
body_truncated: False
```

## Limitations

- ScopeGuard contacts only destinations that are explicit in the assessment file and that pass a connection-time scope check.
- A hostname is not authorized merely because it resolved once. Every address returned at connection time must be in that hostname's address pin set, or the connection is refused.
- The HTTP client connects to the pinned address and does not resolve the name again. This is not a kernel firewall, and it does not constrain other programs on the host.
- Redirects are recorded and never followed. An out-of-scope Location is not requested.
- Environment proxies are ignored so a proxy cannot move a pinned request to another destination.
- Open-redirect validation sends one configured canary to one configured parameter on explicit endpoints. It does not crawl and it does not try encoding bypasses.
- The canary host must be under the .invalid TLD and outside scope. ScopeGuard does not request the canary.
- Debug-exposure confirmation requires HTTP 2xx plus an exact synthetic marker. It is not a judgment that a page is a debug console, and the check does not search for real secrets.
- Cookie, Authorization, and Proxy-Authorization header values are redacted before they are stored. A marker that appears only in those headers is not detected.
- Missing security headers and server banners are observations. They are not confirmed vulnerabilities.
- TLS inspection keeps certificate verification enabled on the recorded result. A certificate captured after verification failure is labeled unverified.
- There is no default target. An empty, wildcard, or CIDR scope is a configuration error.
- Link-local addresses, including cloud metadata addresses, are never scanned. IPv4-mapped IPv6 addresses are classified as the embedded IPv4 address.
