# Security model

ScopeGuard's job is to avoid testing the wrong thing, and to avoid calling an observation a vulnerability.

## Authorization

A destination is authorized only when all of the following are true:

- The host, scheme, and port are explicit entries. Hostnames also require an address pin set.
- The path is under a configured prefix. `/redirect` does not authorize `/redirect-decoy`.
- The address class is permitted. Loopback is allowed by default. Private and public addresses require `allow_private` or `allow_public` in addition to being listed.
- Link-local addresses, including `169.254.169.254`, are never scanned. `allow_private` does not override that. Python classifies that range as private as well as link-local; the policy checks link-local first.
- IPv4-mapped IPv6 addresses are unwrapped and classified as the embedded IPv4 address. `::ffff:8.8.8.8` is a public address, not a loopback bypass.
- `0.0.0.0/8`, multicast, reserved, and shared CGNAT space (`100.64.0.0/10`) are rejected.
- At connection time, every DNS answer must sit inside the pin set. A mixed answer is refused even if one address was expected.

There is no default target. An empty module list, a wildcard, a CIDR, userinfo in a URL, and a canary inside scope are configuration errors.

## Validation bar

Open redirect is confirmed only for HTTP 301, 302, 303, 307, or 308 whose `Location` matches the configured canary's scheme, host, port, and path. A protocol-relative Location is confirmed when the host and path match. A redirect that merely echoes the canary in a query string is not confirmed. The canary must use the `.invalid` TLD. It is not requested.

Debug exposure is confirmed only for HTTP 2xx that contains the configured `SG_` marker as an exact substring. A 200 without the marker is negative. A non-2xx response that contains the marker is inconclusive. Cookie and Authorization values are redacted before analysis, so a marker that appears only there is not detected.

## Severity

- Confirmed open redirect: low. The evidence is an attacker-controlled `Location`, not token theft.
- Confirmed debug exposure: medium. The evidence is an unauthenticated synthetic marker, not use of a real secret.
- Everything else: info. Missing headers are not findings.

## Residual risk

Pinning happens in this process, immediately before connect, against the addresses just returned. A local resolver that returns only an authorized address is not a bypass. A resolver that inserts an unlisted address is refused. Other software on the host is unaffected. Redirect targets are not fetched. Environment proxies are ignored by this client only.

TLS hostname validation uses the configured name, while the TCP connection uses the pinned address. That is deliberate. An unverified certificate capture is labeled and is not a trusted result.

## Lab fixture

`lab/fixture_app.py` binds loopback only. It reflects one query parameter or returns one synthetic marker. It does not fetch the redirect target. Hardened mode ignores the parameter and does not return the marker.
