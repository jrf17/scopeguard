# Security policy

ScopeGuard is an assessment aid. It is not a scanning service and it has no default targets.

Use it only with permission. The maintainers will not help point it at systems you do not own or have written authorization to test.

## Reporting a defect

Once this repository is published, use its private security advisory flow. Until then, do not open a public issue that includes a working bypass of the scope checks. Describe the impact and the conditions, not a turnkey attack against a third party.

## What this project will not accept

- Payload lists, crawlers, or default public targets
- Changes that follow redirects off the authorized host
- Changes that disable TLS verification and record the result as trusted
- Lab fixtures that bind a non-loopback address
