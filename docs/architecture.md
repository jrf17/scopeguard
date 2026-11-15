# Architecture

ScopeGuard is a single package with a thin CLI. A scan loads one YAML file, refuses it if the authorized surface is unsafe, then runs only the named modules.

```text
cli.py
  load_assessment()     config schema + scope consistency
  run_assessment()      module orchestration
    ScopeEnforcer       host, port, scheme, path, address class
    PinnedClient        resolve, pin, rate limit, then HTTPX to the IP
    recon/dns.py        resolve and compare to the pin set; no TCP
    recon/http.py       GET / only; record headers; do not follow redirects
    recon/tls.py        verified handshake to the pinned address
    checks/             explicit endpoints only
  reporting/            JSON is canonical; Markdown is rendered from it
```

## Why the HTTP client rewrites the URL

HTTPX resolves names itself. ScopeGuard instead resolves first, refuses any answer outside the hostname's address pin set, and gives HTTPX an IP URL. The original name is preserved in the `Host` header and, for HTTPS, in the TLS SNI extension (`sni_hostname`). Each request uses a new client so a pool cannot reuse a socket for another host. `trust_env` is false so `HTTP_PROXY` cannot move the request.

That is application-level pinning. It is not a kernel firewall. The limitation is stated in every report.

## Why TLS inspection does not use the HTTP client

Certificate verification, subject, issuer, validity, and the negotiated version are TLS facts. `recon/tls.py` connects to the pinned address with `ssl.create_default_context()`, `CERT_REQUIRED`, and `check_hostname=True`. A failed verification can be followed by a labeled unverified capture so the operator can see the certificate that was rejected. That capture is never recorded as a successful validation.

## What is intentionally absent

- No crawler and no default port list
- No CIDR or wildcard scope
- No redirect following
- No payload catalog
- No severity upgrade for missing headers
