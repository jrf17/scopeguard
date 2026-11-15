# Local fixture

`fixture_app.py` is a loopback HTTP server used to demonstrate the two validation checks. It is not a product and it does not contain real secrets.

```bash
uv run python lab/fixture_app.py --mode vulnerable --port 8765
uv run python lab/fixture_app.py --mode hardened --port 8765
```

The process refuses a non-loopback bind address.

Vulnerable mode:

- `GET /redirect?next=https://scopeguard.invalid/sg-canary` returns 302 with that `Location`
- `GET /debug` returns HTTP 200 and the marker `SG_FIXTURE_DEBUG_TOKEN`

Hardened mode:

- `/redirect` returns 302 to `/home` and ignores `next`
- `/debug` returns 404 without the marker

`/redirect-decoy` always redirects to `https://example.invalid/login` and only echoes `next` in the query string. That must not be reported as an open redirect.

## Optional container

Docker is not required. From the repository root:

```bash
docker compose -f lab/compose.yaml up
```

The compose file uses host networking and the fixture still binds `127.0.0.1`.
