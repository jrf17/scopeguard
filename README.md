# ScopeGuard

ScopeGuard is a command-line tool for authorized reconnaissance and vulnerability validation. It contacts only destinations that are explicit in an assessment file, pins those connections to authorized addresses, and writes evidence that distinguishes confirmed findings from observations.

It is not a general-purpose scanner, and it does not wrap Nmap or Nuclei. There is no default target.

## Authorized use

Use ScopeGuard only against systems you are permitted to test. The local fixture in `lab/` is the supported demonstration target. The tool refuses link-local addresses, including cloud metadata addresses, and it refuses public and private addresses unless the assessment file opts in and lists them.

## Install

Requires Python 3.12 or newer. ScopeGuard uses [uv](https://docs.astral.sh/uv/) to create the virtual environment and install the locked dependencies. `uv` is not part of a normal Python install. If `uv --version` fails, install it, then open a new shell so the installer change to `PATH` is visible:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Inspect the script before running it if you prefer: `curl -LsSf https://astral.sh/uv/install.sh | less`. Other install methods, including a pinned version, are on the [uv installation page](https://docs.astral.sh/uv/getting-started/installation/).

From a checkout of this repository:

```bash
uv sync --all-groups
uv run scopeguard --help
```

`uv sync` installs the project into `.venv`. Use `uv run` for the commands below so that environment is selected. You do not need to activate it.

## Local demonstration

Start the loopback fixture in one terminal:

```bash
uv run python lab/fixture_app.py --mode vulnerable --port 8765
```

In another terminal:

```bash
uv run scopeguard config validate --config examples/scope.local.yaml
uv run scopeguard scan --config examples/scope.local.yaml --output ./results
uv run scopeguard report --input ./results/assessment.json
```

`./results/` is gitignored. Repeat the scan against `--mode hardened` to see the same checks come back negative. A captured vulnerable-fixture report is in `docs/sample-report.md`. Docker is optional; see `lab/README.md`.

## Commands

```text
scopeguard config validate --config scope.yaml
scopeguard scan --config scope.yaml --output ./results
scopeguard report --input ./results/assessment.json
```

Exit codes:

- `0` — the command completed
- `1` — an unexpected failure aborted the command
- `2` — the configuration or invocation is invalid
- `4` — `--fail-on confirmed` was set and a confirmed finding was recorded

Per-target network errors are recorded in the report. They do not by themselves fail the command.

## What a result means

Confirmed findings are limited to the two validation checks:

- Open redirect: one configured parameter, one `.invalid` canary, redirects not followed. Confirmed only when a redirect `Location` matches that canary. Rated low.
- Debug exposure: one explicit endpoint and one `SG_` marker. Confirmed only on HTTP 2xx plus that marker. Rated medium.

Missing security headers and server banners are observations. They are not vulnerabilities. Negative and inconclusive results stay in their own report sections.

## Development

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

Tests bind to loopback or use fakes. They do not contact public hosts.

## Limitations

See `docs/security-model.md`. Every JSON report repeats the same limitation statements. Destination pinning is an application control, not a firewall.
