# Contributing

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) if `uv --version` fails, then open a new shell. Run the checks from a clean checkout:

```bash
uv sync --all-groups
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

New network behavior has to go through `ScopeEnforcer` and `PinnedClient`. A module that opens its own socket must apply the same address pin and the same address-class policy. Tests must not depend on a public host.

Do not add encoding-bypass catalogs to the open-redirect check. That check is intentionally one canary and one parameter. Do not search for real secrets in the debug-exposure check; markers stay in the `SG_` form.

Reports must keep confirmed findings, negative results, inconclusive checks, failed checks, and informational observations separate. Do not raise a severity to make a fixture look more serious than the evidence.
