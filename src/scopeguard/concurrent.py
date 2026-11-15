"""Ordered concurrency for a handful of authorized targets."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor


def run_concurrent[T](functions: list[Callable[[], T]], *, concurrency: int) -> list[T]:
    if concurrency < 1:
        raise ValueError("concurrency must be positive")
    if concurrency == 1 or len(functions) <= 1:
        return [fn() for fn in functions]
    workers = min(concurrency, len(functions))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(fn) for fn in functions]
        return [future.result() for future in futures]
