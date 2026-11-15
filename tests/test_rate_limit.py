"""Rate limiter spacing."""

from scopeguard.rate_limit import RateLimiter


def test_second_wait_sleeps_for_the_interval() -> None:
    slept: list[float] = []
    now = {"t": 0.0}

    def sleep(delay: float) -> None:
        slept.append(delay)
        now["t"] += delay

    def monotonic() -> float:
        return now["t"]

    limiter = RateLimiter(2, sleep=sleep, monotonic=monotonic)
    limiter.wait()
    limiter.wait()
    assert slept == [0.5]
