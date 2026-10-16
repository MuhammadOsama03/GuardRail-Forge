from guardrail_forge.rate_limit import SlidingWindowRateLimiter


def test_limiter_blocks_after_window_capacity() -> None:
    now = [0.0]
    limiter = SlidingWindowRateLimiter(2, 60, clock=lambda: now[0])
    assert limiter.check("client").allowed is True
    assert limiter.check("client").remaining == 0
    assert limiter.check("client").allowed is False
    now[0] = 61
    assert limiter.check("client").allowed is True


def test_limiter_isolates_clients() -> None:
    limiter = SlidingWindowRateLimiter(1, clock=lambda: 0)
    assert limiter.check("one").allowed is True
    assert limiter.check("two").allowed is True
