"""Sliding-window rate limiter — server.py:236 _rate_check().

The limiter is a per-key deque of timestamps. Keys are tuples of
(endpoint, window_tag, ip) so different endpoints + different IPs
maintain independent buckets. These tests exercise boundaries and
isolation without spinning up the HTTP layer.
"""
from __future__ import annotations

import time

import pytest

import server


@pytest.fixture(autouse=True)
def _reset_buckets():
    """Each test gets a clean _RATE_BUCKETS dict. Other tests in this
    module (and any other module) won't leak state."""
    with server._RATE_LOCK:
        server._RATE_BUCKETS.clear()
    yield
    with server._RATE_LOCK:
        server._RATE_BUCKETS.clear()


def test_under_limit_returns_true():
    key = ("/test", "ip-min", "1.1.1.1")
    assert server._rate_check(key, 60, 3) is True
    assert server._rate_check(key, 60, 3) is True
    assert server._rate_check(key, 60, 3) is True


def test_at_limit_rejects_next_call():
    key = ("/test", "ip-min", "1.1.1.1")
    for _ in range(3):
        assert server._rate_check(key, 60, 3) is True
    # 4th call in the window must be refused.
    assert server._rate_check(key, 60, 3) is False


def test_different_ips_isolated():
    """Two IPs hitting the same endpoint should not share a bucket."""
    ip_a = ("/test", "ip-min", "1.1.1.1")
    ip_b = ("/test", "ip-min", "2.2.2.2")
    for _ in range(3):
        assert server._rate_check(ip_a, 60, 3) is True
    # ip_a is at cap; ip_b must still have headroom.
    assert server._rate_check(ip_a, 60, 3) is False
    assert server._rate_check(ip_b, 60, 3) is True


def test_different_endpoints_isolated():
    """Same IP on two endpoints should not share a bucket."""
    a = ("/v1/sign", "ip-min", "1.1.1.1")
    b = ("/v1/verify", "ip-min", "1.1.1.1")
    for _ in range(3):
        assert server._rate_check(a, 60, 3) is True
    assert server._rate_check(a, 60, 3) is False
    assert server._rate_check(b, 60, 3) is True  # separate bucket


def test_sliding_window_expiry():
    """Timestamps older than the window must be evicted, freeing slots."""
    key = ("/test", "ip-min", "1.1.1.1")
    # Window = 1 second, limit = 2.
    assert server._rate_check(key, 1, 2) is True
    assert server._rate_check(key, 1, 2) is True
    assert server._rate_check(key, 1, 2) is False  # over
    time.sleep(1.1)  # wait past the window
    assert server._rate_check(key, 1, 2) is True  # slot re-opened


def test_match_rate_endpoint_prefix():
    """Longer prefixes beat shorter ones in endpoint matching. Confirms
    /v1/sign/batch routes to its own limit (10/min) rather than falling
    through to /v1/sign (100/min)."""
    assert server._match_rate_endpoint("/v1/sign") == "/v1/sign"
    assert server._match_rate_endpoint("/v1/sign/batch") == "/v1/sign/batch"
    assert server._match_rate_endpoint("/v1/verify/prompt") == "/v1/verify/prompt"
    assert server._match_rate_endpoint("/v1/public-key") is None  # not rate-limited


def test_match_rate_endpoint_does_not_match_partial_prefix():
    """Prefix matching must require a full segment boundary. /v1/signup
    must not fall under the /v1/sign limit."""
    assert server._match_rate_endpoint("/v1/signup") is None
