"""Rate Limiter — asyncio token bucket（全局 pps + 单目标 qps）。"""

import asyncio
import time
from collections import defaultdict


class GlobalRateLimiter:
    """全局包速率限制（token bucket）。"""

    def __init__(self, pps: int = 500):
        self.pps = pps
        self._tokens = float(pps)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, cost: float = 1.0):
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._tokens = min(self.pps, self._tokens + elapsed * self.pps)
                self._last = now
                if self._tokens >= cost:
                    self._tokens -= cost
                    return
                wait = (cost - self._tokens) / self.pps
            await asyncio.sleep(wait)


class PerTargetRateLimiter:
    """每目标 qps 限制（每 IP 一个 token bucket）。"""

    def __init__(self, qps: int = 10):
        self.qps = qps
        self._buckets: dict = defaultdict(lambda: float(qps))
        self._lasts: dict = defaultdict(time.monotonic)
        self._lock = asyncio.Lock()

    async def acquire(self, ip: str, cost: float = 1.0):
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._lasts[ip]
                self._buckets[ip] = min(self.qps, self._buckets[ip] + elapsed * self.qps)
                self._lasts[ip] = now
                if self._buckets[ip] >= cost:
                    self._buckets[ip] -= cost
                    return
                wait = (cost - self._buckets[ip]) / self.qps
            await asyncio.sleep(wait)
