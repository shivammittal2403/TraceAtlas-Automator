"""Process-wide request ceilings; provider replies remain authoritative."""
from collections import defaultdict, deque
import threading
import time

# Documented conservative ceilings checked 2026-10-03. These do not claim to
# coordinate other processes/accounts or replace a provider's remaining quota.
QUOTAS = {'sec': ((10, 1),), 'companieshouse': ((600, 300),),
          'github': ((60, 3600),), 'virustotal': ((4, 60), (500, 86400))}


class SourceRateLimiter:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        self.history = defaultdict(deque)

    def reserve(self, provider, source):
        # The general 32/s cap is a local safety ceiling, not a provider quota.
        rules = QUOTAS.get(source, ((32, 1),))
        with self.lock:
            now = self.clock()
            samples = self.history[provider]
            while samples and samples[0] <= now - max(window for _, window in rules):
                samples.popleft()
            if any(sum(t > now - window for t in samples) >= limit for limit, window in rules):
                return False
            samples.append(now)
            return True


REQUEST_LIMITER = SourceRateLimiter()
