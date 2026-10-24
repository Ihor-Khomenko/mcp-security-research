"""Shared request budget for quota-friendly multi-call runs."""

from __future__ import annotations

import time
from typing import Optional

from providers.config import RateLimitParams, load_rate_limit_params
from providers.openai_compat import MaxRequestsExceeded


class RateLimitedSession:
    """Tracks request count and inter-request delay across LLMProvider calls."""

    def __init__(self, params: Optional[RateLimitParams] = None) -> None:
        self.params = params or load_rate_limit_params()
        self.requests = 0
        self._made_request = False

    def before_request(self) -> None:
        if (
            self.params.max_requests is not None
            and self.requests >= self.params.max_requests
        ):
            raise MaxRequestsExceeded(
                f"Reached max_requests={self.params.max_requests}. "
                "Stop or resume later (OpenRouter free tier is ~50 req/day)."
            )
        if self.params.delay > 0 and self._made_request:
            time.sleep(self.params.delay)

    def after_request(self) -> None:
        self.requests += 1
        self._made_request = True

    @property
    def remaining(self) -> Optional[int]:
        if self.params.max_requests is None:
            return None
        return max(0, self.params.max_requests - self.requests)
