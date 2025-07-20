"""GitFuzzer utilities module."""

import asyncio
import logging
import random
from typing import Any

# Import from utils submodules to avoid circular imports
from .common import *
from .dateparse import *


class RateLimitError(Exception):
    """Raised when rate limits are exceeded."""
    pass


class GitHubAPIError(Exception):
    """Raised when GitHub API returns an error."""
    pass


async def async_retry(
    func,
    *args,
    max_retries: int = 3,
    base_delay: float = 1.0,
    backoff_multiplier: float = 2.0,
    **kwargs
) -> Any:
    """Async retry wrapper with exponential backoff."""
    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            last_exception = e

            if attempt == max_retries:
                break

            delay = base_delay * (backoff_multiplier ** attempt)
            jittered_delay = delay + (delay * 0.1 * random.random())

            await asyncio.sleep(jittered_delay)

    raise last_exception
