"""
Rate limiting utilities
"""
import asyncio
import time


_last_request = 0
_min_interval = 0.1  # 100ms between requests


async def rate_limit():
    """Ensure minimum interval between API requests."""
    global _last_request
    
    now = time.time()
    elapsed = now - _last_request
    
    if elapsed < _min_interval:
        await asyncio.sleep(_min_interval - elapsed)
    
    _last_request = time.time()
