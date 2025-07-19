"""Rate limiting and backoff utilities for GitFuzzer."""

import asyncio
import logging
import random
import time
from typing import Dict, Optional


class RateLimitError(Exception):
    """Raised when rate limits are exceeded."""
    pass

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter with token bucket algorithm and backoff strategies."""
    
    def __init__(
        self,
        base_delay: float = 1.0,
        max_delay: float = 300.0,
        backoff_multiplier: float = 2.0,
        jitter_ratio: float = 0.1,
        max_retries: int = 5
    ):
        """Initialize rate limiter.
        
        Args:
            base_delay: Base delay between requests in seconds.
            max_delay: Maximum delay allowed in seconds.
            backoff_multiplier: Multiplier for exponential backoff.
            jitter_ratio: Ratio of jitter to add to delays.
            max_retries: Maximum number of retries for rate limited requests.
        """
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_multiplier = backoff_multiplier
        self.jitter_ratio = jitter_ratio
        self.max_retries = max_retries
        
        # Track rate limit state per token/endpoint
        self._rate_limits: Dict[str, Dict[str, any]] = {}
        self._last_request_time: Dict[str, float] = {}
        
    def _generate_jitter(self, delay: float) -> float:
        """Generate decorrelated jitter for delay.
        
        Args:
            delay: Base delay value.
            
        Returns:
            Jittered delay value.
        """
        jitter_amount = delay * self.jitter_ratio
        return delay + (random.random() * 2 - 1) * jitter_amount
    
    def _calculate_backoff_delay(self, attempt: int) -> float:
        """Calculate exponential backoff delay.
        
        Args:
            attempt: Current attempt number (0-based).
            
        Returns:
            Calculated delay in seconds.
        """
        delay = self.base_delay * (self.backoff_multiplier ** attempt)
        delay = min(delay, self.max_delay)
        return self._generate_jitter(delay)
    
    def update_rate_limit_info(
        self,
        token_id: str,
        remaining: Optional[int] = None,
        limit: Optional[int] = None,
        reset_time: Optional[int] = None,
        retry_after: Optional[int] = None
    ) -> None:
        """Update rate limit information from API response headers.
        
        Args:
            token_id: Identifier for the token/endpoint.
            remaining: Number of requests remaining.
            limit: Total rate limit.
            reset_time: Unix timestamp when rate limit resets.
            retry_after: Seconds to wait before next request.
        """
        current_time = time.time()
        
        self._rate_limits[token_id] = {
            "remaining": remaining,
            "limit": limit,
            "reset_time": reset_time,
            "retry_after": retry_after,
            "last_updated": current_time
        }
        
        logger.debug(
            f"Updated rate limit for {token_id}: "
            f"remaining={remaining}, limit={limit}, reset_time={reset_time}"
        )
    
    def get_delay_until_reset(self, token_id: str) -> float:
        """Get delay until rate limit resets.
        
        Args:
            token_id: Identifier for the token/endpoint.
            
        Returns:
            Delay in seconds until rate limit resets.
        """
        if token_id not in self._rate_limits:
            return 0.0
        
        rate_limit_info = self._rate_limits[token_id]
        reset_time = rate_limit_info.get("reset_time")
        
        if reset_time is None:
            return 0.0
        
        current_time = time.time()
        delay = max(0, reset_time - current_time)
        
        return delay
    
    def should_wait_for_rate_limit(self, token_id: str) -> bool:
        """Check if we should wait due to rate limit.
        
        Args:
            token_id: Identifier for the token/endpoint.
            
        Returns:
            True if we should wait, False otherwise.
        """
        if token_id not in self._rate_limits:
            return False
        
        rate_limit_info = self._rate_limits[token_id]
        remaining = rate_limit_info.get("remaining")
        
        # If we have remaining requests, no need to wait
        if remaining is not None and remaining > 0:
            return False
        
        # If we're out of requests, check if reset time has passed
        reset_time = rate_limit_info.get("reset_time")
        if reset_time is not None:
            current_time = time.time()
            return current_time < reset_time
        
        return False
    
    async def wait_for_rate_limit(self, token_id: str) -> None:
        """Wait for rate limit to reset.
        
        Args:
            token_id: Identifier for the token/endpoint.
        """
        delay = self.get_delay_until_reset(token_id)
        
        if delay > 0:
            logger.info(f"Rate limit hit for {token_id}. Waiting {delay:.1f}s")
            await asyncio.sleep(delay)
            
            # Clear the rate limit info after waiting
            if token_id in self._rate_limits:
                del self._rate_limits[token_id]
    
    async def acquire(self, token_id: str) -> None:
        """Acquire permission to make a request.
        
        Args:
            token_id: Identifier for the token/endpoint.
        """
        # Check if we need to wait for rate limit reset
        if self.should_wait_for_rate_limit(token_id):
            await self.wait_for_rate_limit(token_id)
        
        # Ensure minimum delay between requests
        current_time = time.time()
        last_request = self._last_request_time.get(token_id, 0)
        time_since_last = current_time - last_request
        
        if time_since_last < self.base_delay:
            delay = self.base_delay - time_since_last
            await asyncio.sleep(delay)
        
        self._last_request_time[token_id] = time.time()
    
    async def handle_rate_limit_error(
        self,
        token_id: str,
        attempt: int,
        error: Exception,
        retry_after: Optional[float] = None
    ) -> None:
        """Handle rate limit error with backoff.
        
        Args:
            token_id: Identifier for the token/endpoint.
            attempt: Current attempt number (0-based).
            error: The rate limit error.
            retry_after: Seconds to wait as specified by API.
            
        Raises:
            RateLimitError: If max retries exceeded.
        """
        if attempt >= self.max_retries:
            raise RateLimitError(
                f"Max retries ({self.max_retries}) exceeded for {token_id}",
                retry_after=retry_after
            )
        
        # Use API-specified retry_after if available, otherwise use backoff
        if retry_after is not None:
            delay = retry_after
        else:
            delay = self._calculate_backoff_delay(attempt)
        
        logger.warning(
            f"Rate limit error for {token_id} (attempt {attempt + 1}). "
            f"Backing off for {delay:.2f}s: {error}"
        )
        
        await asyncio.sleep(delay)


class TokenRotator:
    """Rotates through multiple API tokens to distribute load."""
    
    def __init__(self, tokens: list[str], rate_limiter: Optional[RateLimiter] = None):
        """Initialize token rotator.
        
        Args:
            tokens: List of API tokens to rotate through.
            rate_limiter: Rate limiter instance to use.
        """
        if not tokens:
            raise ValueError("At least one token must be provided")
        
        self.tokens = tokens
        self.current_index = 0
        self.rate_limiter = rate_limiter or RateLimiter()
        
        # Track token health (failed requests, etc.)
        self._token_health = {token: {"failures": 0, "last_failure": 0} for token in tokens}
        
        logger.info(f"Initialized token rotator with {len(tokens)} tokens")
    
    def get_current_token(self) -> str:
        """Get the current token.
        
        Returns:
            Current API token.
        """
        return self.tokens[self.current_index]
    
    def get_healthy_token(self) -> str:
        """Get a healthy token, skipping problematic ones.
        
        Returns:
            A healthy API token.
        """
        current_time = time.time()
        
        # Try to find a token that hasn't failed recently
        for _ in range(len(self.tokens)):
            token = self.get_current_token()
            health = self._token_health[token]
            
            # Consider token healthy if it hasn't failed in the last 5 minutes
            if health["failures"] == 0 or (current_time - health["last_failure"]) > 300:
                return token
            
            self.rotate()
        
        # If all tokens are problematic, use the current one anyway
        logger.warning("All tokens appear problematic, using current token anyway")
        return self.get_current_token()
    
    def rotate(self) -> str:
        """Rotate to the next token.
        
        Returns:
            Next API token.
        """
        self.current_index = (self.current_index + 1) % len(self.tokens)
        token = self.get_current_token()
        
        logger.debug(f"Rotated to token index {self.current_index}")
        return token
    
    def mark_token_failure(self, token: str, error: Exception) -> None:
        """Mark a token as having failed.
        
        Args:
            token: Token that failed.
            error: Error that occurred.
        """
        if token in self._token_health:
            self._token_health[token]["failures"] += 1
            self._token_health[token]["last_failure"] = time.time()
            
            logger.warning(f"Marked token failure: {error}")
    
    def mark_token_success(self, token: str) -> None:
        """Mark a token as having succeeded.
        
        Args:
            token: Token that succeeded.
        """
        if token in self._token_health:
            self._token_health[token]["failures"] = 0
    
    async def acquire_token(self) -> tuple[str, str]:
        """Acquire a token for making requests.
        
        Returns:
            Tuple of (token, token_id) ready for use.
        """
        token = self.get_healthy_token()
        token_id = f"token_{self.tokens.index(token)}"
        
        if self.rate_limiter:
            await self.rate_limiter.acquire(token_id)
        
        return token, token_id
    
    def update_rate_limit_from_headers(self, token: str, headers: dict) -> None:
        """Update rate limit information from response headers.
        
        Args:
            token: Token that was used.
            headers: Response headers from API.
        """
        if not self.rate_limiter:
            return
        
        token_id = f"token_{self.tokens.index(token)}"
        
        # Parse GitHub API rate limit headers
        remaining = headers.get("x-ratelimit-remaining")
        limit = headers.get("x-ratelimit-limit")
        reset_time = headers.get("x-ratelimit-reset")
        retry_after = headers.get("retry-after")
        
        # Convert string values to integers where appropriate
        try:
            remaining = int(remaining) if remaining else None
            limit = int(limit) if limit else None
            reset_time = int(reset_time) if reset_time else None
            retry_after = int(retry_after) if retry_after else None
        except (ValueError, TypeError):
            logger.warning("Failed to parse rate limit headers")
            return
        
        self.rate_limiter.update_rate_limit_info(
            token_id=token_id,
            remaining=remaining,
            limit=limit,
            reset_time=reset_time,
            retry_after=retry_after
        )


async def with_rate_limit_retry(
    func,
    token_rotator: TokenRotator,
    *args,
    max_retries: int = 5,
    **kwargs
) -> any:
    """Execute function with rate limit retry logic.
    
    Args:
        func: Async function to execute.
        token_rotator: Token rotator to use.
        *args: Positional arguments for function.
        max_retries: Maximum number of retries.
        **kwargs: Keyword arguments for function.
        
    Returns:
        Function result on success.
        
    Raises:
        RateLimitError: If max retries exceeded.
        Exception: Last exception if all retries fail.
    """
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            token, token_id = await token_rotator.acquire_token()
            result = await func(token, *args, **kwargs)
            
            # Mark token as successful
            token_rotator.mark_token_success(token)
            return result
            
        except RateLimitError as e:
            last_exception = e
            
            # Mark token failure and rotate
            current_token = token_rotator.get_current_token()
            token_rotator.mark_token_failure(current_token, e)
            token_rotator.rotate()
            
            if attempt < max_retries - 1:
                await token_rotator.rate_limiter.handle_rate_limit_error(
                    token_id, attempt, e, e.retry_after
                )
            
        except Exception as e:
            last_exception = e
            
            # For non-rate-limit errors, mark failure but don't rotate immediately
            current_token = token_rotator.get_current_token()
            token_rotator.mark_token_failure(current_token, e)
            
            # Only retry rate-limit related errors
            if "rate limit" in str(e).lower() or getattr(e, 'status_code', None) == 429:
                if attempt < max_retries - 1:
                    token_rotator.rotate()
                    continue
            
            # For other errors, re-raise immediately
            raise e
    
    raise last_exception
