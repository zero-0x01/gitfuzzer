"""Common utilities for GitFuzzer utils package."""

import asyncio
import logging
import random
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import urlparse

import aiofiles
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

# Global console instance
console = Console()


class RateLimitError(Exception):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class ConfigError(Exception):
    """Raised when configuration is invalid."""
    pass


class GitHubAPIError(Exception):
    """Raised when GitHub API returns an error."""
    
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class TelegramError(Exception):
    """Raised when Telegram API returns an error."""
    
    def __init__(self, message: str, error_code: Optional[int] = None):
        super().__init__(message)
        self.error_code = error_code


def validate_url(url: str) -> bool:
    """Validate URL format.
    
    Args:
        url: URL to validate.
        
    Returns:
        True if URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL.
    
    Args:
        url: URL to extract domain from.
        
    Returns:
        Domain name or None if extraction fails.
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return None


def sanitize_keyword(keyword: str) -> str:
    """Sanitize keyword for GitHub search.
    
    Args:
        keyword: Raw keyword to sanitize.
        
    Returns:
        Sanitized keyword safe for GitHub search.
    """
    # Remove special characters and normalize whitespace
    sanitized = re.sub(r'[^\w\s-]', ' ', keyword)
    sanitized = re.sub(r'\s+', ' ', sanitized).strip()
    
    # Convert to lowercase and limit length
    sanitized = sanitized.lower()[:50]
    
    return sanitized


def escape_markdown(text: str) -> str:
    """Escape text for Telegram MarkdownV2.
    
    Args:
        text: Text to escape.
        
    Returns:
        Escaped text safe for MarkdownV2.
    """
    # Characters that need escaping in MarkdownV2
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    
    for char in escape_chars:
        text = text.replace(char, f'\\{char}')
    
    return text


def format_datetime(dt: datetime) -> str:
    """Format datetime for display.
    
    Args:
        dt: Datetime to format.
        
    Returns:
        Formatted datetime string.
    """
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


async def write_file_async(file_path: Union[str, Path], content: str) -> None:
    """Write content to file asynchronously.
    
    Args:
        file_path: Path to file to write.
        content: Content to write.
        
    Raises:
        IOError: If file can't be written.
    """
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    async with aiofiles.open(path, 'w', encoding='utf-8') as f:
        await f.write(content)


def create_progress_bar(description: str = "Processing...") -> Progress:
    """Create a rich progress bar.
    
    Args:
        description: Description to display.
        
    Returns:
        Configured progress bar instance.
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=False
    )


def is_valid_github_token(token: str) -> bool:
    """Validate GitHub token format.
    
    Args:
        token: GitHub token to validate.
        
    Returns:
        True if token format is valid.
    """
    # Classic tokens start with ghp_, fine-grained start with github_pat_
    return bool(re.match(r'^(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]+)$', token))


async def async_retry(
    func,
    *args,
    max_retries: int = 3,
    base_delay: float = 1.0,
    backoff_multiplier: float = 2.0,
    **kwargs
) -> Any:
    """Async retry wrapper with exponential backoff.
    
    Args:
        func: Async function to retry.
        *args: Positional arguments for function.
        max_retries: Maximum number of retry attempts.
        base_delay: Base delay between retries.
        backoff_multiplier: Multiplier for exponential backoff.
        **kwargs: Keyword arguments for function.
        
    Returns:
        Function result on success.
        
    Raises:
        Last exception if all retries fail.
    """
    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            last_exception = e
            
            if attempt == max_retries:
                break
                
            delay = base_delay * (backoff_multiplier ** attempt)
            jittered_delay = generate_jitter(delay)
            
            logging.getLogger(__name__).warning(
                f"Attempt {attempt + 1} failed: {e}. Retrying in {jittered_delay:.2f}s"
            )
            
            await asyncio.sleep(jittered_delay)
    
    raise last_exception


def generate_jitter(base_delay: float, jitter_ratio: float = 0.2) -> float:
    """Generate jittered delay for retry backoff.
    
    Args:
        base_delay: Base delay value.
        jitter_ratio: Ratio of jitter to add.
        
    Returns:
        Jittered delay value.
    """
    jitter = base_delay * jitter_ratio * random.random()
    return base_delay + jitter
