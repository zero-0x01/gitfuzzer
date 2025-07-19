"""Utility functions and shared helpers for GitFuzzer."""

import asyncio
import json
import logging
import random
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import aiofiles
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from gitfuzzer.config import Settings as Config

# Global console instance
console = Console()


def setup_logging(config: Config) -> logging.Logger:
    """Set up logging configuration.
    
    Args:
        config: Configuration object.
        
    Returns:
        Configured logger instance.
    """
    # Create logs directory
    log_path = Path(config.logging.file_path.format(
        date=datetime.now().strftime("%Y%m%d")
    ))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, config.logging.level),
        format=config.logging.format,
        handlers=[
            RichHandler(
                console=console,
                rich_tracebacks=True,
                show_path=False,
                show_time=False
            )
        ]
    )
    
    # Create file handler for JSON logs if enabled
    if config.logging.json_logs:
        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setFormatter(JSONFormatter())
        file_handler.setLevel(getattr(logging, config.logging.level))
        logging.getLogger().addHandler(file_handler)
    
    return logging.getLogger(__name__)


class JSONFormatter(logging.Formatter):
    """JSON log formatter."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON.
        
        Args:
            record: Log record to format.
            
        Returns:
            JSON-formatted log string.
        """
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, ensure_ascii=False)


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


def format_datetime(dt: datetime) -> str:
    """Format datetime for display.
    
    Args:
        dt: Datetime to format.
        
    Returns:
        Formatted datetime string.
    """
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text to maximum length.
    
    Args:
        text: Text to truncate.
        max_length: Maximum length allowed.
        
    Returns:
        Truncated text with ellipsis if needed.
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def generate_jitter(base_delay: float, jitter_ratio: float = 0.1) -> float:
    """Generate jittered delay for rate limiting.
    
    Args:
        base_delay: Base delay in seconds.
        jitter_ratio: Ratio of jitter to add.
        
    Returns:
        Jittered delay value.
    """
    jitter = base_delay * jitter_ratio * random.random()
    return base_delay + jitter


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


async def read_file_async(file_path: Union[str, Path]) -> str:
    """Read file contents asynchronously.
    
    Args:
        file_path: Path to file to read.
        
    Returns:
        File contents as string.
        
    Raises:
        FileNotFoundError: If file doesn't exist.
        IOError: If file can't be read.
    """
    async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
        return await f.read()


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


def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split list into chunks of specified size.
    
    Args:
        lst: List to chunk.
        chunk_size: Size of each chunk.
        
    Returns:
        List of chunks.
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge two dictionaries.
    
    Args:
        dict1: First dictionary.
        dict2: Second dictionary (takes precedence).
        
    Returns:
        Merged dictionary.
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result


def get_file_hash(file_path: Union[str, Path]) -> str:
    """Get SHA-256 hash of file contents.
    
    Args:
        file_path: Path to file.
        
    Returns:
        Hexadecimal hash string.
    """
    import hashlib
    
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    
    return sha256_hash.hexdigest()


def is_valid_github_token(token: str) -> bool:
    """Validate GitHub token format.
    
    Args:
        token: GitHub token to validate.
        
    Returns:
        True if token format is valid.
    """
    # Classic tokens start with ghp_, fine-grained start with github_pat_
    return bool(re.match(r'^(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]+)$', token))


def safe_filename(filename: str) -> str:
    """Create safe filename by removing invalid characters.
    
    Args:
        filename: Original filename.
        
    Returns:
        Safe filename for filesystem.
    """
    # Remove invalid characters
    safe = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove control characters
    safe = re.sub(r'[\x00-\x1f\x7f]', '', safe)
    
    # Limit length and strip whitespace
    safe = safe.strip()[:255]
    
    return safe or "unnamed"


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
