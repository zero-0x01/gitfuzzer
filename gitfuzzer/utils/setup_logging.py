"""Setup logging utility for GitFuzzer utils package."""

import logging
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler


console = Console()


def setup_logging(config) -> logging.Logger:
    """Set up logging configuration.
    
    Args:
        config: Configuration object with logging settings.
        
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
    
    return logging.getLogger(__name__)
