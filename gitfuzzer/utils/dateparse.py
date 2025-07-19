"""
Date parsing utilities for GitHub API
"""
from datetime import datetime


def format_github_date(dt: datetime) -> str:
    """Format datetime for GitHub API queries."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_github_date(date_str: str) -> datetime:
    """Parse GitHub API date string."""
    return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
