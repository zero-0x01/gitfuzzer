"""Test configuration and fixtures."""

import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import yaml

from gitfuzzer.config import Config


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


@pytest.fixture
def config_data():
    """Sample configuration data for tests."""
    return {
        "keyword": {
            "count": 5,
            "hf_endpoint": "https://api-inference.huggingface.co/models/test",
            "timeout": 30.0,
            "fallback_keywords": ["test", "example"]
        },
        "scanner": {
            "per_page": 100,
            "max_concurrency": 8,
            "timeout": 30.0
        },
        "analyzer": {
            "min_stars": 1,
            "max_age_days": 365,
            "require_ci": True
        },
        "telegram": {
            "enable": True,
            "markdown": True
        }
    }


@pytest.fixture
def test_config(config_data, temp_dir):
    """Create a test configuration."""
    # Set test environment variables
    os.environ["GH_TOKENS"] = "ghp_test_token_1,ghp_test_token_2"
    os.environ["TG_BOT_TOKEN"] = "test_bot_token"
    os.environ["TG_CHAT_ID"] = "test_chat_id"
    
    # Create config file
    config_file = temp_dir / "test_config.yml"
    with open(config_file, 'w') as f:
        yaml.dump(config_data, f)
    
    # Load config
    config = Config(**config_data)
    
    yield config
    
    # Cleanup environment variables
    for key in ["GH_TOKENS", "TG_BOT_TOKEN", "TG_CHAT_ID"]:
        if key in os.environ:
            del os.environ[key]


@pytest.fixture
def mock_session():
    """Mock aiohttp session."""
    session = AsyncMock()
    session.get = AsyncMock()
    session.post = AsyncMock()
    session.close = AsyncMock()
    return session


@pytest.fixture
def sample_repo_data():
    """Sample repository data for tests."""
    return {
        "id": 123456,
        "name": "test-repo",
        "full_name": "owner/test-repo",
        "html_url": "https://github.com/owner/test-repo",
        "description": "A test repository",
        "homepage": "https://test.example.com",
        "language": "Python",
        "stargazers_count": 100,
        "forks_count": 25,
        "size": 1024,
        "created_at": "2023-01-01T00:00:00Z",
        "updated_at": "2023-12-01T00:00:00Z",
        "pushed_at": "2023-12-01T00:00:00Z",
        "topics": ["testing", "python"],
        "license": {"name": "MIT License"},
        "default_branch": "main",
        "owner": {
            "login": "owner",
            "type": "User"
        }
    }


@pytest.fixture
def sample_repo(sample_repo_data):
    """Sample RepoInfo object."""
    from gitfuzzer.gh_scanner import RepoInfo
    return RepoInfo.parse_obj(sample_repo_data)


# Test data constants
TEST_KEYWORDS = ["test", "example", "sample"]
TEST_SUBJECT = "testing"
TEST_USER_AGENT = "GitFuzzer-Test/1.0"
