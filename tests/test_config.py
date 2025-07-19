"""Tests for configuration module."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from gitfuzzer.config import Config, load_config
from gitfuzzer.utils import ConfigError


class TestConfig:
    """Test configuration loading and validation."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        
        assert config.keyword.count == 5
        assert config.scanner.per_page == 100
        assert config.analyzer.min_stars == 1
        assert config.telegram.enable is True
        assert config.slack.enable is False
    
    def test_config_with_data(self, config_data):
        """Test configuration with custom data."""
        config = Config(**config_data)
        
        assert config.keyword.count == 5
        assert config.scanner.max_concurrency == 8
        assert config.analyzer.require_ci is True
    
    def test_environment_variables(self):
        """Test environment variable parsing."""
        os.environ["GH_TOKENS"] = "token1,token2,token3"
        os.environ["TG_BOT_TOKEN"] = "bot_token"
        os.environ["LOG_LEVEL"] = "DEBUG"
        
        try:
            config = Config()
            
            assert len(config.gh_tokens) == 3
            assert config.gh_tokens == ["token1", "token2", "token3"]
            assert config.tg_bot_token == "bot_token"
            assert config.log_level == "DEBUG"
        finally:
            # Cleanup
            for key in ["GH_TOKENS", "TG_BOT_TOKEN", "LOG_LEVEL"]:
                if key in os.environ:
                    del os.environ[key]
    
    def test_token_parsing(self):
        """Test GitHub token parsing."""
        # Test string input
        config = Config(gh_tokens="token1,token2, token3 ")
        assert config.gh_tokens == ["token1", "token2", "token3"]
        
        # Test list input
        config = Config(gh_tokens=["token1", "token2"])
        assert config.gh_tokens == ["token1", "token2"]
        
        # Test empty input
        config = Config(gh_tokens="")
        assert config.gh_tokens == []
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Valid ranges
        config = Config()
        config.keyword.count = 10
        config.scanner.max_concurrency = 5
        config.analyzer.min_stars = 0
        
        # Invalid ranges should raise validation errors
        with pytest.raises(ValueError):
            Config(keyword={"count": 0})  # Below minimum
        
        with pytest.raises(ValueError):
            Config(scanner={"max_concurrency": 0})  # Below minimum


class TestLoadConfig:
    """Test configuration file loading."""
    
    def test_load_config_from_file(self, config_data, temp_dir):
        """Test loading configuration from YAML file."""
        config_file = temp_dir / "test_config.yml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        config = load_config(str(config_file))
        
        assert config.keyword.count == 5
        assert config.scanner.max_concurrency == 8
        assert config.analyzer.require_ci is True
    
    def test_load_config_file_not_found(self):
        """Test loading non-existent config file."""
        with pytest.raises(FileNotFoundError):
            load_config("non_existent_file.yml")
    
    def test_load_config_invalid_yaml(self, temp_dir):
        """Test loading invalid YAML file."""
        config_file = temp_dir / "invalid.yml"
        with open(config_file, 'w') as f:
            f.write("invalid: yaml: content: [")
        
        with pytest.raises(ValueError):
            load_config(str(config_file))
    
    def test_load_config_default_files(self, config_data, temp_dir):
        """Test loading from default config files."""
        # Change to temp directory
        old_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            # Create default config file
            with open("config.yml", 'w') as f:
                yaml.dump(config_data, f)
            
            config = load_config()  # No path specified
            
            assert config.keyword.count == 5
            assert config.scanner.max_concurrency == 8
        finally:
            os.chdir(old_cwd)
    
    def test_load_config_no_file(self):
        """Test loading config when no file exists."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            old_cwd = os.getcwd()
            os.chdir(tmp_dir)
            
            try:
                config = load_config()  # Should load defaults
                assert config.keyword.count == 5
            finally:
                os.chdir(old_cwd)
    
    def test_environment_override(self, config_data, temp_dir):
        """Test environment variables override config file."""
        config_file = temp_dir / "test_config.yml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        os.environ["LOG_LEVEL"] = "ERROR"
        os.environ["DISABLE_TELEMETRY"] = "true"
        
        try:
            config = load_config(str(config_file))
            
            # Environment should override config
            assert config.log_level == "ERROR"
            assert config.disable_telemetry is True
        finally:
            for key in ["LOG_LEVEL", "DISABLE_TELEMETRY"]:
                if key in os.environ:
                    del os.environ[key]


class TestConfigSections:
    """Test individual configuration sections."""
    
    def test_keyword_config(self):
        """Test keyword configuration section."""
        config = Config(keyword={
            "count": 10,
            "timeout": 60.0,
            "fallback_keywords": ["test1", "test2"]
        })
        
        assert config.keyword.count == 10
        assert config.keyword.timeout == 60.0
        assert config.keyword.fallback_keywords == ["test1", "test2"]
    
    def test_scanner_config(self):
        """Test scanner configuration section."""
        config = Config(scanner={
            "per_page": 50,
            "max_concurrency": 10,
            "max_results": 5000
        })
        
        assert config.scanner.per_page == 50
        assert config.scanner.max_concurrency == 10
        assert config.scanner.max_results == 5000
    
    def test_analyzer_config(self):
        """Test analyzer configuration section."""
        config = Config(analyzer={
            "min_stars": 5,
            "max_age_days": 180,
            "require_ci": False,
            "ci_files": [".github/workflows", "Jenkinsfile"]
        })
        
        assert config.analyzer.min_stars == 5
        assert config.analyzer.max_age_days == 180
        assert config.analyzer.require_ci is False
        assert ".github/workflows" in config.analyzer.ci_files
    
    def test_deep_linker_config(self):
        """Test deep linker configuration section."""
        config = Config(deep_linker={
            "enable": False,
            "timeout": 15.0,
            "max_redirects": 3
        })
        
        assert config.deep_linker.enable is False
        assert config.deep_linker.timeout == 15.0
        assert config.deep_linker.max_redirects == 3
    
    def test_telegram_config(self):
        """Test Telegram configuration section."""
        config = Config(telegram={
            "enable": False,
            "markdown": False,
            "parse_mode": "HTML",
            "max_message_length": 2048
        })
        
        assert config.telegram.enable is False
        assert config.telegram.markdown is False
        assert config.telegram.parse_mode == "HTML"
        assert config.telegram.max_message_length == 2048
    
    def test_rate_limit_config(self):
        """Test rate limit configuration section."""
        config = Config(rate_limit={
            "base_delay": 2.0,
            "max_delay": 600.0,
            "backoff_multiplier": 3.0,
            "max_retries": 10
        })
        
        assert config.rate_limit.base_delay == 2.0
        assert config.rate_limit.max_delay == 600.0
        assert config.rate_limit.backoff_multiplier == 3.0
        assert config.rate_limit.max_retries == 10
    
    def test_logging_config(self):
        """Test logging configuration section."""
        config = Config(logging={
            "level": "DEBUG",
            "file_path": "/tmp/test.log",
            "json_logs": False
        })
        
        assert config.logging.level == "DEBUG"
        assert config.logging.file_path == "/tmp/test.log"
        assert config.logging.json_logs is False


class TestConfigValidation:
    """Test configuration validation rules."""
    
    def test_invalid_log_level(self):
        """Test invalid log level validation."""
        with pytest.raises(ValueError):
            Config(logging={"level": "INVALID"})
    
    def test_negative_values(self):
        """Test negative value validation."""
        with pytest.raises(ValueError):
            Config(keyword={"count": -1})
        
        with pytest.raises(ValueError):
            Config(scanner={"max_concurrency": -1})
        
        with pytest.raises(ValueError):
            Config(analyzer={"min_stars": -1})
    
    def test_timeout_limits(self):
        """Test timeout limit validation."""
        with pytest.raises(ValueError):
            Config(keyword={"timeout": 0.5})  # Below minimum
        
        with pytest.raises(ValueError):
            Config(scanner={"timeout": 500.0})  # Above maximum
    
    def test_percentage_limits(self):
        """Test percentage value limits."""
        with pytest.raises(ValueError):
            Config(rate_limit={"jitter_ratio": 1.5})  # Above 1.0
        
        with pytest.raises(ValueError):
            Config(rate_limit={"jitter_ratio": -0.1})  # Below 0.0
