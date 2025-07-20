"""
GitFuzzer Configuration Management
"""
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Any, Dict

import yaml

# Load .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass
class ScannerConfig:
    """Scanner configuration for GitHubScanner compatibility."""
    timeout: int = 30
    per_page: int = 100
    retry_attempts: int = 3
    max_results: int = 100
    slice_days: int = 7
    max_concurrency: int = 5
    max_age_days: int = 30


@dataclass 
class AnalyzerConfig:
    """Analyzer configuration for GitHubScanner compatibility."""
    max_age_days: int = 30
    pass


@dataclass
class KeywordConfig:
    """Keyword generation settings."""

    count: int = 5
    hf_endpoint: str = ""
    timeout: float = 30.0
    fallback_keywords: List[str] = field(default_factory=list)


@dataclass
class TelegramConfig:
    """Telegram integration settings."""

    enable: bool = True
    markdown: bool = True
    parse_mode: str = "Markdown"
    max_message_length: int = 4096
    bot_token: str = ""
    chat_id: str = ""


@dataclass
class SlackConfig:
    """Slack integration settings."""

    enable: bool = False


@dataclass
class DeepLinkerConfig:
    """Deep link resolution settings."""

    enable: bool = True
    timeout: float = 10.0
    max_redirects: int = 5
    user_agent: str = "GitFuzzer/1.0"


@dataclass
class RateLimitConfig:
    """Rate limiting and retry configuration."""

    base_delay: float = 1.0
    max_delay: float = 300.0
    backoff_multiplier: float = 2.0
    max_retries: int = 3
    jitter_ratio: float = 0.1


@dataclass
class LoggingConfig:
    """Logging configuration."""

    level: str = "INFO"
    file_path: str = "logs/gitfuzzer_{date}.log"
    format: str = "%(asctime)s - %(levelname)s - %(message)s"
    json_logs: bool = True


@dataclass
class Settings:
    """GitFuzzer configuration settings."""
    
    # Core settings
    keywords: int = 5
    days: int = 30
    analysis_count: int = 20
    
    # Enhanced features
    language_filter: Optional[str] = None
    must_have_relationships: bool = False
    telegram_enabled: bool = False
    
    # New scanning features
    specific_repo: Optional[str] = None
    extended_files: bool = False
    whole_code: bool = False
    code_search: bool = False
    in_one_message: bool = False
    created_after: Optional[str] = None
    pushed_after: Optional[str] = None
    
    # Optional filters
    include_file: str = ""  # File that must exist in repo (e.g., ".env", "package.json")
    include_keyword: str = ""  # Keyword that must exist in repo content
    
    # API tokens
    github_token: str = ""
    github_tokens: List[str] = None
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    hf_token: str = ""
    shodan_api_key: str = ""
    
    def __post_init__(self):
        """Handle default values that need initialization."""
        if self.github_tokens is None:
            self.github_tokens = []
    
    @property
    def gh_tokens(self) -> List[str]:
        """Compatibility property for GitHubScanner."""
        return self.github_tokens
    
    @property 
    def scanner(self) -> ScannerConfig:
        """Scanner configuration for GitHubScanner compatibility."""
        return ScannerConfig(max_age_days=self.days)
    
    @property
    def analyzer(self) -> AnalyzerConfig:
        """Analyzer configuration for GitHubScanner compatibility."""
        return AnalyzerConfig(max_age_days=self.days)
    
    @classmethod
    def load(cls, config_path: Optional[str] = None) -> 'Settings':
        """Load settings from file and environment variables."""
        settings = {}
        
        # Load from YAML file if provided
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                settings.update(yaml.safe_load(f) or {})
        elif Path('config.yml').exists():
            with open('config.yml', 'r') as f:
                settings.update(yaml.safe_load(f) or {})
        
        # Override with environment variables
        env_mappings = {
            'GH_TOKEN': 'github_token',
            'TELEGRAM_BOT_TOKEN': 'telegram_bot_token',
            'TELEGRAM_CHAT_ID': 'telegram_chat_id',
            'HF_TOKEN': 'hf_token',
            'SHODAN_API_KEY': 'shodan_api_key'
        }
        
        for env_var, setting_key in env_mappings.items():
            if os.getenv(env_var):
                settings[setting_key] = os.getenv(env_var)
        
        # Handle github_tokens list
        if 'github' in settings and 'tokens' in settings['github']:
            settings['github_tokens'] = settings['github']['tokens']
        elif settings.get('github_token'):
            settings['github_tokens'] = [settings['github_token']]
        else:
            settings['github_tokens'] = []
        
        # Handle telegram settings
        if 'telegram' in settings:
            if 'bot_token' in settings['telegram']:
                settings['telegram_bot_token'] = settings['telegram']['bot_token']
            if 'chat_id' in settings['telegram']:
                settings['telegram_chat_id'] = settings['telegram']['chat_id']
        
        # Handle shodan settings
        if 'shodan' in settings and 'api_key' in settings['shodan']:
            settings['shodan_api_key'] = settings['shodan']['api_key']
        
        return cls(**{k: v for k, v in settings.items() if k in cls.__annotations__})


@dataclass
class Config:
    """Comprehensive configuration used by tests and utilities."""

    keyword: KeywordConfig = field(default_factory=KeywordConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    analyzer: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    deep_linker: DeepLinkerConfig = field(default_factory=DeepLinkerConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    slack: SlackConfig = field(default_factory=SlackConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    gh_tokens: List[str] = field(default_factory=list)
    tg_bot_token: str = ""
    tg_chat_id: str = ""
    log_level: str = "INFO"
    disable_telemetry: bool = False

    def __post_init__(self):
        # Convert nested dicts to dataclasses
        for field_name, cls in (
            ("keyword", KeywordConfig),
            ("scanner", ScannerConfig),
            ("analyzer", AnalyzerConfig),
            ("deep_linker", DeepLinkerConfig),
            ("telegram", TelegramConfig),
            ("slack", SlackConfig),
            ("rate_limit", RateLimitConfig),
            ("logging", LoggingConfig),
        ):
            value = getattr(self, field_name)
            if isinstance(value, dict):
                setattr(self, field_name, cls(**value))

        # Environment overrides
        env_tokens = os.getenv("GH_TOKENS")
        if env_tokens and not self.gh_tokens:
            self.gh_tokens = [t.strip() for t in env_tokens.split(',') if t.strip()]
        elif isinstance(self.gh_tokens, str):
            self.gh_tokens = [t.strip() for t in self.gh_tokens.split(',') if t.strip()]

        self.tg_bot_token = self.tg_bot_token or os.getenv("TG_BOT_TOKEN", "")
        self.tg_chat_id = self.tg_chat_id or os.getenv("TG_CHAT_ID", "")

        if os.getenv("LOG_LEVEL"):
            self.log_level = os.getenv("LOG_LEVEL")
        if os.getenv("DISABLE_TELEMETRY"):
            self.disable_telemetry = os.getenv("DISABLE_TELEMETRY").lower() == "true"

        self._validate()

    def _validate(self):
        if self.keyword.count < 1:
            raise ValueError("keyword count must be >=1")
        if self.keyword.timeout < 1.0:
            raise ValueError("keyword timeout too low")
        if not 0 < self.rate_limit.jitter_ratio <= 1:
            raise ValueError("jitter_ratio must be between 0 and 1")
        if self.scanner.max_concurrency < 1:
            raise ValueError("max_concurrency must be >=1")
        if self.analyzer.min_stars < 0:
            raise ValueError("min_stars must be >=0")
        if self.scanner.timeout > 300:
            raise ValueError("scanner timeout too high")
        valid_levels = {
            "CRITICAL",
            "ERROR",
            "WARNING",
            "INFO",
            "DEBUG",
            "NOTSET",
        }
        if self.logging.level not in valid_levels:
            raise ValueError("invalid log level")


def load_config(path: Optional[str] = None) -> Config:
    """Load configuration from YAML file or defaults."""

    data: Dict[str, Any] = {}
    if path:
        if not Path(path).exists():
            raise FileNotFoundError(path)
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ValueError("Invalid YAML") from e
    else:
        for name in ("config.yml", "config.yaml"):
            if Path(name).exists():
                with open(name, "r") as f:
                    try:
                        data = yaml.safe_load(f) or {}
                    except yaml.YAMLError as e:
                        raise ValueError("Invalid YAML") from e
                break

    return Config(**data)

