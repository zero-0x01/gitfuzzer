"""
GitFuzzer Configuration Management
"""
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List

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
