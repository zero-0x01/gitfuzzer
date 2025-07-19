"""
Enhanced GitFuzzer Repository Analyzer - Comprehensive security scanning
"""
import asyncio
import base64
import logging
import math
import re
from dataclasses import dataclass
from typing import List, Set, Dict, Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    has_secrets: bool = False
    secrets_found: List[str] = None
    related_urls: List[str] = None
    readme_content: str = ""
    risk_score: int = 0
    secret_types: List[str] = None
    
    def __post_init__(self):
        if self.secrets_found is None:
            self.secrets_found = []
        if self.related_urls is None:
            self.related_urls = []
        if self.secret_types is None:
            self.secret_types = []


async def analyze_repository(repo, token: str, scan_mode: str = "standard") -> AnalysisResult:
    """Comprehensive repository analysis with enhanced secret detection.
    
    Args:
        repo: Repository object with full_name and other attributes
        token: GitHub API token
        scan_mode: "standard" (3 files) or "extended" (many files) or "whole" (all files)
    """
    
    result = AnalysisResult()
    
    try:
        if scan_mode == "whole":
            # Scan entire repository code
            all_content = await _fetch_whole_repository(repo.full_name, token)
        elif scan_mode == "extended":
            # Scan extended file list
            all_content = await _fetch_extended_files(repo.full_name, token)
        else:
            # Standard scan (original 3 files)
            readme_content = await _fetch_readme(repo.full_name, token)
            env_content = await _fetch_file(repo.full_name, ".env", token)
            config_content = await _fetch_file(repo.full_name, "config.json", token)
            all_content = f"{readme_content}\n{env_content}\n{config_content}\n{repo.description or ''}"
        
        result.readme_content = all_content[:1000] if len(all_content) > 1000 else all_content
        
        # Enhanced secret detection
        secrets_result = scan_secrets_enhanced(all_content, repo.full_name)
        result.secrets_found = secrets_result["secrets"]
        result.secret_types = secrets_result["types"]
        result.has_secrets = len(result.secrets_found) > 0
        
        # Extract URLs and endpoints
        result.related_urls = list(_extract_urls_enhanced(all_content))
        
        # Calculate risk score
        result.risk_score = _calculate_risk_score(result, repo)
        
        logger.debug(f"Analyzed {repo.full_name}: {len(result.secrets_found)} secrets, risk: {result.risk_score}")
        
    except Exception as e:
        logger.warning(f"Analysis failed for {repo.full_name}: {e}")
    
    return result


def scan_secrets_enhanced(text: str, filename: str = "unknown") -> Dict[str, List[str]]:
    """Enhanced secret detection with comprehensive patterns and file/line tracking."""
    
    secrets = []
    secret_types = []
    
    # Split text into lines for line number tracking
    lines = text.split('\n')
    
    # COMPREHENSIVE secret patterns - detect EVERYTHING suspicious
    patterns = {
        # GitHub tokens (all variants)
        'github_token': {
            'pattern': r'gh[ops]_[A-Za-z0-9]{36}',
            'severity': 'CRITICAL'
        },
        'github_pat': {
            'pattern': r'github_pat_[A-Za-z0-9_]{22,255}',
            'severity': 'CRITICAL'
        },
        
        # AWS credentials (all formats)
        'aws_access_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'severity': 'CRITICAL'
        },
        'aws_session_token': {
            'pattern': r'ASIA[0-9A-Z]{16}',
            'severity': 'CRITICAL'
        },
        'aws_secret_key': {
            'pattern': r'(?i)(aws[_-]?secret|secret[_-]?access[_-]?key)[\'"\s]*[:=][\'"\s]*([A-Za-z0-9/+=]{40})',
            'severity': 'CRITICAL'
        },
        
        # OpenAI/AI services
        'openai_api_key': {
            'pattern': r'sk-[A-Za-z0-9]{48,}',
            'severity': 'CRITICAL'
        },
        
        # Generic API keys and secrets (VERY broad to catch everything)
        'api_key_generic': {
            'pattern': r'(?i)(api[_-]?key|apikey|x-api-key|api[_-]?secret)[\'"\s]*[:=][\'"\s]*([a-zA-Z0-9_\-\.]{12,})',
            'severity': 'HIGH'
        },
        'secret_key_generic': {
            'pattern': r'(?i)(secret[_-]?key|secretkey|secret)[\'"\s]*[:=][\'"\s]*([a-zA-Z0-9_\-\.\/\+]{12,})',
            'severity': 'HIGH'
        },
        
        # PASSWORDS - Multiple comprehensive patterns
        'password_generic': {
            'pattern': r'(?i)(password|passwd|pwd)[\'"\s]*[:=][\'"\s]*([^\s\'"<>{}\[\]]{6,})',
            'severity': 'HIGH'
        },
        
        # JWT tokens
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'severity': 'HIGH'
        },
        
        # Private keys
        'private_key': {
            'pattern': r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
            'severity': 'CRITICAL'
        }
    }
    
    # Scan each line for secrets to track line numbers
    for line_num, line in enumerate(lines, 1):
        for secret_type, config in patterns.items():
            matches = re.finditer(config['pattern'], line)
            
            for match in matches:
                if hasattr(match, 'groups') and match.groups():
                    secret_value = match.groups()[-1]  # Get the actual secret value
                else:
                    secret_value = match.group(0)
                
                # Enhanced validation
                if _is_likely_real_secret(secret_value, secret_type):
                    # Create detailed secret info with file and line
                    secret_info = {
                        'type': secret_type,
                        'severity': config['severity'],
                        'value': secret_value,
                        'file': filename,
                        'line': line_num,
                        'context': line.strip()
                    }
                    secrets.append(secret_info)
                    secret_types.append(secret_type)
    
    
    # COMPREHENSIVE secret patterns - detect EVERYTHING suspicious
    patterns = {
        # GitHub tokens (all variants)
        'github_token': {
            'pattern': r'gh[ops]_[A-Za-z0-9]{36}',
            'severity': 'CRITICAL'
        },
        'github_pat': {
            'pattern': r'github_pat_[A-Za-z0-9_]{22,255}',
            'severity': 'CRITICAL'
        },
        
        # AWS credentials (all formats)
        'aws_access_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'severity': 'CRITICAL'
        },
        'aws_session_token': {
            'pattern': r'ASIA[0-9A-Z]{16}',
            'severity': 'CRITICAL'
        },
        'aws_secret_key': {
            'pattern': r'(?i)(aws[_-]?secret|secret[_-]?access[_-]?key)[\'"\s]*[:=][\'"\s]*([A-Za-z0-9/+=]{40})',
            'severity': 'CRITICAL'
        },
        
        # OpenAI/AI services
        'openai_api_key': {
            'pattern': r'sk-[A-Za-z0-9]{48,}',
            'severity': 'CRITICAL'
        },
        'anthropic_api_key': {
            'pattern': r'sk-ant-[A-Za-z0-9\-_]{95,}',
            'severity': 'CRITICAL'
        },
        
        # Generic API keys and secrets (VERY broad to catch everything)
        'api_key_generic': {
            'pattern': r'(?i)(api[_-]?key|apikey|x-api-key|api[_-]?secret)[\'"\s]*[:=][\'"\s]*([a-zA-Z0-9_\-\.]{12,})',
            'severity': 'HIGH'
        },
        'secret_key_generic': {
            'pattern': r'(?i)(secret[_-]?key|secretkey|secret)[\'"\s]*[:=][\'"\s]*([a-zA-Z0-9_\-\.\/\+]{12,})',
            'severity': 'HIGH'
        },
        'access_key_generic': {
            'pattern': r'(?i)(access[_-]?key|accesskey)[\'"\s]*[:=][\'"\s]*([a-zA-Z0-9_\-\.]{12,})',
            'severity': 'HIGH'
        },
        'client_secret': {
            'pattern': r'(?i)(client[_-]?secret|clientsecret)[\'"\s]*[:=][\'"\s]*([a-zA-Z0-9_\-\.]{12,})',
            'severity': 'HIGH'
        },
        'auth_token': {
            'pattern': r'(?i)(auth[_-]?token|authtoken|authorization[_-]?token)[\'"\s]*[:=][\'"\s]*([a-zA-Z0-9_\-\.]{12,})',
            'severity': 'HIGH'
        },
        
        # PASSWORDS - Multiple comprehensive patterns
        'password_generic': {
            'pattern': r'(?i)(password|passwd|pwd)[\'"\s]*[:=][\'"\s]*([^\s\'"<>{}\[\]]{6,})',
            'severity': 'HIGH'
        },
        'db_password': {
            'pattern': r'(?i)(db[_-]?password|database[_-]?password)[\'"\s]*[:=][\'"\s]*([^\s\'"<>{}\[\]]{6,})',
            'severity': 'CRITICAL'
        },
        
        # JWT and bearer tokens
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'severity': 'HIGH'
        },
        'bearer_token': {
            'pattern': r'(?i)bearer\s+([A-Za-z0-9\-\._~\+\/]{20,})',
            'severity': 'MEDIUM'
        },
        
        # Private keys and certificates
        'private_key': {
            'pattern': r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
            'severity': 'CRITICAL'
        },
        'ssh_private_key': {
            'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'severity': 'CRITICAL'
        },
        
        # Database URLs and connection strings
        'database_url': {
            'pattern': r'(?i)(database_url|db_url)[\'"\s]*[:=][\'"\s]*([^\s\'"]+)',
            'severity': 'HIGH'
        },
        'mongodb_url': {
            'pattern': r'mongodb://[^\s\'"<>{}]+',
            'severity': 'HIGH'
        },
        'postgresql_url': {
            'pattern': r'postgresql://[^\s\'"<>{}]+',
            'severity': 'HIGH'
        },
        
        # Telegram bot token
        'telegram_bot_token': {
            'pattern': r'\d{8,10}:[a-zA-Z0-9_-]{35}',
            'severity': 'HIGH'
        },
        
        # Email credentials
        'email_credential': {
            'pattern': r'(?i)(email|username)[\'"\s]*[:=][\'"\s]*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            'severity': 'MEDIUM'
        },
        
        # Generic high-entropy patterns
        'hex_key': {
            'pattern': r'(?i)(key|secret|token)[\'"\s]*[:=][\'"\s]*([a-fA-F0-9]{32,})',
            'severity': 'MEDIUM'
        }
    }
    
    # Scan each line for secrets to track line numbers
    for line_num, line in enumerate(lines, 1):
        for secret_type, config in patterns.items():
            matches = re.finditer(config['pattern'], line)
            
            for match in matches:
                if hasattr(match, 'groups') and match.groups():
                    secret_value = match.groups()[-1]  # Get the actual secret value
                else:
                    secret_value = match.group(0)
                
                # Enhanced validation
                if _is_likely_real_secret(secret_value, secret_type):
                    # Create detailed secret info with file and line
                    secret_info = {
                        'type': secret_type,
                        'severity': config['severity'],
                        'value': secret_value,
                        'file': filename,
                        'line': line_num,
                        'context': line.strip()
                    }
                    secrets.append(secret_info)
                    secret_types.append(secret_type)
    
    return {
        "secrets": secrets,
        "types": list(set(secret_types))
    }


def _is_likely_real_secret(value: str, secret_type: str) -> bool:
    """Enhanced validation for potential secrets - less restrictive to catch more real secrets."""
    
    if not value or len(value) < 6:  # Reduced minimum length
        return False
    
    # Only filter out very obvious fake patterns
    obvious_fakes = [
        'password', 'secret', 'token', 'key', 'example', 'test', 'demo', 'sample',
        'your_api_key', 'your_token', 'insert_here', 'change_me', 'replace_me',
        'admin', 'root', 'default', 'placeholder'
    ]
    
    # Very obvious test patterns
    test_patterns = [
        'xxxxxxxxxxxx', 'yyyyyyyyyyyy', 'zzzzzzzzzzzz',
        'aaaaaaaaaaaa', 'bbbbbbbbbbbb', 'cccccccccccc',
        '111111111111', '000000000000'
    ]
    
    value_lower = value.lower().strip()
    
    # Only reject exact matches to obvious placeholders
    if value_lower in obvious_fakes:
        return False
    
    # Only reject obvious repeating patterns
    for pattern in test_patterns:
        if pattern in value_lower:
            return False
    
    # For structured tokens with known formats, be very permissive
    structured_types = [
        'github_token', 'github_pat', 'aws_access_key', 'aws_session_token', 
        'google_api_key', 'openai_api_key', 'stripe_live_key', 'stripe_test_key',
        'jwt_token', 'slack_token', 'discord_token', 'telegram_bot_token'
    ]
    
    if secret_type in structured_types:
        # These have specific formats, if they match the regex, they're likely real
        return True
    
    # For passwords, be more permissive - real passwords can contain common words
    if 'password' in secret_type:
        # Only reject if it's an exact match to obvious placeholders
        return value_lower not in ['password', 'admin', 'root', '123456', 'password123']
    
    # For other types, check basic entropy but be lenient
    if len(value) >= 12:  # Longer strings are more likely to be real
        return True
    
    # Check if it has some variety (not all same character)
    if len(set(value.lower())) > 3:  # At least 4 different characters
        return True
    
    # Type-specific validation
    if secret_type == 'base64_potential':
        # Additional validation for base64 - check entropy and length
        if len(value) < 16 or shannon_entropy(value) < 4.0:
            return False
        
        # Check if it's actually base64
        try:
            decoded = base64.b64decode(value, validate=True)
            if len(decoded) < 8:
                return False
        except Exception:
            return False
    
    # Check entropy for all secrets
    entropy = shannon_entropy(value)
    min_entropy = {
        'github_token': 4.5,
        'aws_access_key': 4.0,
        'jwt_token': 4.0,
        'api_key_generic': 3.5,
        'base64_potential': 4.0
    }.get(secret_type, 3.0)
    
    return entropy >= min_entropy


def _detect_high_entropy_strings(text: str, filename: str = "unknown", lines: List[str] = None) -> List[Dict]:
    """Detect high-entropy strings that might be secrets with file/line tracking."""
    
    if lines is None:
        lines = text.split('\n')
    
    # Look for quoted strings that might be secrets
    quoted_patterns = [
        r'"([A-Za-z0-9+/=]{20,})"',
        r"'([A-Za-z0-9+/=]{20,})'",
        r'=([A-Za-z0-9+/=]{20,})\s',
        r':([A-Za-z0-9+/=]{20,})\s'
    ]
    
    high_entropy_secrets = []
    
    # Scan each line for high entropy strings
    for line_num, line in enumerate(lines, 1):
        for pattern in quoted_patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                value = match.group(1)
                if shannon_entropy(value) > 4.5 and len(value) > 16:
                    secret_info = {
                        'type': 'high_entropy',
                        'severity': 'MEDIUM',
                        'value': value,
                        'file': filename,
                        'line': line_num,
                        'context': line.strip()
                    }
                    high_entropy_secrets.append(secret_info)
                    if len(high_entropy_secrets) >= 5:  # Limit to 5 to avoid spam
                        break
        if len(high_entropy_secrets) >= 5:
            break
    
    return high_entropy_secrets


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0
    
    # Get frequency of each character
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy


def _extract_urls_enhanced(text: str) -> Set[str]:
    """Enhanced URL extraction with better filtering."""
    
    # Enhanced URL patterns
    url_patterns = [
        r'https?://[^\s<>"\'(){}[\]]+[^\s<>"\'(){}[\].,;:]',
        r'(?i)(?:api|endpoint|webhook)[\'"\s]*[:=][\'"\s]*(https?://[^\s\'"]+)',
        r'(?i)(?:url|uri|link)[\'"\s]*[:=][\'"\s]*(https?://[^\s\'"]+)'
    ]
    
    urls = set()
    
    for pattern in url_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            if isinstance(match, tuple):
                url = match[-1]
            else:
                url = match
            
            # Clean up URL
            url = url.rstrip('.,;:')
            
            # Filter interesting URLs
            if _is_interesting_url(url):
                urls.add(url)
    
    return urls


def _is_interesting_url(url: str) -> bool:
    """Check if URL is worth reporting."""
    
    # Skip common uninteresting domains
    skip_domains = [
        'github.com', 'githubusercontent.com', 'example.com', 'localhost',
        'httpbin.org', 'jsonplaceholder.typicode.com', 'google.com',
        'stackoverflow.com', 'medium.com', 'docs.microsoft.com'
    ]
    
    url_lower = url.lower()
    for domain in skip_domains:
        if domain in url_lower:
            return False
    
    # Look for interesting patterns
    interesting_patterns = [
        'api', 'webhook', 'admin', 'internal', 'staging', 'dev',
        'test', 'beta', 'prod', 'secure', 'auth', 'oauth'
    ]
    
    for pattern in interesting_patterns:
        if pattern in url_lower:
            return True
    
    # Check for non-standard ports or suspicious TLDs
    if re.search(r':\d{4,5}/', url) or any(tld in url_lower for tld in ['.tk', '.ml', '.ga']):
        return True
    
    return len(url) > 30  # Longer URLs might be more interesting


def _calculate_risk_score(result: AnalysisResult, repo) -> int:
    """Calculate risk score based on findings."""
    
    score = 0
    
    # Secret findings
    for secret_type in result.secret_types:
        type_scores = {
            'github_token': 100,
            'aws_access_key': 90,
            'aws_secret_key': 90,
            'private_key': 85,
            'crypto_private_key': 80,
            'database_url': 70,
            'api_key_generic': 60,
            'jwt_token': 50,
            'slack_token': 40,
            'telegram_bot_token': 30,
            'high_entropy': 25,
            'base64_potential': 15
        }
        score += type_scores.get(secret_type, 10)
    
    # Repository characteristics
    if repo.stars < 10:
        score += 10  # Less visible repos might have more secrets
    
    if 'test' in repo.full_name.lower() or 'demo' in repo.full_name.lower():
        score -= 20  # Test repos less likely to have real secrets
    
    # URL findings
    score += min(len(result.related_urls) * 5, 25)
    
    return min(score, 100)


async def _fetch_readme(repo_name: str, token: str) -> str:
    """Fetch README content from repository."""
    return await _fetch_file(repo_name, "README.md", token)


async def _fetch_file(repo_name: str, filename: str, token: str) -> str:
    """Fetch file content from repository."""
    
    if not token or token == "dummy_token":
        return ""
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitFuzzer/1.0"
        }
        
        try:
            response = await client.get(
                f"https://api.github.com/repos/{repo_name}/contents/{filename}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("encoding") == "base64":
                    content = base64.b64decode(data["content"]).decode('utf-8', errors='ignore')
                    return content
        except Exception as e:
            logger.debug(f"Failed to fetch {filename} for {repo_name}: {e}")
    
    return ""


async def _fetch_extended_files(repo_name: str, token: str) -> str:
    """Fetch content from extended list of common secret-containing files."""
    
    # Extended file list for secret scanning
    extended_files = [
        "README.md", ".env", "config.json", "package.json", "docker-compose.yml",
        ".env.example", ".env.local", ".env.production", "config.yaml", "config.yml",
        "settings.json", "settings.py", "config.py", "constants.py", "secrets.json",
        ".gitignore", "Dockerfile", "docker-compose.yaml", "webpack.config.js",
        "next.config.js", "nuxt.config.js", "vue.config.js", "angular.json",
        "tsconfig.json", "babel.config.js", ".babelrc", "jest.config.js",
        "karma.conf.js", "gulpfile.js", "Gruntfile.js", "Makefile", "requirements.txt",
        "Pipfile", "poetry.lock", "yarn.lock", "package-lock.json", "composer.json",
        "Gemfile", "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.sbt"
    ]
    
    all_content = []
    
    if not token or token == "dummy_token":
        return ""
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitFuzzer/1.0"
        }
        
        for filename in extended_files:
            try:
                response = await client.get(
                    f"https://api.github.com/repos/{repo_name}/contents/{filename}",
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("encoding") == "base64":
                        content = base64.b64decode(data["content"]).decode('utf-8', errors='ignore')
                        all_content.append(f"=== {filename} ===\n{content}\n")
                        
                        # Limit total content size to prevent memory issues
                        if len(''.join(all_content)) > 500000:  # 500KB limit
                            break
                            
            except Exception as e:
                logger.debug(f"Failed to fetch {filename} for {repo_name}: {e}")
                continue
    
    return '\n'.join(all_content)


async def _fetch_whole_repository(repo_name: str, token: str) -> str:
    """Fetch content from all files in the repository (with size limits)."""
    
    all_content = []
    
    if not token or token == "dummy_token":
        return ""
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitFuzzer/1.0"
        }
        
        try:
            # Get repository tree
            response = await client.get(
                f"https://api.github.com/repos/{repo_name}/git/trees/HEAD?recursive=1",
                headers=headers
            )
            
            if response.status_code != 200:
                logger.warning(f"Failed to get repository tree for {repo_name}")
                return ""
            
            tree_data = response.json()
            files = tree_data.get("tree", [])
            
            # Filter to code files only and exclude large files
            code_extensions = {
                '.py', '.js', '.ts', '.java', '.go', '.rs', '.cpp', '.c', '.h',
                '.php', '.rb', '.swift', '.kt', '.scala', '.clj', '.hs', '.ml',
                '.json', '.yml', '.yaml', '.xml', '.toml', '.ini', '.cfg', '.conf',
                '.env', '.properties', '.config', '.settings', '.md', '.txt'
            }
            
            code_files = []
            for file_obj in files:
                if file_obj.get("type") == "blob":  # It's a file
                    path = file_obj.get("path", "")
                    size = file_obj.get("size", 0)
                    
                    # Check if it's a code file and not too large
                    if (any(path.lower().endswith(ext) for ext in code_extensions) and 
                        size < 100000):  # 100KB per file limit
                        code_files.append(path)
            
            # Limit number of files to prevent rate limiting
            code_files = code_files[:50]  # Max 50 files
            
            # Fetch content of each file
            for filepath in code_files:
                try:
                    file_response = await client.get(
                        f"https://api.github.com/repos/{repo_name}/contents/{filepath}",
                        headers=headers
                    )
                    
                    if file_response.status_code == 200:
                        file_data = file_response.json()
                        if file_data.get("encoding") == "base64":
                            content = base64.b64decode(file_data["content"]).decode('utf-8', errors='ignore')
                            all_content.append(f"=== {filepath} ===\n{content}\n")
                            
                            # Limit total content size
                            if len(''.join(all_content)) > 1000000:  # 1MB total limit
                                break
                                
                    # Add small delay to respect rate limits
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    logger.debug(f"Failed to fetch {filepath} for {repo_name}: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Failed to fetch whole repository {repo_name}: {e}")
            return ""
    
    return '\n'.join(all_content)
