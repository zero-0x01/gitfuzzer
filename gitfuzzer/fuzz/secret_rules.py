"""Secret detection rules engine for GitFuzzer.

This module combines Gitleaks and TruffleHog regex patterns
with entropy analysis for comprehensive secret detection.
"""

import math
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from collections import Counter


@dataclass
class SecretMatch:
    """Represents a detected secret."""
    rule_id: str
    line_no: int
    file_path: str
    snippet: str
    masked_snippet: str
    entropy: float
    confidence: float


class SecretRuleEngine:
    """Engine for detecting secrets using compiled regex patterns and entropy analysis."""
    
    def __init__(self, custom_rules: Optional[Dict[str, str]] = None):
        """Initialize secret detection engine.
        
        Args:
            custom_rules: Optional custom regex rules in format {rule_id: pattern}
        """
        self.rules = self._load_default_rules()
        if custom_rules:
            self.rules.update(custom_rules)
        
        # Compile all patterns for performance
        self.compiled_patterns = {
            rule_id: re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for rule_id, pattern in self.rules.items()
        }
        
        # Entropy thresholds
        self.min_entropy = 4.2
        self.min_string_length = 16
        
        # Base64/hex character sets
        self.base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        self.hex_chars = set('0123456789abcdefABCDEF')
    
    def _load_default_rules(self) -> Dict[str, str]:
        """Load default secret detection rules from Gitleaks and TruffleHog."""
        return {
            # AWS Keys
            'aws-access-key-id': r'AKIA[0-9A-Z]{16}',
            'aws-secret-access-key': r'(?i)aws(.{0,20})?[\'\"\s]{0,5}[0-9a-zA-Z\/+]{40}',
            'aws-session-token': r'(?i)aws(.{0,20})?session(.{0,20})?[\'\"\s]{0,5}[0-9a-zA-Z\/+]{16,}',
            
            # GitHub
            'github-pat': r'ghp_[0-9a-zA-Z]{36}',
            'github-oauth': r'gho_[0-9a-zA-Z]{36}',
            'github-app': r'(ghu|ghs)_[0-9a-zA-Z]{36}',
            'github-refresh': r'ghr_[0-9a-zA-Z]{76}',
            
            # Google
            'google-api-key': r'AIza[0-9A-Za-z\\-_]{35}',
            'google-oauth-id': r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
            'google-service-account': r'"type"\\s*:\\s*"service_account"',
            
            # Slack
            'slack-token': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
            'slack-webhook': r'https://hooks\\.slack\\.com/services/[A-Za-z0-9+/]{44,46}',
            
            # Discord
            'discord-bot-token': r'[MN][A-Za-z\d]{23}\.[w-]{6}\.[w-]{27}',
            'discord-webhook': r'https://discord(app)?\\.com/api/webhooks/[0-9]{18}/[A-Za-z0-9\\-_]{68}',
            
            # Telegram
            'telegram-bot-token': r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}',
            
            # Database URLs
            'postgres-url': r'postgres(ql)?://[^\\s]+',
            'mysql-url': r'mysql://[^\\s]+',
            'mongodb-url': r'mongodb(\\+srv)?://[^\\s]+',
            'redis-url': r'redis://[^\\s]+',
            
            # API Keys (Generic)
            'generic-api-key': r'(?i)(api[_-]?key|apikey|secret[_-]?key|secretkey)\\s*[=:]\\s*[\'\"\\s]*([0-9a-zA-Z\\-_]{16,64})',
            'bearer-token': r'(?i)bearer\\s+[A-Za-z0-9\\-_+/]{16,}',
            
            # Private Keys
            'private-key': r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
            'ssh-private-key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            
            # JWT Tokens
            'jwt-token': r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-.+/=]*',
            
            # Generic Secrets (High Entropy)
            'high-entropy-base64': r'[A-Za-z0-9+/]{32,}={0,2}',
            'high-entropy-hex': r'[a-fA-F0-9]{32,}',
            
            # Docker
            'docker-auth': r'"auth"\\s*:\\s*"[A-Za-z0-9+/]+=*"',
            
            # Stripe
            'stripe-publishable': r'pk_(test|live)_[0-9a-zA-Z]{24}',
            'stripe-secret': r'sk_(test|live)_[0-9a-zA-Z]{24}',
            
            # Twilio
            'twilio-sid': r'AC[a-fA-F0-9]{32}',
            'twilio-auth-token': r'SK[a-fA-F0-9]{32}',
            
            # Mailgun
            'mailgun-api-key': r'key-[0-9a-zA-Z]{32}',
            
            # SendGrid
            'sendgrid-api-key': r'SG\\.[a-zA-Z0-9\\-_]{22}\\.[a-zA-Z0-9\\-_]{43}',
            
            # Generic Password/Secret patterns
            'password-in-url': r'[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}',
            'connection-string': r'(?i)(connectionstring|connstr)\\s*[=:]\\s*[\'\"\\s]*([^\'\"\\n\\r]+)',
        }
    
    def calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string.
        
        Args:
            data: String to analyze
            
        Returns:
            Shannon entropy value
        """
        if not data:
            return 0.0
        
        # Count character frequencies
        entropy = 0.0
        counter = Counter(data)
        length = len(data)
        
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def is_likely_base64(self, data: str) -> bool:
        """Check if string is likely base64 encoded.
        
        Args:
            data: String to check
            
        Returns:
            True if likely base64
        """
        if len(data) < self.min_string_length:
            return False
        
        # Check character set
        if not set(data).issubset(self.base64_chars):
            return False
        
        # Check length (base64 should be multiple of 4)
        if len(data) % 4 != 0:
            return False
        
        # Check padding
        if data.endswith('==') or data.endswith('='):
            return True
        
        return len(data) >= 32
    
    def is_likely_hex(self, data: str) -> bool:
        """Check if string is likely hex encoded.
        
        Args:
            data: String to check
            
        Returns:
            True if likely hex
        """
        if len(data) < self.min_string_length:
            return False
        
        return set(data).issubset(self.hex_chars) and len(data) >= 32
    
    def mask_secret(self, secret: str, visible_chars: int = 4) -> str:
        """Mask middle portion of secret for safe display.
        
        Args:
            secret: Secret string to mask
            visible_chars: Number of characters to keep visible at start/end
            
        Returns:
            Masked secret string
        """
        if len(secret) <= visible_chars * 2:
            return '*' * len(secret)
        
        start = secret[:visible_chars]
        end = secret[-visible_chars:]
        middle_length = len(secret) - (visible_chars * 2)
        
        # Mask 60% of middle portion
        mask_length = max(1, int(middle_length * 0.6))
        visible_middle = middle_length - mask_length
        
        if visible_middle > 0:
            middle_start = visible_middle // 2
            middle_end = middle_start + mask_length
            middle = secret[visible_chars:visible_chars + middle_start] + \
                    '*' * mask_length + \
                    secret[visible_chars + middle_end:len(secret) - visible_chars]
        else:
            middle = '*' * middle_length
        
        return start + middle + end
    
    def scan_content(self, content: str, file_path: str) -> List[SecretMatch]:
        """Scan content for secrets using compiled regex patterns.
        
        Args:
            content: File content to scan
            file_path: Path of the file being scanned
            
        Returns:
            List of detected secrets
        """
        matches = []
        lines = content.split('\n')
        
        for line_no, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Apply each compiled pattern
            for rule_id, pattern in self.compiled_patterns.items():
                for match in pattern.finditer(line):
                    secret_text = match.group(0)
                    
                    # Skip if too short
                    if len(secret_text) < self.min_string_length:
                        continue
                    
                    # Calculate entropy
                    entropy = self.calculate_shannon_entropy(secret_text)
                    
                    # For high-entropy rules, check entropy threshold
                    if rule_id in ['high-entropy-base64', 'high-entropy-hex']:
                        if entropy < self.min_entropy:
                            continue
                        
                        # Additional validation for base64/hex
                        if rule_id == 'high-entropy-base64' and not self.is_likely_base64(secret_text):
                            continue
                        elif rule_id == 'high-entropy-hex' and not self.is_likely_hex(secret_text):
                            continue
                    
                    # Calculate confidence based on rule type and entropy
                    confidence = self._calculate_confidence(rule_id, entropy, secret_text)
                    
                    # Create masked version
                    masked_snippet = self.mask_secret(secret_text)
                    
                    matches.append(SecretMatch(
                        rule_id=rule_id,
                        line_no=line_no,
                        file_path=file_path,
                        snippet=secret_text,
                        masked_snippet=masked_snippet,
                        entropy=entropy,
                        confidence=confidence
                    ))
        
        return matches
    
    def _calculate_confidence(self, rule_id: str, entropy: float, secret_text: str) -> float:
        """Calculate confidence score for a secret match.
        
        Args:
            rule_id: ID of the matching rule
            entropy: Shannon entropy of the secret
            secret_text: The secret text
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        base_confidence = 0.7
        
        # Higher confidence for specific patterns
        if rule_id.startswith(('aws-', 'github-', 'google-', 'slack-')):
            base_confidence = 0.9
        elif rule_id.startswith(('stripe-', 'twilio-', 'sendgrid-')):
            base_confidence = 0.85
        elif rule_id in ['private-key', 'ssh-private-key', 'jwt-token']:
            base_confidence = 0.95
        
        # Adjust based on entropy
        if entropy > 5.0:
            base_confidence += 0.1
        elif entropy < 3.0:
            base_confidence -= 0.2
        
        # Adjust based on length
        if len(secret_text) > 64:
            base_confidence += 0.05
        elif len(secret_text) < 24:
            base_confidence -= 0.1
        
        return max(0.0, min(1.0, base_confidence))
    
    def get_rule_description(self, rule_id: str) -> str:
        """Get human-readable description of a rule.
        
        Args:
            rule_id: Rule identifier
            
        Returns:
            Description string
        """
        descriptions = {
            'aws-access-key-id': 'AWS Access Key ID',
            'aws-secret-access-key': 'AWS Secret Access Key',
            'github-pat': 'GitHub Personal Access Token',
            'google-api-key': 'Google API Key',
            'slack-token': 'Slack Token',
            'discord-bot-token': 'Discord Bot Token',
            'telegram-bot-token': 'Telegram Bot Token',
            'private-key': 'Private Key',
            'jwt-token': 'JWT Token',
            'high-entropy-base64': 'High Entropy Base64 String',
            'high-entropy-hex': 'High Entropy Hex String',
            'generic-api-key': 'Generic API Key',
            'bearer-token': 'Bearer Token',
            'password-in-url': 'Password in URL',
        }
        
        return descriptions.get(rule_id, rule_id.replace('-', ' ').title())
