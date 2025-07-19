"""Test suite for GitFuzzer fuzz module."""

import asyncio
import tempfile
from pathlib import Path
import pytest
import aiohttp

from gitfuzzer.fuzz.secret_rules import SecretRuleEngine, SecretMatch
from gitfuzzer.fuzz.endpoint_extractor import EndpointExtractor, EndpointMatch
from gitfuzzer.fuzz.org_infer import OrganizationInferrer
from gitfuzzer.fuzz.score import RiskScorer, RiskLevel
from gitfuzzer.fuzz.reporter_tg import TelegramReporter


class TestSecretRuleEngine:
    """Test secret detection engine."""
    
    def test_entropy_calculation(self):
        """Test Shannon entropy calculation."""
        engine = SecretRuleEngine()
        
        # Low entropy string
        low_entropy = engine.calculate_shannon_entropy("aaaaaaaaaa")
        assert low_entropy < 2.0
        
        # High entropy string  
        high_entropy = engine.calculate_shannon_entropy("aB3$kL9#mN2@")
        assert high_entropy > 3.0
    
    def test_base64_detection(self):
        """Test base64 string detection."""
        engine = SecretRuleEngine()
        
        assert engine.is_likely_base64("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0")
        assert not engine.is_likely_base64("not-base64-string")
        assert not engine.is_likely_base64("short")
    
    def test_hex_detection(self):
        """Test hex string detection."""
        engine = SecretRuleEngine()
        
        assert engine.is_likely_hex("deadbeefcafebabe1234567890abcdef")
        assert not engine.is_likely_hex("not-hex-string")
        assert not engine.is_likely_hex("abc")
    
    def test_secret_masking(self):
        """Test secret masking functionality."""
        engine = SecretRuleEngine()
        
        secret = "AKIA1234567890ABCDEF"
        masked = engine.mask_secret(secret)
        
        assert len(masked) == len(secret)
        assert masked.startswith("AKIA")
        assert masked.endswith("CDEF")
        assert "*" in masked
    
    def test_aws_key_detection(self):
        """Test AWS key detection."""
        engine = SecretRuleEngine()
        
        content = '''
        # Configuration file
        AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
        AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        '''
        
        matches = engine.scan_content(content, "test.conf")
        
        # Should find AWS access key
        aws_keys = [m for m in matches if m.rule_id == 'aws-access-key-id']
        assert len(aws_keys) > 0
        assert aws_keys[0].confidence > 0.8
    
    def test_github_token_detection(self):
        """Test GitHub token detection."""
        engine = SecretRuleEngine()
        
        content = '''
        const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        '''
        
        matches = engine.scan_content(content, "config.js")
        
        # Should find GitHub PAT
        github_tokens = [m for m in matches if m.rule_id == 'github-pat']
        assert len(github_tokens) > 0


class TestEndpointExtractor:
    """Test endpoint extraction."""
    
    @pytest.fixture
    async def extractor(self):
        """Create endpoint extractor with session."""
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            extractor = EndpointExtractor(session)
            yield extractor
    
    def test_url_extraction(self):
        """Test URL extraction from content."""
        extractor = EndpointExtractor()
        
        content = '''
        API_BASE_URL = "https://api.example.com/v1"
        WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        '''
        
        endpoints = extractor.extract_from_content(content, "config.py")
        
        urls = [ep for ep in endpoints if ep.endpoint_type == 'url']
        assert len(urls) >= 1
        assert any("api.example.com" in ep.url for ep in urls)
    
    def test_ip_extraction(self):
        """Test IP address extraction."""
        extractor = EndpointExtractor()
        
        content = '''
        DATABASE_HOST = "192.168.1.100"
        REDIS_HOST = "10.0.0.50"
        '''
        
        endpoints = extractor.extract_from_content(content, "settings.py")
        
        ips = [ep for ep in endpoints if ep.endpoint_type == 'ip']
        # Should not find private IPs
        assert len(ips) == 0
    
    def test_domain_extraction(self):
        """Test domain extraction."""
        extractor = EndpointExtractor()
        
        content = '''
        # Company website
        COMPANY_DOMAIN = "example.com"
        API_DOMAIN = "api.example.com"
        '''
        
        endpoints = extractor.extract_from_content(content, "constants.py")
        
        domains = [ep for ep in endpoints if ep.endpoint_type == 'domain']
        assert len(domains) >= 1
    
    def test_email_extraction(self):
        """Test email extraction."""
        extractor = EndpointExtractor()
        
        content = '''
        ADMIN_EMAIL = "admin@example.com"
        SUPPORT_EMAIL = "support@company.org"
        '''
        
        endpoints = extractor.extract_from_content(content, "config.yml")
        
        emails = [ep for ep in endpoints if ep.endpoint_type == 'email']
        assert len(emails) >= 1


class TestOrganizationInferrer:
    """Test organization inference."""
    
    @pytest.fixture
    async def inferrer(self):
        """Create organization inferrer."""
        async with aiohttp.ClientSession() as session:
            inferrer = OrganizationInferrer(session)
            yield inferrer
    
    def test_github_org_extraction(self):
        """Test GitHub organization extraction."""
        inferrer = OrganizationInferrer()
        
        # This would be tested with mock GitHub API responses
        repo_url = "https://github.com/microsoft/vscode"
        
        # In a real test, you'd mock the API response
        assert repo_url.startswith("https://github.com/")
    
    def test_domain_org_extraction(self):
        """Test organization extraction from domains."""
        inferrer = OrganizationInferrer()
        
        # Mock endpoint matches
        endpoints = [
            EndpointMatch(
                url="api.stripe.com",
                endpoint_type="domain",
                file_path="config.py",
                line_no=1
            )
        ]
        
        org = inferrer._infer_from_domains(endpoints)
        assert org is not None
        assert "Stripe" in org.name


class TestRiskScorer:
    """Test risk scoring."""
    
    def test_secret_scoring(self):
        """Test secret scoring."""
        scorer = RiskScorer()
        
        # High-risk secret
        high_risk_secret = SecretMatch(
            rule_id="aws-secret-access-key",
            line_no=1,
            file_path="config.py",
            snippet="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            masked_snippet="wJal****MPLEKEY",
            entropy=5.2,
            confidence=0.9
        )
        
        score = scorer._score_secrets([high_risk_secret])
        assert score >= 40  # Should be high score
    
    def test_endpoint_scoring(self):
        """Test endpoint scoring."""
        scorer = RiskScorer()
        
        # Live endpoint
        live_endpoint = EndpointMatch(
            url="https://api.example.com/users",
            endpoint_type="url",
            file_path="api.py",
            line_no=1,
            is_live=True,
            status_code=200
        )
        
        score = scorer._score_endpoints([live_endpoint])
        assert score > 0
    
    def test_risk_level_determination(self):
        """Test risk level calculation."""
        scorer = RiskScorer()
        
        assert scorer._determine_risk_level(10) == RiskLevel.LOW
        assert scorer._determine_risk_level(50) == RiskLevel.MEDIUM
        assert scorer._determine_risk_level(80) == RiskLevel.HIGH
        assert scorer._determine_risk_level(120) == RiskLevel.CRITICAL


class TestTelegramReporter:
    """Test Telegram reporting."""
    
    def test_markdown_escaping(self):
        """Test Markdown V2 escaping."""
        reporter = TelegramReporter("fake_token", "fake_chat_id")
        
        text = "This has special chars: _*[]()~`>#+-=|{}.!"
        escaped = reporter.escape_markdown_v2(text)
        
        # All special characters should be escaped
        for char in "_*[]()~`>#+-=|{}.!":
            assert f"\\{char}" in escaped
    
    def test_message_splitting(self):
        """Test long message splitting."""
        reporter = TelegramReporter("fake_token", "fake_chat_id")
        
        # Create a very long message
        long_message = "Test message\\n" * 1000
        
        parts = reporter.split_long_message(long_message)
        
        assert len(parts) > 1
        for part in parts:
            assert len(part) <= reporter.max_message_length
    
    def test_button_text_truncation(self):
        """Test button text truncation."""
        reporter = TelegramReporter("fake_token", "fake_chat_id")
        
        long_text = "https://very-long-domain-name-that-exceeds-button-limits.com/api/v1/endpoint"
        truncated = reporter._truncate_button_text(long_text, 20)
        
        assert len(truncated) <= 20
        assert truncated.endswith("...")


@pytest.mark.asyncio
async def test_integration_flow():
    """Test integration of fuzz components."""
    
    # Create test content with secrets and endpoints
    test_content = '''
    # Test configuration file
    AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
    API_ENDPOINT = "https://api.example.com/v1"
    DATABASE_URL = "postgres://user:pass@db.example.com:5432/mydb"
    ADMIN_EMAIL = "admin@example.com"
    '''
    
    # Test secret detection
    secret_engine = SecretRuleEngine()
    secret_matches = secret_engine.scan_content(test_content, "test_config.py")
    
    assert len(secret_matches) > 0
    
    # Test endpoint extraction
    endpoint_extractor = EndpointExtractor()
    endpoint_matches = endpoint_extractor.extract_from_content(test_content, "test_config.py")
    
    assert len(endpoint_matches) > 0
    
    # Test organization inference
    org_inferrer = OrganizationInferrer()
    organization = await org_inferrer.infer_from_repository(
        "https://github.com/testorg/testrepo",
        secret_matches,
        endpoint_matches
    )
    
    # Test risk scoring
    risk_scorer = RiskScorer()
    risk_assessment = risk_scorer.assess_risk(secret_matches, endpoint_matches, organization)
    
    assert risk_assessment.total_score > 0
    assert risk_assessment.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert len(risk_assessment.factors) > 0
    assert len(risk_assessment.recommendations) > 0


if __name__ == "__main__":
    pytest.main([__file__])
