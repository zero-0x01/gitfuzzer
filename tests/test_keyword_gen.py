"""Tests for keyword generation module."""

import pytest
from unittest.mock import AsyncMock, patch
from aiohttp import ClientResponse, ClientSession

from gitfuzzer.keyword_gen import KeywordGenerator, KeywordResponse, generate_keywords_for_subject
from gitfuzzer.config import Config


class TestKeywordGenerator:
    """Test keyword generation functionality."""
    
    @pytest.fixture
    def generator(self, test_config):
        """Create a KeywordGenerator instance."""
        return KeywordGenerator(test_config)
    
    def test_create_prompt(self, generator):
        """Test prompt creation."""
        prompt = generator._create_prompt("crypto", 5)
        
        assert "crypto" in prompt
        assert "5" in prompt
        assert "programming-related keywords" in prompt
        assert "GitHub repositories" in prompt
    
    def test_create_prompt_with_context(self, generator):
        """Test prompt creation with additional context."""
        prompt = generator._create_prompt("crypto", 5, "blockchain technology")
        
        assert "crypto" in prompt
        assert "blockchain technology" in prompt
        assert "Additional context" in prompt
    
    def test_parse_keywords_from_text(self, generator):
        """Test keyword parsing from generated text."""
        # Test numbered list
        text = "1. blockchain\n2. cryptocurrency\n3. bitcoin"
        keywords = generator._parse_keywords_from_text(text)
        
        assert "blockchain" in keywords
        assert "cryptocurrency" in keywords
        assert "bitcoin" in keywords
    
    def test_parse_keywords_comma_separated(self, generator):
        """Test parsing comma-separated keywords."""
        text = "blockchain, cryptocurrency, bitcoin, ethereum"
        keywords = generator._parse_keywords_from_text(text)
        
        assert len(keywords) >= 4
        assert "blockchain" in keywords
        assert "bitcoin" in keywords
    
    def test_parse_keywords_mixed_format(self, generator):
        """Test parsing mixed format keywords."""
        text = "• blockchain\n- cryptocurrency\n* bitcoin\nweb3"
        keywords = generator._parse_keywords_from_text(text)
        
        assert "blockchain" in keywords
        assert "cryptocurrency" in keywords
        assert "bitcoin" in keywords
        assert "web3" in keywords
    
    def test_get_fallback_keywords(self, generator):
        """Test fallback keyword generation."""
        keywords = generator._get_fallback_keywords("crypto", 5)
        
        assert len(keywords) <= 5
        assert any("crypto" in kw.lower() for kw in keywords)
    
    def test_get_fallback_keywords_subjects(self, generator):
        """Test fallback keywords for different subjects."""
        subjects = ["ai", "web", "mobile", "game", "security"]
        
        for subject in subjects:
            keywords = generator._get_fallback_keywords(subject, 3)
            assert len(keywords) <= 3
            assert len(keywords) > 0
    
    def test_expand_keywords(self, generator):
        """Test keyword expansion."""
        keywords = ["test", "example"]
        expanded = generator._expand_keywords(keywords)
        
        assert "test" in expanded
        assert "example" in expanded
        assert len(expanded) > len(keywords)
        
        # Check for plurals
        assert any("tests" in kw for kw in expanded)
        
        # Check for variations
        assert any("_" in kw for kw in expanded)
    
    @pytest.mark.asyncio
    async def test_query_huggingface_success(self, generator, mock_session):
        """Test successful Hugging Face API query."""
        # Mock response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = [{"generated_text": "blockchain\ncryptocurrency\nbitcoin"}]
        
        mock_session.post.return_value.__aenter__.return_value = mock_response
        
        with patch.object(generator, 'session', mock_session):
            keywords = await generator._query_huggingface("test prompt")
        
        assert keywords is not None
        assert len(keywords) > 0
        assert "blockchain" in keywords
    
    @pytest.mark.asyncio
    async def test_query_huggingface_rate_limit(self, generator, mock_session):
        """Test Hugging Face API rate limit handling."""
        mock_response = AsyncMock()
        mock_response.status = 429
        
        mock_session.post.return_value.__aenter__.return_value = mock_response
        
        with patch.object(generator, 'session', mock_session):
            keywords = await generator._query_huggingface("test prompt")
        
        assert keywords is None
    
    @pytest.mark.asyncio
    async def test_query_huggingface_model_loading(self, generator, mock_session):
        """Test Hugging Face API model loading response."""
        mock_response = AsyncMock()
        mock_response.status = 503
        
        mock_session.post.return_value.__aenter__.return_value = mock_response
        
        with patch.object(generator, 'session', mock_session):
            keywords = await generator._query_huggingface("test prompt")
        
        assert keywords is None
    
    @pytest.mark.asyncio
    async def test_query_huggingface_error(self, generator, mock_session):
        """Test Hugging Face API error handling."""
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_response.text.return_value = "Internal server error"
        
        mock_session.post.return_value.__aenter__.return_value = mock_response
        
        with patch.object(generator, 'session', mock_session):
            keywords = await generator._query_huggingface("test prompt")
        
        assert keywords is None
    
    @pytest.mark.asyncio
    async def test_generate_keywords_ai_success(self, generator):
        """Test successful AI keyword generation."""
        with patch.object(generator, '_query_huggingface') as mock_hf:
            mock_hf.return_value = ["blockchain", "cryptocurrency", "bitcoin", "ethereum", "defi"]
            
            result = await generator.generate_keywords("crypto", 5)
        
        assert isinstance(result, KeywordResponse)
        assert result.source == "ai"
        assert len(result.keywords) >= 5
        assert result.model_used is not None
    
    @pytest.mark.asyncio
    async def test_generate_keywords_fallback(self, generator):
        """Test fallback keyword generation when AI fails."""
        with patch.object(generator, '_query_huggingface') as mock_hf:
            mock_hf.return_value = None  # AI failure
            
            result = await generator.generate_keywords("crypto", 5)
        
        assert isinstance(result, KeywordResponse)
        assert result.source == "fallback"
        assert len(result.keywords) > 0
        assert result.model_used is None
    
    @pytest.mark.asyncio
    async def test_generate_keywords_hybrid(self, generator):
        """Test hybrid keyword generation (AI + fallback)."""
        with patch.object(generator, '_query_huggingface') as mock_hf:
            mock_hf.return_value = ["blockchain", "bitcoin"]  # Partial AI result
            
            result = await generator.generate_keywords("crypto", 5)
        
        assert isinstance(result, KeywordResponse)
        assert result.source == "hybrid"
        assert len(result.keywords) >= 2
        assert "blockchain" in result.keywords
        assert "bitcoin" in result.keywords
    
    @pytest.mark.asyncio
    async def test_generate_keywords_with_expansion(self, generator):
        """Test keyword generation with expansion enabled."""
        with patch.object(generator, '_query_huggingface') as mock_hf:
            mock_hf.return_value = ["test", "example"]
            
            result = await generator.generate_keywords("testing", 5, expand=True)
        
        assert len(result.keywords) > 2  # Should be expanded
        assert "test" in result.keywords
    
    @pytest.mark.asyncio
    async def test_generate_keywords_no_expansion(self, generator):
        """Test keyword generation without expansion."""
        with patch.object(generator, '_query_huggingface') as mock_hf:
            mock_hf.return_value = ["test", "example", "sample", "demo", "prototype"]
            
            result = await generator.generate_keywords("testing", 5, expand=False)
        
        assert len(result.keywords) == 5
    
    @pytest.mark.asyncio 
    async def test_context_manager(self, test_config):
        """Test using KeywordGenerator as context manager."""
        async with KeywordGenerator(test_config) as generator:
            assert generator.session is not None
        
        # Session should be closed after context exit
        assert generator.session.closed


class TestKeywordFunctions:
    """Test module-level keyword functions."""
    
    @pytest.mark.asyncio
    async def test_generate_keywords_for_subject(self, test_config):
        """Test convenience function for keyword generation."""
        with patch('gitfuzzer.keyword_gen.KeywordGenerator') as mock_gen_class:
            mock_generator = AsyncMock()
            mock_generator.generate_keywords.return_value = KeywordResponse(
                keywords=["test1", "test2"],
                source="ai",
                model_used="test-model"
            )
            mock_gen_class.return_value.__aenter__.return_value = mock_generator
            
            result = await generate_keywords_for_subject("testing", test_config)
        
        assert isinstance(result, KeywordResponse)
        assert result.keywords == ["test1", "test2"]
        assert result.source == "ai"


class TestKeywordSanitization:
    """Test keyword sanitization and validation."""
    
    def test_sanitize_special_characters(self, generator):
        """Test sanitization of special characters."""
        from gitfuzzer.utils import sanitize_keyword
        
        # Test special characters removal
        assert sanitize_keyword("test@#$%") == "test"
        assert sanitize_keyword("hello-world") == "hello-world"
        assert sanitize_keyword("test_case") == "test_case"
    
    def test_sanitize_whitespace(self, generator):
        """Test whitespace normalization."""
        from gitfuzzer.utils import sanitize_keyword
        
        assert sanitize_keyword("  test  ") == "test"
        assert sanitize_keyword("hello   world") == "hello world"
        assert sanitize_keyword("test\n\tcase") == "test case"
    
    def test_sanitize_length_limit(self, generator):
        """Test length limiting."""
        from gitfuzzer.utils import sanitize_keyword
        
        long_keyword = "a" * 100
        sanitized = sanitize_keyword(long_keyword)
        assert len(sanitized) <= 50
    
    def test_keyword_deduplication(self, generator):
        """Test keyword deduplication in results."""
        keywords = ["test", "example", "test", "sample", "example"]
        expanded = generator._expand_keywords(keywords)
        
        # Should not contain duplicates
        assert len(set(expanded)) == len(expanded)


class TestSubjectSpecificKeywords:
    """Test subject-specific keyword generation."""
    
    def test_crypto_keywords(self, generator):
        """Test crypto-specific keywords."""
        keywords = generator._get_fallback_keywords("crypto", 10)
        
        crypto_terms = ["blockchain", "bitcoin", "ethereum", "cryptocurrency"]
        assert any(term in " ".join(keywords).lower() for term in crypto_terms)
    
    def test_ai_keywords(self, generator):
        """Test AI-specific keywords."""
        keywords = generator._get_fallback_keywords("artificial intelligence", 10)
        
        ai_terms = ["machine learning", "neural", "tensorflow", "pytorch"]
        assert any(term in " ".join(keywords).lower() for term in ai_terms)
    
    def test_web_keywords(self, generator):
        """Test web development keywords."""
        keywords = generator._get_fallback_keywords("web development", 10)
        
        web_terms = ["javascript", "react", "vue", "angular", "frontend"]
        assert any(term in " ".join(keywords).lower() for term in web_terms)
    
    def test_unknown_subject_keywords(self, generator):
        """Test keywords for unknown subject."""
        keywords = generator._get_fallback_keywords("unknown_subject_xyz", 5)
        
        # Should still return some keywords
        assert len(keywords) > 0
        
        # Should include the subject itself
        assert any("unknown_subject_xyz" in kw.lower() for kw in keywords)
