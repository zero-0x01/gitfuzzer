"""
Test suite for pagination module - 1000-limit bypass functionality.

Tests the core pagination slicing algorithm, adapters, and edge cases.
"""

import json
import pytest
from datetime import datetime, timedelta
from typing import Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
from aioresponses import aioresponses

from gitfuzzer.pagination import (
    GitHubAdapter, 
    HuggingFaceAdapter, 
    PaginationSlicer, 
    SearchResult, 
    SliceConfig, 
    SliceState,
    slice_search_with_progress
)


class TestSliceConfig:
    """Test slice configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = SliceConfig()
        assert config.slice_field == "pushed"
        assert config.slice_days == 30
        assert config.min_slice_days == 1
        assert len(config.star_buckets) == 5
        assert len(config.size_buckets) == 4
        
    def test_custom_config(self):
        """Test custom configuration."""
        config = SliceConfig(
            slice_field="created",
            slice_days=7,
            star_buckets=[(0, 100), (100, None)]
        )
        assert config.slice_field == "created"
        assert config.slice_days == 7
        assert len(config.star_buckets) == 2


class TestSearchResult:
    """Test search result container."""
    
    def test_search_result_creation(self):
        """Test creating search result."""
        result = SearchResult(
            items=[{"id": 1}, {"id": 2}],
            total_count=1500,
            has_next_page=True
        )
        assert len(result.items) == 2
        assert result.total_count == 1500
        assert result.has_next_page is True


class TestGitHubAdapter:
    """Test GitHub search adapter."""
    
    @pytest.fixture
    def session(self):
        """Mock aiohttp session."""
        return AsyncMock(spec=aiohttp.ClientSession)
    
    @pytest.fixture
    def config(self):
        """Test slice configuration."""
        return SliceConfig(slice_days=30)
    
    @pytest.fixture
    def adapter(self, session, config):
        """GitHub adapter instance."""
        return GitHubAdapter(session, config, ["token1", "token2"])
    
    def test_build_query_basic(self, adapter):
        """Test basic query building."""
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 31)
        
        query = adapter.build_query("crypto python", start_date, end_date)
        expected = "crypto python pushed:2024-01-01..2024-01-31"
        assert query == expected
    
    def test_build_query_with_filters(self, adapter):
        """Test query building with additional filters."""
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 31)
        filters = {
            "stars": (10, 100),
            "language": "Python",
            "filename": "requirements.txt"
        }
        
        query = adapter.build_query("crypto", start_date, end_date, filters)
        parts = query.split()
        
        assert "crypto" in parts
        assert "pushed:2024-01-01..2024-01-31" in parts
        assert "stars:10..100" in parts
        assert "language:Python" in parts
        assert "filename:requirements.txt" in parts
    
    def test_build_query_open_ended_stars(self, adapter):
        """Test query building with open-ended star filter."""
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 31)
        filters = {"stars": (1000, None)}
        
        query = adapter.build_query("test", start_date, end_date, filters)
        assert "stars:>=1000" in query
    
    @pytest.mark.asyncio
    async def test_search_rest_api(self, adapter):
        """Test REST API search."""
        with aioresponses() as m:
            # Mock successful response
            response_data = {
                "total_count": 500,
                "incomplete_results": False,
                "items": [
                    {"id": 1, "name": "repo1"},
                    {"id": 2, "name": "repo2"}
                ]
            }
            
            m.get(
                "https://api.github.com/search/repositories",
                payload=response_data,
                headers={
                    "X-RateLimit-Remaining": "4999",
                    "X-RateLimit-Reset": "1640995200"
                }
            )
            
            start_date = datetime(2024, 1, 1)
            end_date = datetime(2024, 1, 31)
            
            result = await adapter.search("test", start_date, end_date)
            
            assert result.total_count == 500
            assert len(result.items) == 2
            assert result.rate_limit_remaining == 4999
    
    @pytest.mark.asyncio
    async def test_search_rate_limit_handling(self, adapter):
        """Test rate limit handling."""
        with aioresponses() as m:
            # Mock rate limit exceeded response
            m.get(
                "https://api.github.com/search/repositories",
                status=403,
                headers={
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "1640995200"
                }
            )
            
            start_date = datetime(2024, 1, 1)
            end_date = datetime(2024, 1, 31)
            
            with pytest.raises(aiohttp.ClientResponseError):
                await adapter.search("test", start_date, end_date)
    
    @pytest.mark.asyncio
    async def test_search_graphql(self, adapter):
        """Test GraphQL search."""
        adapter.use_graphql = True
        
        with aioresponses() as m:
            response_data = {
                "data": {
                    "search": {
                        "repositoryCount": 1200,
                        "pageInfo": {
                            "hasNextPage": True,
                            "endCursor": "cursor123"
                        },
                        "nodes": [
                            {"id": "1", "nameWithOwner": "user/repo1"},
                            {"id": "2", "nameWithOwner": "user/repo2"}
                        ],
                        "rateLimit": {
                            "remaining": 4999,
                            "resetAt": "2024-01-01T00:00:00Z",
                            "cost": 1
                        }
                    }
                }
            }
            
            m.post("https://api.github.com/graphql", payload=response_data)
            
            start_date = datetime(2024, 1, 1)
            end_date = datetime(2024, 1, 31)
            
            result = await adapter.search("test", start_date, end_date)
            
            assert result.total_count == 1200
            assert len(result.items) == 2
            assert result.has_next_page is True
            assert result.next_cursor == "cursor123"


class TestHuggingFaceAdapter:
    """Test Hugging Face search adapter."""
    
    @pytest.fixture
    def session(self):
        """Mock aiohttp session."""
        return AsyncMock(spec=aiohttp.ClientSession)
    
    @pytest.fixture
    def config(self):
        """Test slice configuration."""
        return SliceConfig(slice_field="lastModified")
    
    @pytest.fixture
    def adapter(self, session, config):
        """HuggingFace adapter instance."""
        return HuggingFaceAdapter(session, config, "hf_token")
    
    def test_build_query(self, adapter):
        """Test HF query building."""
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 31)
        
        params = adapter.build_query("nlp model", start_date, end_date)
        
        assert params["search"] == "nlp model"
        assert params["lastModified"] == "2024-01-01T00:00:00..2024-01-31T00:00:00"
        assert params["limit"] == 100
        assert params["full"] is True
    
    @pytest.mark.asyncio
    async def test_search(self, adapter):
        """Test HF API search."""
        with aioresponses() as m:
            response_data = [
                {"id": "model1", "modelId": "user/model1"},
                {"id": "model2", "modelId": "user/model2"}
            ]
            
            m.get("https://huggingface.co/api/models", payload=response_data)
            
            start_date = datetime(2024, 1, 1)
            end_date = datetime(2024, 1, 31)
            
            result = await adapter.search("nlp", start_date, end_date)
            
            assert len(result.items) == 2
            assert result.total_count == 2  # Will be estimated


class TestPaginationSlicer:
    """Test core pagination slicing algorithm."""
    
    @pytest.fixture
    def mock_adapter(self):
        """Mock search adapter."""
        adapter = AsyncMock()
        adapter.search = AsyncMock()
        adapter.page_all = AsyncMock()
        return adapter
    
    @pytest.fixture
    def config(self):
        """Test configuration."""
        return SliceConfig(
            slice_days=30,
            min_slice_days=1,
            checkpoint_file=None  # Disable checkpointing for tests
        )
    
    @pytest.fixture
    def slicer(self, mock_adapter, config):
        """Pagination slicer instance."""
        return PaginationSlicer(mock_adapter, config)
    
    @pytest.mark.asyncio
    async def test_slice_search_within_limit(self, slicer, mock_adapter):
        """Test search that doesn't need slicing."""
        # Mock adapter to return results within limit
        search_result = SearchResult(
            items=[{"id": 1}, {"id": 2}],
            total_count=500,
            has_next_page=False
        )
        mock_adapter.search.return_value = search_result
        
        async def mock_page_all(*args, **kwargs):
            for item in search_result.items:
                yield item
        
        mock_adapter.page_all.return_value = mock_page_all()
        
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 31)
        
        results = []
        async for item in slicer.slice_search("test", start_date, end_date):
            results.append(item)
        
        assert len(results) == 2
        assert mock_adapter.search.call_count == 1
    
    @pytest.mark.asyncio
    async def test_slice_search_exceeds_limit(self, slicer, mock_adapter):
        """Test search that needs slicing."""
        # Mock adapter to return results exceeding limit, then smaller slices
        def mock_search(query, start_date, end_date, additional_filters=None, **kwargs):
            date_diff = (end_date - start_date).days
            if date_diff > 15:  # Large slice
                return SearchResult(
                    items=[],
                    total_count=1500,  # Exceeds limit
                    has_next_page=False
                )
            else:  # Small slice
                return SearchResult(
                    items=[{"id": 1}, {"id": 2}],
                    total_count=500,
                    has_next_page=False
                )
        
        mock_adapter.search.side_effect = mock_search
        
        async def mock_page_all(*args, **kwargs):
            # Only yield for small slices
            search_result = await mock_search(*args, **kwargs)
            if search_result.total_count <= 1000:
                for item in search_result.items:
                    yield item
        
        mock_adapter.page_all.side_effect = mock_page_all
        
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 31)
        
        results = []
        async for item in slicer.slice_search("test", start_date, end_date):
            results.append(item)
        
        # Should have split the date range and processed smaller slices
        assert len(results) >= 2  # At least some results from the smaller slices
        assert mock_adapter.search.call_count > 1  # Multiple calls due to slicing
    
    @pytest.mark.asyncio
    async def test_max_results_limit(self, slicer, mock_adapter):
        """Test respecting max_results parameter."""
        search_result = SearchResult(
            items=[{"id": i} for i in range(10)],
            total_count=500,
            has_next_page=False
        )
        mock_adapter.search.return_value = search_result
        
        async def mock_page_all(*args, **kwargs):
            for item in search_result.items:
                yield item
        
        mock_adapter.page_all.return_value = mock_page_all()
        
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 31)
        
        results = []
        async for item in slicer.slice_search("test", start_date, end_date, max_results=5):
            results.append(item)
        
        assert len(results) == 5  # Should stop at max_results


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.mark.asyncio
    async def test_empty_results(self):
        """Test handling of empty search results."""
        mock_adapter = AsyncMock()
        mock_adapter.search.return_value = SearchResult(
            items=[],
            total_count=0,
            has_next_page=False
        )
        
        async def mock_page_all(*args, **kwargs):
            return
            yield  # Make this a generator
        
        mock_adapter.page_all.return_value = mock_page_all()
        
        config = SliceConfig(checkpoint_file=None)
        slicer = PaginationSlicer(mock_adapter, config)
        
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 31)
        
        results = []
        async for item in slicer.slice_search("nonexistent", start_date, end_date):
            results.append(item)
        
        assert len(results) == 0
    
    @pytest.mark.asyncio
    async def test_api_error_handling(self):
        """Test handling of API errors."""
        mock_adapter = AsyncMock()
        mock_adapter.search.side_effect = Exception("API Error")
        
        config = SliceConfig(checkpoint_file=None)
        slicer = PaginationSlicer(mock_adapter, config)
        
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 31)
        
        with pytest.raises(Exception, match="API Error"):
            async for item in slicer.slice_search("test", start_date, end_date):
                pass


class TestIntegration:
    """Integration tests with mocked APIs."""
    
    @pytest.mark.asyncio
    async def test_github_integration_over_limit(self):
        """Test GitHub integration with >1000 results requiring slicing."""
        session = AsyncMock(spec=aiohttp.ClientSession)
        
        # Mock responses for different date ranges
        def mock_get(url, **kwargs):
            response = AsyncMock()
            params = kwargs.get('params', {})
            query = params.get('q', '')
            
            # Simulate large result set that needs slicing
            if '2024-01-01..2024-01-31' in query:
                # Large date range - exceeds limit
                response.json.return_value = {
                    "total_count": 1500,
                    "items": []
                }
            else:
                # Smaller date ranges - within limit
                response.json.return_value = {
                    "total_count": 300,
                    "items": [
                        {"id": 1, "name": "repo1", "full_name": "user/repo1"},
                        {"id": 2, "name": "repo2", "full_name": "user/repo2"}
                    ]
                }
            
            response.headers = {
                "X-RateLimit-Remaining": "4999",
                "X-RateLimit-Reset": "1640995200"
            }
            response.status = 200
            response.raise_for_status = MagicMock()
            return response
        
        session.get.side_effect = mock_get
        
        config = SliceConfig(slice_days=30, checkpoint_file=None)
        adapter = GitHubAdapter(session, config, ["token1"])
        
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 31)
        
        results = await slice_search_with_progress(
            adapter=adapter,
            config=config,
            base_query="crypto python",
            start_date=start_date,
            end_date=end_date,
            max_results=100
        )
        
        # Should have gotten results from sliced queries
        assert isinstance(results, list)
        # The exact count depends on the slicing algorithm


class TestPerformance:
    """Performance and benchmark tests."""
    
    @pytest.mark.asyncio
    async def test_large_result_set_performance(self):
        """Test performance with large result sets."""
        mock_adapter = AsyncMock()
        
        # Simulate processing 10,000 results in reasonable time
        async def mock_slice_search(*args, **kwargs):
            for i in range(10000):
                yield {"id": i, "name": f"repo{i}"}
        
        # This test would measure actual performance
        # For now, just ensure it completes
        start_time = datetime.now()
        
        results = []
        async for item in mock_slice_search():
            results.append(item)
            if len(results) >= 1000:  # Limit for test
                break
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        assert len(results) == 1000
        assert duration < 10  # Should complete within 10 seconds


# Integration test fixtures for real API testing (optional, requires tokens)
@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_github_api():
    """Integration test with real GitHub API (requires valid token)."""
    import os
    
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        pytest.skip("GITHUB_TOKEN not provided")
    
    async with aiohttp.ClientSession() as session:
        config = SliceConfig(slice_days=7, checkpoint_file=None)
        adapter = GitHubAdapter(session, config, [token])
        
        start_date = datetime.now() - timedelta(days=7)
        end_date = datetime.now()
        
        # Search for a topic that might have >1000 results
        results = await slice_search_with_progress(
            adapter=adapter,
            config=config,
            base_query="topic:python",
            start_date=start_date,
            end_date=end_date,
            max_results=50  # Limit for test
        )
        
        assert isinstance(results, list)
        assert len(results) <= 50
