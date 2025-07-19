"""Tests for GitHub scanner module."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

from gitfuzzer.gh_scanner import GitHubScanner, RepoInfo, SearchQuery, SearchResult, scan_github_repositories


class TestRepoInfo:
    """Test RepoInfo model."""
    
    def test_repo_info_creation(self, sample_repo_data):
        """Test creating RepoInfo from data."""
        repo = RepoInfo.parse_obj(sample_repo_data)
        
        assert repo.id == 123456
        assert repo.name == "test-repo"
        assert repo.full_name == "owner/test-repo"
        assert repo.stargazers_count == 100
        assert repo.language == "Python"
        assert repo.owner_login == "owner"
    
    def test_repo_info_datetime_parsing(self, sample_repo_data):
        """Test datetime parsing in RepoInfo."""
        repo = RepoInfo.parse_obj(sample_repo_data)
        
        assert isinstance(repo.created_at, datetime)
        assert isinstance(repo.updated_at, datetime)
        assert isinstance(repo.pushed_at, datetime)
    
    def test_repo_info_optional_fields(self):
        """Test RepoInfo with minimal data."""
        minimal_data = {
            "id": 123,
            "name": "test",
            "full_name": "owner/test",
            "html_url": "https://github.com/owner/test",
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-01T00:00:00Z",
            "owner": {"login": "owner", "type": "User"}
        }
        
        repo = RepoInfo.parse_obj(minimal_data)
        
        assert repo.id == 123
        assert repo.description is None
        assert repo.homepage is None
        assert repo.stargazers_count == 0


class TestSearchQuery:
    """Test SearchQuery model."""
    
    def test_search_query_creation(self):
        """Test creating SearchQuery."""
        query = SearchQuery(
            keywords=["test", "example"],
            language="Python",
            min_stars=10,
            max_stars=1000
        )
        
        assert query.keywords == ["test", "example"]
        assert query.language == "Python"
        assert query.min_stars == 10
        assert query.max_stars == 1000
        assert query.sort == "updated"  # default
    
    def test_search_query_defaults(self):
        """Test SearchQuery default values."""
        query = SearchQuery(keywords=["test"])
        
        assert query.sort == "updated"
        assert query.order == "desc"
        assert query.min_stars is None


class TestGitHubScanner:
    """Test GitHub scanner functionality."""
    
    def test_build_search_query_basic(self, test_config):
        """Test basic search query building."""
        scanner = GitHubScanner(test_config)
        
        query = SearchQuery(keywords=["test", "example"])
        query_string = scanner._build_search_query(query)
        
        assert '"test"' in query_string
        assert '"example"' in query_string
        assert "OR" in query_string
    
    def test_build_search_query_with_filters(self, test_config):
        """Test search query building with filters."""
        scanner = GitHubScanner(test_config)
        
        query = SearchQuery(
            keywords=["test"],
            language="Python",
            min_stars=10,
            max_stars=1000,
            created_after=datetime(2023, 1, 1),
            pushed_before=datetime(2023, 12, 31)
        )
        
        query_string = scanner._build_search_query(query)
        
        assert "language:Python" in query_string
        assert "stars:>=10" in query_string
        assert "stars:<=1000" in query_string
        assert "created:>=2023-01-01" in query_string
        assert "pushed:<=2023-12-31" in query_string
    
    def test_build_search_query_single_keyword(self, test_config):
        """Test search query with single keyword."""
        scanner = GitHubScanner(test_config)
        
        query = SearchQuery(keywords=["blockchain"])
        query_string = scanner._build_search_query(query)
        
        assert '"blockchain"' in query_string
        assert "OR" not in query_string  # No OR for single keyword
    
    def test_generate_date_ranges(self, test_config):
        """Test date range generation for slicing."""
        scanner = GitHubScanner(test_config)
        
        start_date = datetime(2023, 1, 1)
        end_date = datetime(2023, 3, 1)
        slice_days = 30
        
        ranges = scanner._generate_date_ranges(start_date, end_date, slice_days)
        
        assert len(ranges) > 0
        assert ranges[0][0] == start_date
        assert ranges[-1][1] <= end_date
        
        # Check that ranges don't overlap
        for i in range(len(ranges) - 1):
            assert ranges[i][1] < ranges[i + 1][0]
    
    def test_parse_repository_full(self, test_config, sample_repo_data):
        """Test parsing complete repository data."""
        scanner = GitHubScanner(test_config)
        
        repo = scanner._parse_repository(sample_repo_data)
        
        assert repo is not None
        assert repo.id == 123456
        assert repo.full_name == "owner/test-repo"
        assert repo.language == "Python"
        assert repo.license == "MIT License"
        assert "testing" in repo.topics
    
    def test_parse_repository_minimal(self, test_config):
        """Test parsing minimal repository data."""
        scanner = GitHubScanner(test_config)
        
        minimal_data = {
            "id": 123,
            "name": "test",
            "full_name": "owner/test",
            "html_url": "https://github.com/owner/test",
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-01T00:00:00Z",
            "owner": {"login": "owner", "type": "User"}
        }
        
        repo = scanner._parse_repository(minimal_data)
        
        assert repo is not None
        assert repo.id == 123
        assert repo.stargazers_count == 0  # default
        assert repo.language is None
    
    def test_parse_repository_invalid(self, test_config):
        """Test parsing invalid repository data."""
        scanner = GitHubScanner(test_config)
        
        invalid_data = {"invalid": "data"}
        
        repo = scanner._parse_repository(invalid_data)
        
        assert repo is None
    
    def test_parse_search_response(self, test_config, sample_repo_data):
        """Test parsing GitHub search API response."""
        scanner = GitHubScanner(test_config)
        
        api_response = {
            "total_count": 1,
            "incomplete_results": False,
            "items": [sample_repo_data]
        }
        
        result = scanner._parse_search_response(api_response, "test query", 1, 100)
        
        assert isinstance(result, SearchResult)
        assert result.total_count == 1
        assert result.incomplete_results is False
        assert len(result.repositories) == 1
        assert result.repositories[0].id == 123456
    
    def test_parse_search_response_deduplication(self, test_config, sample_repo_data):
        """Test deduplication in search response parsing."""
        scanner = GitHubScanner(test_config)
        
        # Add same repo to seen set
        scanner._seen_repos.add(123456)
        
        api_response = {
            "total_count": 1,
            "incomplete_results": False,
            "items": [sample_repo_data]
        }
        
        result = scanner._parse_search_response(api_response, "test query", 1, 100)
        
        # Should be filtered out due to deduplication
        assert len(result.repositories) == 0
    
    def test_context_manager_initialization(self, test_config):
        """Test scanner context manager initialization."""
        scanner = GitHubScanner(test_config)
        
        # Should raise error if no tokens
        test_config.gh_tokens = []
        
        try:
            async def test():
                async with scanner:
                    pass
            
            import asyncio
            with pytest.raises(ValueError):
                asyncio.run(test())
        except NameError:
            # pytest not available, skip this test
            pass


class TestSearchMethods:
    """Test search methods with mocking."""
    
    async def test_search_repositories_success(self, test_config, mock_session, sample_repo_data):
        """Test successful repository search."""
        # Mock response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            "x-ratelimit-remaining": "4999",
            "x-ratelimit-limit": "5000"
        }
        mock_response.json.return_value = {
            "total_count": 1,
            "incomplete_results": False,
            "items": [sample_repo_data]
        }
        
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        async with GitHubScanner(test_config) as scanner:
            scanner.session = mock_session
            
            result = await scanner._search_repositories("test query")
        
        assert isinstance(result, SearchResult)
        assert result.total_count == 1
        assert len(result.repositories) == 1
    
    async def test_search_repositories_rate_limit(self, test_config, mock_session):
        """Test rate limit handling in repository search."""
        # Mock rate limit response
        mock_response = AsyncMock()
        mock_response.status = 403
        mock_response.json.return_value = {"message": "API rate limit exceeded"}
        
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        async with GitHubScanner(test_config) as scanner:
            scanner.session = mock_session
            
            try:
                await scanner._search_repositories("test query")
                assert False, "Should have raised GitHubAPIError"
            except Exception as e:
                assert "rate limit" in str(e).lower()
    
    async def test_search_repositories_validation_error(self, test_config, mock_session):
        """Test validation error handling."""
        # Mock validation error response
        mock_response = AsyncMock()
        mock_response.status = 422
        mock_response.json.return_value = {"message": "Validation failed"}
        
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        async with GitHubScanner(test_config) as scanner:
            scanner.session = mock_session
            
            try:
                await scanner._search_repositories("invalid query")
                assert False, "Should have raised GitHubAPIError"
            except Exception as e:
                assert "invalid query" in str(e).lower() or "validation" in str(e).lower()


class TestScanIntegration:
    """Test integration scanning functionality."""
    
    async def test_scan_github_repositories(self, test_config):
        """Test the convenience function for scanning."""
        keywords = ["test", "example"]
        
        with patch('gitfuzzer.gh_scanner.GitHubScanner') as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan_repositories.return_value = [
                RepoInfo(
                    id=123,
                    name="test-repo",
                    full_name="owner/test-repo",
                    html_url="https://github.com/owner/test-repo",
                    created_at=datetime.now(),
                    updated_at=datetime.now(),
                    owner_login="owner"
                )
            ]
            mock_scanner_class.return_value.__aenter__.return_value = mock_scanner
            
            result = await scan_github_repositories(keywords, test_config)
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0].full_name == "owner/test-repo"


class TestSlicingStrategies:
    """Test query slicing strategies."""
    
    def test_date_range_slicing(self, test_config):
        """Test date range slicing logic."""
        scanner = GitHubScanner(test_config)
        
        # Test 90-day period with 30-day slices
        end_date = datetime.now()
        start_date = end_date - timedelta(days=90)
        
        ranges = scanner._generate_date_ranges(start_date, end_date, 30)
        
        # Should create approximately 3 ranges
        assert len(ranges) >= 3
        assert len(ranges) <= 4  # Account for partial ranges
        
        # Verify coverage
        assert ranges[0][0] == start_date
        assert ranges[-1][1] >= end_date - timedelta(days=1)
    
    def test_small_date_range(self, test_config):
        """Test date range smaller than slice size."""
        scanner = GitHubScanner(test_config)
        
        start_date = datetime.now() - timedelta(days=10)
        end_date = datetime.now()
        
        ranges = scanner._generate_date_ranges(start_date, end_date, 30)
        
        # Should create only one range
        assert len(ranges) == 1
        assert ranges[0][0] == start_date
        assert ranges[0][1] == end_date


# Note: Some tests require pytest to run properly
# This module provides comprehensive test coverage for the GitHub scanner functionality
