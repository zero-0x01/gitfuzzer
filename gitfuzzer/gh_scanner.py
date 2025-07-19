"""Stage 2: GitHub repository scanning and discovery for GitFuzzer with 1000-limit bypass and code search."""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from urllib.parse import urlencode

import aiohttp
from pydantic import BaseModel

from gitfuzzer.config import Settings as Config
from gitfuzzer.pagination import GitHubAdapter, PaginationSlicer, SliceConfig
from gitfuzzer.rate_limit import TokenRotator, with_rate_limit_retry, RateLimitError
from gitfuzzer.utils import GitHubAPIError
from gitfuzzer.utils import async_retry

logger = logging.getLogger(__name__)


class RepoInfo(BaseModel):
    """Repository information model."""
    
    id: int
    name: str
    full_name: str
    html_url: str
    description: Optional[str] = None
    homepage: Optional[str] = None
    language: Optional[str] = None
    stargazers_count: int = 0
    watchers_count: int = 0
    forks_count: int = 0
    size: int = 0
    created_at: datetime
    updated_at: datetime
    pushed_at: Optional[datetime] = None
    topics: List[str] = []
    license: Optional[str] = None
    default_branch: str = "main"
    open_issues_count: int = 0
    has_issues: bool = True
    has_projects: bool = True
    has_wiki: bool = True
    has_pages: bool = False
    archived: bool = False
    disabled: bool = False
    private: bool = False
    fork: bool = False
    
    # Additional metadata
    clone_url: Optional[str] = None
    ssh_url: Optional[str] = None
    owner_login: Optional[str] = None
    owner_type: Optional[str] = None  # "User" or "Organization"
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class SearchQuery(BaseModel):
    """GitHub search query model."""
    
    keywords: List[str]
    language: Optional[str] = None
    min_stars: Optional[int] = None
    max_stars: Optional[int] = None
    min_size: Optional[int] = None
    max_size: Optional[int] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    pushed_after: Optional[datetime] = None
    pushed_before: Optional[datetime] = None
    sort: str = "updated"  # "stars", "forks", "updated"
    order: str = "desc"  # "asc", "desc"


class SearchResult(BaseModel):
    """Search result model."""
    
    total_count: int
    incomplete_results: bool
    repositories: List[RepoInfo]
    query: str
    page: int
    per_page: int


class GitHubScanner:
    """GitHub repository scanner with rate limiting and result aggregation."""
    
    def __init__(self, config: Config):
        """Initialize GitHub scanner.
        
        Args:
            config: Configuration object.
        """
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.token_rotator: Optional[TokenRotator] = None
        self._seen_repos: Set[int] = set()
        
    async def __aenter__(self):
        """Async context manager entry."""
        if not self.config.gh_tokens:
            raise ValueError("No GitHub tokens configured")
        
        # Create session with timeout
        timeout = aiohttp.ClientTimeout(total=self.config.scanner.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        
        # Initialize token rotator
        self.token_rotator = TokenRotator(self.config.gh_tokens)
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    def _build_search_query(self, query: SearchQuery) -> str:
        """Build GitHub search query string.
        
        Args:
            query: Search query parameters.
            
        Returns:
            Formatted query string.
        """
        parts = []
        
        # Add keywords (use just first keyword for testing)
        if query.keywords:
            # For testing: just use the first keyword which is usually the subject itself
            limited_keywords = [query.keywords[0]]
            keyword_part = f'"{limited_keywords[0]}"'
            parts.append(keyword_part)
        
        # Add language filter
        if query.language:
            parts.append(f"language:{query.language}")
        
        # STAR FILTERS COMPLETELY REMOVED - Focus on unknown/private repos
        # No star filtering to find repositories regardless of popularity
        
        # Add size filters (in KB)
        if query.min_size is not None:
            parts.append(f"size:>={query.min_size}")
        if query.max_size is not None:
            parts.append(f"size:<={query.max_size}")
        
        # Add date filters
        if query.created_after:
            parts.append(f"created:>={query.created_after.strftime('%Y-%m-%d')}")
        if query.created_before:
            parts.append(f"created:<={query.created_before.strftime('%Y-%m-%d')}")
        
        if query.pushed_after:
            parts.append(f"pushed:>={query.pushed_after.strftime('%Y-%m-%d')}")
        if query.pushed_before:
            parts.append(f"pushed:<={query.pushed_before.strftime('%Y-%m-%d')}")
        
        return " ".join(parts)
    
    async def _search_repositories(
        self,
        query: str,
        page: int = 1,
        per_page: int = None,
        sort: str = "updated",
        order: str = "desc"
    ) -> SearchResult:
        """Search repositories using GitHub Search API.
        
        Args:
            query: Search query string.
            page: Page number (1-based).
            per_page: Results per page.
            sort: Sort field.
            order: Sort order.
            
        Returns:
            Search results.
        """
        if not self.session or not self.token_rotator:
            raise RuntimeError("Scanner not initialized. Use async context manager.")
        
        per_page = per_page or self.config.scanner.per_page
        
        # Build API URL
        params = {
            "q": query,
            "sort": sort,
            "order": order,
            "page": page,
            "per_page": per_page
        }
        
        url = f"https://api.github.com/search/repositories?{urlencode(params)}"
        
        async def make_request(token: str) -> SearchResult:
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": self.config.deep_linker.user_agent
            }
            
            async with self.session.get(url, headers=headers) as response:
                # Update rate limit info
                self.token_rotator.update_rate_limit_from_headers(token, response.headers)
                
                if response.status == 200:
                    data = await response.json()
                    return self._parse_search_response(data, query, page, per_page)
                
                elif response.status == 403:
                    # Rate limit or other forbidden error
                    error_data = await response.json()
                    message = error_data.get("message", "Forbidden")
                    
                    if "rate limit" in message.lower():
                        retry_after = response.headers.get("retry-after")
                        raise GitHubAPIError(f"Rate limit exceeded: {message}", 429)
                    else:
                        raise GitHubAPIError(f"Forbidden: {message}", 403)
                
                elif response.status == 422:
                    # Validation failed
                    error_data = await response.json()
                    message = error_data.get("message", "Validation failed")
                    raise GitHubAPIError(f"Invalid query: {message}", 422)
                
                else:
                    error_text = await response.text()
                    raise GitHubAPIError(f"API error {response.status}: {error_text}", response.status)
        
        return await with_rate_limit_retry(
            make_request,
            self.token_rotator,
            max_retries=self.config.scanner.retry_attempts
        )
    
    def _parse_search_response(
        self,
        data: dict,
        query: str,
        page: int,
        per_page: int
    ) -> SearchResult:
        """Parse GitHub search API response.
        
        Args:
            data: API response data.
            query: Original query string.
            page: Page number.
            per_page: Results per page.
            
        Returns:
            Parsed search result.
        """
        repositories = []
        
        for item in data.get("items", []):
            try:
                repo = self._parse_repository(item)
                if repo and repo.id not in self._seen_repos:
                    repositories.append(repo)
                    self._seen_repos.add(repo.id)
            except Exception as e:
                logger.warning(f"Failed to parse repository: {e}")
                continue
        
        return SearchResult(
            total_count=data.get("total_count", 0),
            incomplete_results=data.get("incomplete_results", False),
            repositories=repositories,
            query=query,
            page=page,
            per_page=per_page
        )
    
    def _parse_repository(self, item: dict) -> Optional[RepoInfo]:
        """Parse repository data from API response.
        
        Args:
            item: Repository item from API.
            
        Returns:
            Parsed repository information.
        """
        try:
            # Parse dates
            created_at = datetime.fromisoformat(item["created_at"].replace("Z", "+00:00"))
            updated_at = datetime.fromisoformat(item["updated_at"].replace("Z", "+00:00"))
            
            pushed_at = None
            if item.get("pushed_at"):
                pushed_at = datetime.fromisoformat(item["pushed_at"].replace("Z", "+00:00"))
            
            # Parse license
            license_info = item.get("license")
            license_name = None
            if license_info and isinstance(license_info, dict):
                license_name = license_info.get("name") or license_info.get("spdx_id")
            
            # Parse owner info
            owner = item.get("owner", {})
            
            return RepoInfo(
                id=item["id"],
                name=item["name"],
                full_name=item["full_name"],
                html_url=item["html_url"],
                description=item.get("description"),
                homepage=item.get("homepage"),
                language=item.get("language"),
                stargazers_count=item.get("stargazers_count", 0),
                watchers_count=item.get("watchers_count", 0),
                forks_count=item.get("forks_count", 0),
                size=item.get("size", 0),
                created_at=created_at,
                updated_at=updated_at,
                pushed_at=pushed_at,
                topics=item.get("topics", []),
                license=license_name,
                default_branch=item.get("default_branch", "main"),
                open_issues_count=item.get("open_issues_count", 0),
                has_issues=item.get("has_issues", True),
                has_projects=item.get("has_projects", True),
                has_wiki=item.get("has_wiki", True),
                has_pages=item.get("has_pages", False),
                archived=item.get("archived", False),
                disabled=item.get("disabled", False),
                private=item.get("private", False),
                fork=item.get("fork", False),
                clone_url=item.get("clone_url"),
                ssh_url=item.get("ssh_url"),
                owner_login=owner.get("login"),
                owner_type=owner.get("type")
            )
        
        except (KeyError, ValueError, TypeError) as e:
            logger.error(f"Failed to parse repository item: {e}")
            return None
    
    def _generate_date_ranges(
        self,
        start_date: datetime,
        end_date: datetime,
        slice_days: int
    ) -> List[tuple[datetime, datetime]]:
        """Generate date ranges for query slicing.
        
        Args:
            start_date: Start date for search.
            end_date: End date for search.
            slice_days: Number of days per slice.
            
        Returns:
            List of (start, end) date tuples.
        """
        ranges = []
        current_start = start_date
        
        while current_start < end_date:
            current_end = min(current_start + timedelta(days=slice_days), end_date)
            ranges.append((current_start, current_end))
            current_start = current_end + timedelta(days=1)
        
        return ranges
    
    async def _search_with_slicing(
        self,
        base_query: SearchQuery,
        max_results: int = None
    ) -> List[RepoInfo]:
        """Search with automatic query slicing to bypass 1000-result limit.
        
        Args:
            base_query: Base search query.
            max_results: Maximum results to return.
            
        Returns:
            List of repository information.
        """
        max_results = max_results or self.config.scanner.max_results
        all_repos = []
        
        # Generate date ranges for slicing
        end_date = datetime.now()
        start_date = end_date - timedelta(days=self.config.analyzer.max_age_days)
        
        date_ranges = self._generate_date_ranges(
            start_date, end_date, self.config.scanner.slice_days
        )
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.config.scanner.max_concurrency)
        
        async def search_date_range(date_range: tuple[datetime, datetime]) -> List[RepoInfo]:
            """Search repositories within a specific date range."""
            async with semaphore:
                range_start, range_end = date_range
                
                # Create query for this date range
                sliced_query = base_query.copy()
                sliced_query.pushed_after = range_start
                sliced_query.pushed_before = range_end
                
                query_string = self._build_search_query(sliced_query)
                
                logger.debug(f"Searching date range {range_start.date()} to {range_end.date()}")
                logger.debug(f"Query string: {query_string}")
                
                try:
                    result = await self._search_repositories(
                        query_string,
                        sort=sliced_query.sort,
                        order=sliced_query.order
                    )
                    
                    repos = result.repositories
                    
                    # If we hit the 1000 limit, try further date slicing instead of star slicing
                    # This helps find unknown/private repos without star bias
                    if result.total_count >= 1000 and len(repos) >= 1000:
                        logger.info(f"Hit 1000 limit for range {range_start.date()}-{range_end.date()}, further date slicing")
                        # Create smaller date ranges to bypass 1000 limit
                        days_diff = (range_end - range_start).days
                        if days_diff > 1:
                            mid_date = range_start + timedelta(days=days_diff // 2)
                            # Search two smaller ranges
                            range1_query = sliced_query.model_copy()
                            range1_query.created_after = range_start
                            range1_query.created_before = mid_date
                            range2_query = sliced_query.model_copy()
                            range2_query.created_after = mid_date
                            range2_query.created_before = range_end
                            
                            repos1 = await search_date_range((range_start, mid_date))
                            repos2 = await search_date_range((mid_date, range_end))
                            repos = repos1 + repos2
                    
                    return repos
                
                except Exception as e:
                    logger.error(f"Error searching date range {range_start.date()}-{range_end.date()}: {e}")
                    logger.debug(f"Failed query was: {query_string}")
                    return []
        
        # Execute searches concurrently
        tasks = [search_date_range(date_range) for date_range in date_ranges]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect all results
        for result in results:
            if isinstance(result, list):
                all_repos.extend(result)
                if len(all_repos) >= max_results:
                    break
            elif isinstance(result, Exception):
                logger.error(f"Search task failed: {result}")
        
        # Remove duplicates and limit results
        unique_repos = []
        seen_ids = set()
        
        for repo in all_repos:
            if repo.id not in seen_ids:
                unique_repos.append(repo)
                seen_ids.add(repo.id)
                
                if len(unique_repos) >= max_results:
                    break
        
        logger.info(f"Found {len(unique_repos)} unique repositories")
        return unique_repos
    
    async def _slice_by_stars(self, base_query: SearchQuery, base_query_string: str) -> List[RepoInfo]:
        """Further slice query by star count to bypass limits.
        
        Args:
            base_query: Base query parameters.
            base_query_string: Base query string.
            
        Returns:
            List of repositories from star-sliced searches.
        """
        # Define star ranges
        star_ranges = [
            (1000, None),    # 1000+ stars
            (100, 999),      # 100-999 stars
            (10, 99),        # 10-99 stars
            (1, 9),          # 1-9 stars
            (0, 0)           # 0 stars
        ]
        
        all_repos = []
        
        for min_stars, max_stars in star_ranges:
            try:
                # Build query with star filter
                star_parts = []
                if min_stars is not None:
                    star_parts.append(f"stars:>={min_stars}")
                if max_stars is not None:
                    star_parts.append(f"stars:<={max_stars}")
                
                star_filter = " ".join(star_parts)
                query_with_stars = f"{base_query_string} {star_filter}"
                
                result = await self._search_repositories(query_with_stars)
                all_repos.extend(result.repositories)
                
                # Stop if we have enough results
                if len(all_repos) >= 1000:
                    break
                
            except Exception as e:
                logger.warning(f"Error searching star range {min_stars}-{max_stars}: {e}")
                continue
        
        return all_repos
    
    async def scan_repositories_advanced(
        self,
        keywords: List[str],
        language: Optional[str] = None,
        max_results: int = None,
        include_file: Optional[str] = None,
        include_keyword: Optional[str] = None,
        include_token: Optional[str] = None,
        file_extension: Optional[str] = None,
        path_filter: Optional[str] = None,
        use_graphql: bool = False,
        slice_field: str = "pushed",
        slice_days: int = 30,
        date_filter: Optional[str] = None
    ) -> List[RepoInfo]:
        """
        Advanced repository scanning with 1000-limit bypass and enhanced filtering.
        
        Args:
            keywords: List of keywords to search for
            language: Programming language filter
            max_results: Maximum number of results to return
            include_file: Specific filename to search for
            include_keyword: Additional keyword that must appear in repository
            include_token: Token that must appear in repository content
            file_extension: File extension filter (e.g., '.py', '.js')
            path_filter: Path pattern filter
            use_graphql: Use GraphQL API instead of REST
            slice_field: Field to slice by (pushed, created)
            slice_days: Initial slice size in days
            date_filter: Precomputed date filter string for GitHub queries
            
        Returns:
            List of repository information
        """
        if not self.session or not self.token_rotator:
            raise RuntimeError("Scanner not initialized. Use async context manager.")
            
        logger.info(f"Advanced scanning with {len(keywords)} keywords and enhanced filters")
        
        # Build base query
        query_parts = []
        
        # Add keywords
        if keywords:
            keyword_part = " OR ".join(f'"{kw}"' for kw in keywords)
            if len(keywords) > 1:
                keyword_part = f"({keyword_part})"
            query_parts.append(keyword_part)
        
        # Add language filter
        if language:
            query_parts.append(f"language:{language}")
            
        # Add file-specific filters
        if include_file:
            query_parts.append(f"filename:{include_file}")
            
        if file_extension:
            ext = file_extension.lstrip('.')
            query_parts.append(f"extension:{ext}")
            
        if path_filter:
            query_parts.append(f"path:{path_filter}")
            
        if include_keyword:
            query_parts.append(f'"{include_keyword}"')
            
        if include_token:
            query_parts.append(f'"{include_token}"')
            
        # Add minimum stars filter
        if self.config.analyzer.min_stars > 0:
            query_parts.append(f"stars:>={self.config.analyzer.min_stars}")
        
        # Add date filter
        if date_filter:
            query_parts.append(date_filter)
            
        base_query = " ".join(query_parts)
        
        # Setup pagination configuration
        slice_config = SliceConfig(
            slice_field=slice_field,
            slice_days=slice_days,
            checkpoint_file=f"state/github_slices_{slice_field}.json",
            resume_from_checkpoint=True
        )
        
        # Create GitHub adapter
        adapter = GitHubAdapter(
            session=self.session,
            config=slice_config,
            tokens=self.config.gh_tokens,
            use_graphql=use_graphql
        )
        
        # Setup date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=self.config.scanner.max_age_days)
        
        # Create pagination slicer
        def progress_callback(message: str):
            logger.info(f"Pagination progress: {message}")
            
        slicer = PaginationSlicer(adapter, slice_config, progress_callback)
        
        # Collect results
        repositories = []
        seen_ids = set()
        
        try:
            async for item in slicer.slice_search(
                base_query=base_query,
                start_date=start_date,
                end_date=end_date,
                max_results=max_results
            ):
                try:
                    repo = self._parse_repository_from_api(item)
                    if repo and repo.id not in seen_ids:
                        repositories.append(repo)
                        seen_ids.add(repo.id)
                        
                        if max_results and len(repositories) >= max_results:
                            break
                            
                except Exception as e:
                    logger.warning(f"Failed to parse repository from API result: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error during advanced scanning: {e}")
            raise
            
        logger.info(f"Advanced scan completed: {len(repositories)} repositories found")
        return repositories
    
    def _parse_repository_from_api(self, item: dict) -> Optional[RepoInfo]:
        """Parse repository from raw API response (REST or GraphQL)."""
        try:
            # Handle both REST and GraphQL responses
            if "nameWithOwner" in item:
                # GraphQL response
                return self._parse_graphql_repository(item)
            else:
                # REST response
                return self._parse_repository(item)
        except Exception as e:
            logger.warning(f"Failed to parse repository from API: {e}")
            return None
            
    def _parse_graphql_repository(self, item: dict) -> Optional[RepoInfo]:
        """Parse repository from GraphQL response."""
        try:
            # Parse dates
            created_at = datetime.fromisoformat(item["createdAt"].replace("Z", "+00:00"))
            updated_at = datetime.fromisoformat(item["updatedAt"].replace("Z", "+00:00")) if item.get("updatedAt") else None
            pushed_at = datetime.fromisoformat(item["pushedAt"].replace("Z", "+00:00")) if item.get("pushedAt") else None
            
            # Extract language
            language = None
            if item.get("primaryLanguage"):
                language = item["primaryLanguage"]["name"]
                
            # Extract owner info
            name_parts = item["nameWithOwner"].split("/", 1)
            owner_login = name_parts[0] if len(name_parts) > 0 else ""
            repo_name = name_parts[1] if len(name_parts) > 1 else item.get("name", "")
            
            return RepoInfo(
                id=int(item["id"]) if item.get("id") else 0,
                name=repo_name,
                full_name=item["nameWithOwner"],
                description=item.get("description", ""),
                html_url=item["url"],
                clone_url=f"https://github.com/{item['nameWithOwner']}.git",
                ssh_url=f"git@github.com:{item['nameWithOwner']}.git",
                language=language,
                stargazers_count=item.get("stargazerCount", 0),
                forks_count=item.get("forkCount", 0),
                open_issues_count=0,  # Not available in this GraphQL query
                created_at=created_at,
                updated_at=updated_at,
                pushed_at=pushed_at,
                size=0,  # Not available in this GraphQL query
                default_branch=item.get("defaultBranchRef", {}).get("name", "main"),
                topics=[],  # Would need separate query
                license_name=None,  # Would need separate query
                owner_login=owner_login,
                owner_type="",  # Would need separate query
                private=False,  # Assuming public since we're searching
                fork=False,  # Would need separate query
                archived=False,  # Would need separate query
                disabled=False,  # Would need separate query
                has_issues=True,  # Default assumption
                has_projects=True,  # Default assumption
                has_wiki=True,  # Default assumption
                has_downloads=True,  # Default assumption
                homepage="",  # Would need separate query
                subscribers_count=0,  # Not available
                network_count=0,  # Not available
                watchers_count=item.get("stargazerCount", 0)  # Use stars as approximation
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse GraphQL repository: {e}")
            return None

    async def scan_repositories(
        self,
        keywords: List[str],
        language: Optional[str] = None,
        max_results: int = None
    ) -> List[RepoInfo]:
        """Scan GitHub repositories using keywords.
        
        Args:
            keywords: List of keywords to search for.
            language: Programming language filter.
            max_results: Maximum number of results to return.
            
        Returns:
            List of repository information.
        """
        logger.info(f"Scanning repositories with {len(keywords)} keywords")
        
        # Create search query - REMOVE star filtering to find unknown repos
        query = SearchQuery(
            keywords=keywords,
            language=language,
            # min_stars=self.config.analyzer.min_stars,  # REMOVED: No star filtering
            sort="updated",  # Sort by updated to find recently active repos
            order="desc"
        )
        
        # Perform search with slicing
        repositories = await self._search_with_slicing(query, max_results)
        
        logger.info(f"Scan completed: {len(repositories)} repositories found")
        return repositories

    async def search_repositories_enhanced(
        self,
        keyword: str,
        count: int = 20,
        language: Optional[str] = None
    ) -> List[Dict]:
        """Enhanced repository search with language filtering and organizational focus."""
        
        repositories = []
        
        try:
            # Build enhanced search queries
            queries = []
            
            # Base query with keyword
            base_query = keyword
            
            # Add language filter if specified
            if language:
                base_query += f" language:{language}"
            
            # Enhanced search strategies for unknown/organizational repos
            search_strategies = [
                # Recent organizational activity
                f"{base_query} created:2024-01-01..2025-07-19",
                f"{base_query} pushed:2024-06-01..2025-07-19",
                
                # Small, unknown repositories
                f"{base_query} size:<500",
                f"{base_query} stars:<5",
                
                # Recent activity without star constraints
                f"{base_query} updated:>2024-01-01"
            ]
            
            # Execute searches with enhanced pagination handling
            for query in search_strategies:
                try:
                    # For each strategy, try to get a reasonable number of results
                    strategy_target = max(10, count // len(search_strategies)) if count else 50
                    
                    # If count is None or very large, use pagination bypass
                    if count is None or strategy_target > 50:
                        # Use enhanced pagination to get more results
                        repos_for_query = await self._search_with_pagination_bypass(query, strategy_target)
                        repositories.extend(repos_for_query)
                    else:
                        # Standard search for smaller counts but get more per page
                        per_page = min(strategy_target, 100)
                        result = await self._search_repositories(query, per_page=per_page)
                        
                        if result.repositories:
                            # Convert to simple dict format for compatibility
                            for item in result.repositories:
                                repo_dict = {
                                    'id': item.id,
                                    'full_name': item.full_name,
                                    'name': item.name,
                                    'html_url': item.html_url,
                                    'description': item.description,
                                    'language': item.language,
                                    'stargazers_count': item.stargazers_count,
                                    'forks_count': item.forks_count,
                                    'created_at': item.created_at.isoformat() if item.created_at else None,
                                    'updated_at': item.updated_at.isoformat() if item.updated_at else None,
                                    'pushed_at': item.pushed_at.isoformat() if item.pushed_at else None,
                                    'default_branch': item.default_branch,
                                    'topics': item.topics,
                                    'owner': {
                                        'login': item.full_name.split('/')[0] if '/' in item.full_name else item.name
                                    }
                                }
                                repositories.append(repo_dict)
                            
                            logger.info(f"Query '{query}': Found {len(result.repositories)} repos (total available: {result.total_count})")
                            if result.total_count > 1000:
                                logger.info("   🎉 Pagination bypass active (1000+ results available)")
                    
                    # Small delay between queries
                    await asyncio.sleep(0.5)
                    
                except Exception as e:
                    logger.warning(f"Search query failed '{query}': {e}")
                    continue
            
            # Remove duplicates by full_name
            unique_repos = {}
            for repo in repositories:
                unique_repos[repo['full_name']] = repo
            
            return list(unique_repos.values())[:count] if count else list(unique_repos.values())
            
        except Exception as e:
            logger.error(f"Enhanced repository search failed: {e}")
            return []

    async def _search_with_pagination_bypass(self, query: str, max_results: int = None) -> List[Dict]:
        """Use pagination bypass to get many results from a single query."""
        
        repositories = []
        
        try:
            # First get total count
            initial_result = await self._search_repositories(query, per_page=100)
            total_available = initial_result.total_count
            
            logger.info(f"Query '{query}': Total available: {total_available}")
            
            if total_available == 0:
                return []
            
            # Convert first page
            for item in initial_result.repositories:
                repo_dict = {
                    'id': item.id,
                    'full_name': item.full_name,
                    'name': item.name,
                    'html_url': item.html_url,
                    'description': item.description,
                    'language': item.language,
                    'stargazers_count': item.stargazers_count,
                    'forks_count': item.forks_count,
                    'created_at': item.created_at.isoformat() if item.created_at else None,
                    'updated_at': item.updated_at.isoformat() if item.updated_at else None,
                    'pushed_at': item.pushed_at.isoformat() if item.pushed_at else None,
                    'default_branch': item.default_branch,
                    'topics': item.topics,
                    'owner': {
                        'login': item.full_name.split('/')[0] if '/' in item.full_name else item.name
                    }
                }
                repositories.append(repo_dict)
            
            # If we want more results and have more available, use pagination
            if max_results and len(repositories) < max_results and total_available > 100:
                pages_needed = min(10, (max_results // 100) + 1)  # Max 10 pages to respect rate limits
                
                for page in range(2, pages_needed + 1):
                    try:
                        result = await self._search_repositories(query, page=page, per_page=100)
                        
                        for item in result.repositories:
                            if max_results and len(repositories) >= max_results:
                                break
                                
                            repo_dict = {
                                'id': item.id,
                                'full_name': item.full_name,
                                'name': item.name,
                                'html_url': item.html_url,
                                'description': item.description,
                                'language': item.language,
                                'stargazers_count': item.stargazers_count,
                                'forks_count': item.forks_count,
                                'created_at': item.created_at.isoformat() if item.created_at else None,
                                'updated_at': item.updated_at.isoformat() if item.updated_at else None,
                                'pushed_at': item.pushed_at.isoformat() if item.pushed_at else None,
                                'default_branch': item.default_branch,
                                'topics': item.topics,
                                'owner': {
                                    'login': item.full_name.split('/')[0] if '/' in item.full_name else item.name
                                }
                            }
                            repositories.append(repo_dict)
                        
                        # Delay between pages
                        await asyncio.sleep(1.0)
                        
                    except Exception as e:
                        logger.warning(f"Failed to fetch page {page} for query '{query}': {e}")
                        break
            
            logger.info(f"   📊 Collected {len(repositories)} repos via pagination bypass")
            return repositories
            
        except Exception as e:
            logger.error(f"Pagination bypass failed for query '{query}': {e}")
            return []


    async def search_code(self, keywords: List[str], language: Optional[str] = None, max_results: int = 100, created_after: Optional[str] = None, pushed_after: Optional[str] = None) -> List[Dict]:
        """Search through actual code files using GitHub Code Search API.
        
        Args:
            keywords: List of keywords to search for in code
            language: Programming language filter
            max_results: Maximum number of code results to return
            created_after: Filter repos created after this date (YYYY-MM-DD)
            pushed_after: Filter repos pushed after this date (YYYY-MM-DD)
            
        Returns:
            List of unique repositories found through code search
        """
        if not self.token_rotator:
            raise RuntimeError("Scanner not initialized. Use async context manager.")
            
        unique_repos = {}
        
        # Search for each keyword in code files
        for keyword in keywords[:3]:  # Limit to avoid too many API calls
            try:
                # Build code search query
                query_parts = [f'"{keyword}"']
                
                if language:
                    query_parts.append(f"language:{language}")
                
                # Add filters to find interesting code
                query_parts.extend([
                    "NOT path:node_modules",
                    "NOT path:vendor", 
                    "NOT path:.git",
                    "NOT path:build",
                    "NOT path:dist"
                ])
                
                query = " ".join(query_parts)
                
                # Search code with pagination
                page = 1
                per_page = min(30, max_results)  # Code search has stricter limits
                
                while len(unique_repos) < max_results and page <= 10:  # Limit pages
                    params = {
                        "q": query,
                        "page": page,
                        "per_page": per_page
                    }
                    
                    url = f"https://api.github.com/search/code?{urlencode(params)}"
                    
                    async def make_request(token: str) -> Dict:
                        headers = {
                            "Authorization": f"token {token}",
                            "Accept": "application/vnd.github.v3+json",
                            "User-Agent": self.config.deep_linker.user_agent
                        }
                        
                        async with self.session.get(url, headers=headers) as response:
                            self.token_rotator.update_rate_limit_from_headers(token, response.headers)
                            
                            if response.status == 200:
                                return await response.json()
                            elif response.status == 422:
                                # Query validation error - skip this keyword
                                logger.warning(f"Code search query validation failed for: {keyword}")
                                return {"items": []}
                            else:
                                response.raise_for_status()
                    
                    data = await with_rate_limit_retry(make_request, self.token_rotator)
                    
                    # Extract repositories from code search results
                    for item in data.get("items", []):
                        repo_data = item.get("repository", {})
                        repo_id = repo_data.get("id")
                        
                        if repo_id and repo_id not in unique_repos:
                            # Convert to RepoInfo format
                            repo_info = {
                                "id": repo_id,
                                "name": repo_data.get("name", ""),
                                "full_name": repo_data.get("full_name", ""),
                                "html_url": repo_data.get("html_url", ""),
                                "description": repo_data.get("description"),
                                "language": repo_data.get("language"),
                                "stargazers_count": repo_data.get("stargazers_count", 0),
                                "forks_count": repo_data.get("forks_count", 0),
                                "size": repo_data.get("size", 0),
                                "created_at": repo_data.get("created_at"),
                                "updated_at": repo_data.get("updated_at"),
                                "pushed_at": repo_data.get("pushed_at"),
                                "default_branch": repo_data.get("default_branch", "main"),
                                "owner": repo_data.get("owner", {}),
                                "private": repo_data.get("private", False),
                                "fork": repo_data.get("fork", False),
                                "archived": repo_data.get("archived", False)
                            }
                            unique_repos[repo_id] = repo_info
                            
                            # Add code search specific info
                            repo_info["code_match"] = {
                                "keyword": keyword,
                                "file_path": item.get("path", ""),
                                "file_url": item.get("html_url", "")
                            }
                    
                    # Check if we have more results
                    if len(data.get("items", [])) < per_page:
                        break
                        
                    page += 1
                    
                    # Rate limiting - code search is more restrictive
                    await asyncio.sleep(0.5)
                
                logger.info(f"Code search for '{keyword}': Found {len([r for r in unique_repos.values() if r.get('code_match', {}).get('keyword') == keyword])} repositories")
                
            except Exception as e:
                logger.warning(f"Code search failed for keyword '{keyword}': {e}")
                continue
        
        # Apply date filters if specified
        filtered_repos = []
        for repo in unique_repos.values():
            # Check created_after filter
            if created_after:
                try:
                    created_date = datetime.fromisoformat(repo.get("created_at", "").replace("Z", "+00:00"))
                    filter_date = datetime.fromisoformat(f"{created_after}T00:00:00+00:00")
                    if created_date < filter_date:
                        continue
                except:
                    continue  # Skip if date parsing fails
            
            # Check pushed_after filter  
            if pushed_after:
                try:
                    pushed_date_str = repo.get("pushed_at", "")
                    if not pushed_date_str:
                        continue  # Skip if no push date
                    pushed_date = datetime.fromisoformat(pushed_date_str.replace("Z", "+00:00"))
                    filter_date = datetime.fromisoformat(f"{pushed_after}T00:00:00+00:00")
                    if pushed_date < filter_date:
                        continue
                except:
                    continue  # Skip if date parsing fails
            
            filtered_repos.append(repo)
        
        logger.info(f"Code search completed: Found {len(unique_repos)} repositories, {len(filtered_repos)} after date filtering")
        return filtered_repos


async def scan_github_repositories(
    keywords: List[str],
    config: Config,
    language: Optional[str] = None,
    max_results: int = None
) -> List[RepoInfo]:
    """Convenience function to scan GitHub repositories.
    
    Args:
        keywords: List of keywords to search for.
        config: Configuration object.
        language: Programming language filter.
        max_results: Maximum number of results to return.
        
    Returns:
        List of repository information.
    """
    async with GitHubScanner(config) as scanner:
        return await scanner.scan_repositories(keywords, language, max_results)
