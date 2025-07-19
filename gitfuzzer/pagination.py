"""
Advanced pagination and slicing module for bypassing 1000-result limits.

This module implements sophisticated query slicing algorithms to overcome the
1000-result limitation in GitHub Search API and Hugging Face Hub Search.

Core Algorithm:
1. Start with a broad query that may return >1000 results
2. Recursively slice by date ranges until each slice returns ≤1000 results
3. Use additional buckets (stars, size, downloads) when date slicing insufficient
4. Implement state checkpointing for resume capability
5. Apply exponential backoff and rate limiting

GitHub Search API: https://docs.github.com/rest/search/search
Hugging Face Hub API: https://huggingface.co/docs/hub/api
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple, Union
from urllib.parse import quote_plus, urlencode

import aiohttp
from pydantic import BaseModel

# Import async_retry directly from the utils.py file (not utils directory)
import importlib.util
import os
spec = importlib.util.spec_from_file_location("utils_module", os.path.join(os.path.dirname(__file__), "utils.py"))
utils_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(utils_module)
async_retry = utils_module.async_retry

logger = logging.getLogger(__name__)


@dataclass
class SliceConfig:
    """Configuration for query slicing."""
    
    # Date slicing
    slice_field: str = "pushed"  # pushed, created, lastModified, createdAt
    slice_days: int = 30  # Initial slice size in days
    min_slice_days: int = 1  # Minimum slice size
    max_date_ranges: int = 1000  # Maximum date ranges to prevent infinite recursion
    
    # Additional buckets
    star_buckets: List[Tuple[int, Optional[int]]] = field(default_factory=lambda: [
        (0, 10), (10, 50), (50, 200), (200, 1000), (1000, None)
    ])
    size_buckets: List[Tuple[int, Optional[int]]] = field(default_factory=lambda: [
        (0, 1000), (1000, 10000), (10000, 100000), (100000, None)
    ])
    
    # HF specific buckets
    download_buckets: List[Tuple[int, Optional[int]]] = field(default_factory=lambda: [
        (0, 100), (100, 1000), (1000, 10000), (10000, None)
    ])
    like_buckets: List[Tuple[int, Optional[int]]] = field(default_factory=lambda: [
        (0, 10), (10, 100), (100, 1000), (1000, None)
    ])
    
    # State management
    checkpoint_file: Optional[str] = "state/slices.json"
    resume_from_checkpoint: bool = True


@dataclass
class SearchResult:
    """Search result container."""
    
    items: List[Dict[str, Any]]
    total_count: int
    has_next_page: bool = False
    next_cursor: Optional[str] = None
    page_info: Optional[Dict[str, Any]] = None
    rate_limit_remaining: Optional[int] = None
    rate_limit_reset: Optional[datetime] = None


@dataclass
class SliceState:
    """State for a single slice."""
    
    query: str
    start_date: datetime
    end_date: datetime
    additional_filters: Dict[str, Any] = field(default_factory=dict)
    completed: bool = False
    total_items: int = 0
    pages_processed: int = 0
    last_cursor: Optional[str] = None


class SearchAdapter(ABC):
    """Abstract base class for search adapters."""
    
    def __init__(self, session: aiohttp.ClientSession, config: SliceConfig):
        self.session = session
        self.config = config
        
    @abstractmethod
    async def search(
        self,
        query: str,
        start_date: datetime,
        end_date: datetime,
        additional_filters: Optional[Dict[str, Any]] = None,
        per_page: int = 100,
        page: int = 1,
        cursor: Optional[str] = None
    ) -> SearchResult:
        """Execute a search query with date range."""
        pass
        
    @abstractmethod
    async def page_all(
        self,
        initial_result: SearchResult,
        query: str,
        start_date: datetime,
        end_date: datetime,
        additional_filters: Optional[Dict[str, Any]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Iterate through all pages of results."""
        pass
        
    @abstractmethod
    def build_query(
        self,
        base_query: str,
        start_date: datetime,
        end_date: datetime,
        additional_filters: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the complete query string."""
        pass


class GitHubAdapter(SearchAdapter):
    """GitHub Search API adapter with REST and GraphQL support."""
    
    def __init__(
        self,
        session: aiohttp.ClientSession,
        config: SliceConfig,
        tokens: List[str],
        use_graphql: bool = False
    ):
        super().__init__(session, config)
        self.tokens = tokens
        self.current_token_idx = 0
        self.use_graphql = use_graphql
        self.base_url = "https://api.github.com"
        
    def _get_headers(self) -> Dict[str, str]:
        """Get headers with current token."""
        token = self.tokens[self.current_token_idx]
        return {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitFuzzer/1.0"
        }
        
    def _rotate_token(self):
        """Rotate to next available token."""
        self.current_token_idx = (self.current_token_idx + 1) % len(self.tokens)
        
    def build_query(
        self,
        base_query: str,
        start_date: datetime,
        end_date: datetime,
        additional_filters: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build GitHub search query."""
        parts = [base_query]
        
        # Date range
        date_range = f"{start_date.strftime('%Y-%m-%d')}..{end_date.strftime('%Y-%m-%d')}"
        parts.append(f"{self.config.slice_field}:{date_range}")
        
        # Additional filters
        if additional_filters:
            for key, value in additional_filters.items():
                if key == "stars" and isinstance(value, tuple):
                    min_stars, max_stars = value
                    if max_stars is None:
                        parts.append(f"stars:>={min_stars}")
                    else:
                        parts.append(f"stars:{min_stars}..{max_stars}")
                elif key == "size" and isinstance(value, tuple):
                    min_size, max_size = value
                    if max_size is None:
                        parts.append(f"size:>={min_size}")
                    else:
                        parts.append(f"size:{min_size}..{max_size}")
                elif key == "language":
                    parts.append(f"language:{value}")
                elif key == "filename":
                    parts.append(f"filename:{value}")
                elif key == "extension":
                    parts.append(f"extension:{value}")
                elif key == "path":
                    parts.append(f"path:{value}")
                elif key == "in":
                    parts.append(f"in:{value}")
                else:
                    parts.append(f"{key}:{value}")
                    
        return " ".join(parts)
        
    async def search(
        self,
        query: str,
        start_date: datetime,
        end_date: datetime,
        additional_filters: Optional[Dict[str, Any]] = None,
        per_page: int = 100,
        page: int = 1,
        cursor: Optional[str] = None
    ) -> SearchResult:
        """Execute GitHub search query with retry logic."""
        return await async_retry(
            self._search_impl,
            query, start_date, end_date, additional_filters, per_page, page, cursor,
            max_retries=3,
            base_delay=1.0,
            backoff_multiplier=2.0
        )
        
    async def _search_impl(
        self,
        query: str,
        start_date: datetime,
        end_date: datetime,
        additional_filters: Optional[Dict[str, Any]] = None,
        per_page: int = 100,
        page: int = 1,
        cursor: Optional[str] = None
    ) -> SearchResult:
        """Execute GitHub search query implementation."""
        full_query = self.build_query(query, start_date, end_date, additional_filters)
        
        if self.use_graphql:
            return await self._search_graphql(full_query, per_page, cursor)
        else:
            return await self._search_rest(full_query, per_page, page)
            
    async def _search_rest(self, query: str, per_page: int, page: int) -> SearchResult:
        """Execute REST API search."""
        url = f"{self.base_url}/search/repositories"
        params = {
            "q": query,
            "per_page": min(per_page, 100),
            "page": page,
            "sort": "updated",
            "order": "desc"
        }
        
        headers = self._get_headers()
        
        async with self.session.get(url, params=params, headers=headers) as response:
            # Handle rate limiting
            remaining_header = response.headers.get("X-RateLimit-Remaining", "0")
            reset_header = response.headers.get("X-RateLimit-Reset", "0")
            
            # Handle case where headers might be coroutines (in tests)
            if hasattr(remaining_header, '__await__'):
                remaining_header = await remaining_header
            if hasattr(reset_header, '__await__'):
                reset_header = await reset_header
                
            remaining = int(remaining_header)
            reset_timestamp = int(reset_header)
            reset_time = datetime.fromtimestamp(reset_timestamp) if reset_timestamp else None
            
            if response.status == 403 and remaining == 0:
                logger.warning(f"Rate limit exceeded, rotating token")
                self._rotate_token()
                raise aiohttp.ClientResponseError(
                    request_info=response.request_info,
                    history=response.history,
                    status=response.status,
                    message="Rate limit exceeded"
                )
                
            response.raise_for_status()
            data = await response.json()
            
            return SearchResult(
                items=data.get("items", []),
                total_count=data.get("total_count", 0),
                has_next_page=len(data.get("items", [])) == per_page and page * per_page < data.get("total_count", 0),
                rate_limit_remaining=remaining,
                rate_limit_reset=reset_time
            )
            
    async def _search_graphql(self, query: str, per_page: int, cursor: Optional[str]) -> SearchResult:
        """Execute GraphQL search."""
        graphql_query = """
        query SearchRepositories($query: String!, $first: Int!, $after: String) {
            search(query: $query, type: REPOSITORY, first: $first, after: $after) {
                repositoryCount
                pageInfo {
                    hasNextPage
                    endCursor
                }
                nodes {
                    ... on Repository {
                        id
                        name
                        nameWithOwner
                        description
                        url
                        stargazerCount
                        forkCount
                        primaryLanguage {
                            name
                        }
                        createdAt
                        updatedAt
                        pushedAt
                        defaultBranchRef {
                            name
                        }
                    }
                }
                rateLimit {
                    remaining
                    resetAt
                    cost
                }
            }
        }
        """
        
        variables = {
            "query": query,
            "first": min(per_page, 100),
            "after": cursor
        }
        
        headers = self._get_headers()
        headers["Accept"] = "application/vnd.github.v4+json"
        
        payload = {
            "query": graphql_query,
            "variables": variables
        }
        
        url = f"{self.base_url}/graphql"
        
        async with self.session.post(url, json=payload, headers=headers) as response:
            # Check if raise_for_status is a coroutine (in tests)
            if hasattr(response.raise_for_status, '__await__'):
                await response.raise_for_status()
            else:
                response.raise_for_status()
            data = await response.json()
            
            if "errors" in data:
                raise Exception(f"GraphQL errors: {data['errors']}")
                
            search_data = data["data"]["search"]
            rate_limit = data["data"]["search"]["rateLimit"]
            
            return SearchResult(
                items=search_data["nodes"],
                total_count=search_data["repositoryCount"],
                has_next_page=search_data["pageInfo"]["hasNextPage"],
                next_cursor=search_data["pageInfo"]["endCursor"],
                page_info=search_data["pageInfo"],
                rate_limit_remaining=rate_limit["remaining"]
            )
            
    async def page_all(
        self,
        initial_result: SearchResult,
        query: str,
        start_date: datetime,
        end_date: datetime,
        additional_filters: Optional[Dict[str, Any]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Iterate through all pages."""
        # Yield initial results
        for item in initial_result.items:
            yield item
            
        if not initial_result.has_next_page:
            return
            
        if self.use_graphql:
            cursor = initial_result.next_cursor
            while cursor:
                result = await self.search(
                    query, start_date, end_date, additional_filters, cursor=cursor
                )
                for item in result.items:
                    yield item
                cursor = result.next_cursor if result.has_next_page else None
        else:
            page = 2
            while True:
                result = await self.search(
                    query, start_date, end_date, additional_filters, page=page
                )
                if not result.items:
                    break
                for item in result.items:
                    yield item
                if not result.has_next_page:
                    break
                page += 1


class HuggingFaceAdapter(SearchAdapter):
    """Hugging Face Hub Search API adapter."""
    
    def __init__(
        self,
        session: aiohttp.ClientSession,
        config: SliceConfig,
        token: Optional[str] = None
    ):
        super().__init__(session, config)
        self.token = token
        self.base_url = "https://huggingface.co/api"
        
    def _get_headers(self) -> Dict[str, str]:
        """Get headers with token if available."""
        headers = {"User-Agent": "GitFuzzer/1.0"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers
        
    def build_query(
        self,
        base_query: str,
        start_date: datetime,
        end_date: datetime,
        additional_filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Build HF search parameters."""
        params = {
            "search": base_query,
            "limit": 100,
            "full": True,
            "sort": "lastModified",
            "direction": -1
        }
        
        # Date range
        date_range = f"{start_date.isoformat()}..{end_date.isoformat()}"
        params[self.config.slice_field] = date_range
        
        # Additional filters
        if additional_filters:
            for key, value in additional_filters.items():
                if key == "downloads" and isinstance(value, tuple):
                    min_dl, max_dl = value
                    if max_dl is None:
                        params["downloads"] = f">={min_dl}"
                    else:
                        params["downloads"] = f"{min_dl}..{max_dl}"
                elif key == "likes" and isinstance(value, tuple):
                    min_likes, max_likes = value
                    if max_likes is None:
                        params["likes"] = f">={min_likes}"
                    else:
                        params["likes"] = f"{min_likes}..{max_likes}"
                else:
                    params[key] = value
                    
        return params
        
    async def search(
        self,
        query: str,
        start_date: datetime,
        end_date: datetime,
        additional_filters: Optional[Dict[str, Any]] = None,
        per_page: int = 100,
        page: int = 1,
        cursor: Optional[str] = None
    ) -> SearchResult:
        """Execute HF search query with retry logic."""
        return await async_retry(
            self._search_impl,
            query, start_date, end_date, additional_filters, per_page, page, cursor,
            max_retries=3,
            base_delay=1.0,
            backoff_multiplier=2.0
        )
        
    async def _search_impl(
        self,
        query: str,
        start_date: datetime,
        end_date: datetime,
        additional_filters: Optional[Dict[str, Any]] = None,
        per_page: int = 100,
        page: int = 1,
        cursor: Optional[str] = None
    ) -> SearchResult:
        """Execute HF search query implementation."""
        params = self.build_query(query, start_date, end_date, additional_filters)
        params["limit"] = min(per_page, 100)
        
        # HF uses offset-based pagination
        if page > 1:
            params["offset"] = (page - 1) * per_page
            
        url = f"{self.base_url}/models"
        headers = self._get_headers()
        
        async with self.session.get(url, params=params, headers=headers) as response:
            # Check if raise_for_status is a coroutine (in tests)
            if hasattr(response.raise_for_status, '__await__'):
                await response.raise_for_status()
            else:
                response.raise_for_status()
            items = await response.json()
            
            # HF doesn't provide total count directly, estimate from results
            total_count = len(items)
            if len(items) == per_page:
                # There might be more, set a high estimate
                total_count = per_page * 100  # Will trigger slicing if > 1000
                
            return SearchResult(
                items=items,
                total_count=total_count,
                has_next_page=len(items) == per_page
            )
            
    async def page_all(
        self,
        initial_result: SearchResult,
        query: str,
        start_date: datetime,
        end_date: datetime,
        additional_filters: Optional[Dict[str, Any]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Iterate through all HF pages."""
        # Yield initial results
        for item in initial_result.items:
            yield item
            
        if not initial_result.has_next_page:
            return
            
        page = 2
        while True:
            result = await self.search(
                query, start_date, end_date, additional_filters, page=page
            )
            if not result.items:
                break
            for item in result.items:
                yield item
            if not result.has_next_page:
                break
            page += 1


class PaginationSlicer:
    """
    Core pagination slicer that bypasses 1000-result limits.
    
    Implements recursive date slicing with additional bucket filters
    to ensure no single query returns more than 1000 results.
    """
    
    def __init__(
        self,
        adapter: SearchAdapter,
        config: SliceConfig,
        progress_callback: Optional[callable] = None
    ):
        self.adapter = adapter
        self.config = config
        self.progress_callback = progress_callback
        self.processed_slices: List[SliceState] = []
        self.pending_slices: deque = deque()
        
    async def slice_search(
        self,
        base_query: str,
        start_date: datetime,
        end_date: datetime,
        max_results: Optional[int] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Main entry point for sliced search.
        
        Args:
            base_query: Base search query
            start_date: Start date for search
            end_date: End date for search
            max_results: Maximum results to return (None for unlimited)
            
        Yields:
            Individual search result items
        """
        # Load checkpoint if exists
        if self.config.resume_from_checkpoint:
            await self._load_checkpoint()
            
        # Initialize with base slice
        initial_slice = SliceState(
            query=base_query,
            start_date=start_date,
            end_date=end_date
        )
        
        if not self._is_slice_completed(initial_slice):
            self.pending_slices.append(initial_slice)
            
        total_yielded = 0
        
        try:
            while self.pending_slices:
                current_slice = self.pending_slices.popleft()
                
                if self._is_slice_completed(current_slice):
                    continue
                    
                async for item in self._process_slice(current_slice):
                    yield item
                    total_yielded += 1
                    
                    if max_results and total_yielded >= max_results:
                        logger.info(f"Reached max_results limit: {max_results}")
                        return
                        
                # Save checkpoint periodically
                if len(self.processed_slices) % 10 == 0:
                    await self._save_checkpoint()
                    
        finally:
            # Final checkpoint save
            await self._save_checkpoint()
            
    async def _process_slice(self, slice_state: SliceState) -> AsyncGenerator[Dict[str, Any], None]:
        """Process a single slice."""
        logger.debug(f"Processing slice: {slice_state.start_date} to {slice_state.end_date}")
        
        # Try the slice without additional buckets first
        result = await self.adapter.search(
            slice_state.query,
            slice_state.start_date,
            slice_state.end_date,
            slice_state.additional_filters
        )
        
        if result.total_count <= 1000:
            # Safe to paginate through all results
            async for item in self.adapter.page_all(
                result,
                slice_state.query,
                slice_state.start_date,
                slice_state.end_date,
                slice_state.additional_filters
            ):
                yield item
                slice_state.total_items += 1
                
            slice_state.completed = True
            self.processed_slices.append(slice_state)
            
            if self.progress_callback:
                self.progress_callback(f"Completed slice: {slice_state.total_items} items")
                
        else:
            # Need to slice further
            async for item in self._split_slice(slice_state):
                yield item
            
    async def _split_slice(self, slice_state: SliceState) -> AsyncGenerator[Dict[str, Any], None]:
        """Split a slice that returns too many results."""
        date_diff = slice_state.end_date - slice_state.start_date
        
        if date_diff.days <= self.config.min_slice_days:
            # Can't slice by date anymore, try additional buckets
            created_slices = await self._apply_additional_buckets(slice_state)
            if not created_slices:
                # Exhausted all slicing options - process directly with truncation
                async for item in self._process_exhausted_slice(slice_state):
                    yield item
                return
        else:
            # Split by date
            mid_date = slice_state.start_date + date_diff / 2
            
            # Create two new slices
            slice1 = SliceState(
                query=slice_state.query,
                start_date=slice_state.start_date,
                end_date=mid_date,
                additional_filters=slice_state.additional_filters.copy()
            )
            
            slice2 = SliceState(
                query=slice_state.query,
                start_date=mid_date + timedelta(days=1),
                end_date=slice_state.end_date,
                additional_filters=slice_state.additional_filters.copy()
            )
            
            self.pending_slices.append(slice1)
            self.pending_slices.append(slice2)
            
            logger.debug(f"Split slice into: {slice1.start_date}-{slice1.end_date} and {slice2.start_date}-{slice2.end_date}")
            
    async def _apply_additional_buckets(self, slice_state: SliceState) -> bool:
        """Apply additional bucket filters when date slicing insufficient.
        
        Returns:
            True if new slices were created, False if exhausted and should process directly
        """
        if isinstance(self.adapter, GitHubAdapter):
            # Try star buckets
            if "stars" not in slice_state.additional_filters:
                for star_bucket in self.config.star_buckets:
                    new_slice = SliceState(
                        query=slice_state.query,
                        start_date=slice_state.start_date,
                        end_date=slice_state.end_date,
                        additional_filters={**slice_state.additional_filters, "stars": star_bucket}
                    )
                    self.pending_slices.append(new_slice)
                return True
                
            # Try size buckets
            if "size" not in slice_state.additional_filters:
                for size_bucket in self.config.size_buckets:
                    new_slice = SliceState(
                        query=slice_state.query,
                        start_date=slice_state.start_date,
                        end_date=slice_state.end_date,
                        additional_filters={**slice_state.additional_filters, "size": size_bucket}
                    )
                    self.pending_slices.append(new_slice)
                return True
                
        elif isinstance(self.adapter, HuggingFaceAdapter):
            # Try download buckets
            if "downloads" not in slice_state.additional_filters:
                for dl_bucket in self.config.download_buckets:
                    new_slice = SliceState(
                        query=slice_state.query,
                        start_date=slice_state.start_date,
                        end_date=slice_state.end_date,
                        additional_filters={**slice_state.additional_filters, "downloads": dl_bucket}
                    )
                    self.pending_slices.append(new_slice)
                return True
                
        # If we reach here, we've exhausted slicing options
        return False
        
    async def _process_exhausted_slice(self, slice_state: SliceState) -> AsyncGenerator[Dict[str, Any], None]:
        """Process a slice that can't be subdivided further."""
        logger.warning(f"Cannot slice further, accepting truncated results for {slice_state.start_date}-{slice_state.end_date}")
        
        # Process what we can get
        result = await self.adapter.search(
            slice_state.query,
            slice_state.start_date,
            slice_state.end_date,
            slice_state.additional_filters,
            per_page=100
        )
        
        # Take first 1000 results only
        count = 0
        async for item in self.adapter.page_all(
            result,
            slice_state.query,
            slice_state.start_date,
            slice_state.end_date,
            slice_state.additional_filters
        ):
            if count >= 1000:
                break
            yield item
            count += 1
            
        slice_state.completed = True
        slice_state.total_items = count
        self.processed_slices.append(slice_state)
        
    def _is_slice_completed(self, slice_state: SliceState) -> bool:
        """Check if a slice has already been completed."""
        for processed in self.processed_slices:
            if (processed.query == slice_state.query and
                processed.start_date == slice_state.start_date and
                processed.end_date == slice_state.end_date and
                processed.additional_filters == slice_state.additional_filters and
                processed.completed):
                return True
        return False
        
    async def _save_checkpoint(self):
        """Save current progress to checkpoint file."""
        if not self.config.checkpoint_file:
            return
            
        checkpoint_path = Path(self.config.checkpoint_file)
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        
        checkpoint_data = {
            "processed_slices": [
                {
                    "query": s.query,
                    "start_date": s.start_date.isoformat(),
                    "end_date": s.end_date.isoformat(),
                    "additional_filters": s.additional_filters,
                    "completed": s.completed,
                    "total_items": s.total_items,
                    "pages_processed": s.pages_processed
                }
                for s in self.processed_slices
            ],
            "pending_slices": [
                {
                    "query": s.query,
                    "start_date": s.start_date.isoformat(),
                    "end_date": s.end_date.isoformat(),
                    "additional_filters": s.additional_filters,
                    "completed": s.completed,
                    "total_items": s.total_items,
                    "pages_processed": s.pages_processed
                }
                for s in list(self.pending_slices)
            ]
        }
        
        with open(checkpoint_path, 'w') as f:
            json.dump(checkpoint_data, f, indent=2)
            
        logger.debug(f"Saved checkpoint: {len(self.processed_slices)} processed, {len(self.pending_slices)} pending")
        
    async def _load_checkpoint(self):
        """Load progress from checkpoint file."""
        if not self.config.checkpoint_file:
            return
            
        checkpoint_path = Path(self.config.checkpoint_file)
        if not checkpoint_path.exists():
            return
            
        try:
            with open(checkpoint_path, 'r') as f:
                checkpoint_data = json.load(f)
                
            # Load processed slices
            for slice_data in checkpoint_data.get("processed_slices", []):
                slice_state = SliceState(
                    query=slice_data["query"],
                    start_date=datetime.fromisoformat(slice_data["start_date"]),
                    end_date=datetime.fromisoformat(slice_data["end_date"]),
                    additional_filters=slice_data["additional_filters"],
                    completed=slice_data["completed"],
                    total_items=slice_data["total_items"],
                    pages_processed=slice_data["pages_processed"]
                )
                self.processed_slices.append(slice_state)
                
            # Load pending slices
            for slice_data in checkpoint_data.get("pending_slices", []):
                slice_state = SliceState(
                    query=slice_data["query"],
                    start_date=datetime.fromisoformat(slice_data["start_date"]),
                    end_date=datetime.fromisoformat(slice_data["end_date"]),
                    additional_filters=slice_data["additional_filters"],
                    completed=slice_data["completed"],
                    total_items=slice_data["total_items"],
                    pages_processed=slice_data["pages_processed"]
                )
                self.pending_slices.append(slice_state)
                
            logger.info(f"Loaded checkpoint: {len(self.processed_slices)} processed, {len(self.pending_slices)} pending slices")
            
        except Exception as e:
            logger.warning(f"Failed to load checkpoint: {e}")


async def slice_search_with_progress(
    adapter: SearchAdapter,
    config: SliceConfig,
    base_query: str,
    start_date: datetime,
    end_date: datetime,
    max_results: Optional[int] = None,
    progress_callback: Optional[callable] = None
) -> List[Dict[str, Any]]:
    """
    Convenience function to perform sliced search with progress tracking.
    
    Args:
        adapter: Search adapter (GitHub or HuggingFace)
        config: Slice configuration
        base_query: Base search query
        start_date: Start date for search
        end_date: End date for search
        max_results: Maximum results to return
        progress_callback: Optional progress callback function
        
    Returns:
        List of all search results
    """
    slicer = PaginationSlicer(adapter, config, progress_callback)
    results = []
    
    async for item in slicer.slice_search(base_query, start_date, end_date, max_results):
        results.append(item)
        
    return results
