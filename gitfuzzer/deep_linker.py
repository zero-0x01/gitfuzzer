"""Stage 4: Deep linking and website discovery for GitFuzzer."""

import asyncio
import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import aiohttp
from bs4 import BeautifulSoup
from pydantic import BaseModel

from gitfuzzer.config import Settings as Config
from gitfuzzer.gh_scanner import RepoInfo
from gitfuzzer.utils import async_retry, extract_domain, validate_url

logger = logging.getLogger(__name__)


class WebsiteInfo(BaseModel):
    """Website information model."""
    
    url: str
    title: Optional[str] = None
    description: Optional[str] = None
    favicon_hash: Optional[str] = None
    status_code: int = 0
    redirect_chain: List[str] = []
    response_time: float = 0.0
    content_type: Optional[str] = None
    server: Optional[str] = None
    
    # Technical details
    ip_address: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    
    # Security/tech stack
    technologies: List[str] = []
    ssl_info: Dict[str, Any] = {}


class DeepLinkResult(BaseModel):
    """Deep linking result for a repository."""
    
    repo: RepoInfo
    primary_website: Optional[WebsiteInfo] = None
    additional_websites: List[WebsiteInfo] = []
    discovered_urls: List[str] = []
    analysis_notes: List[str] = []


class DeepLinker:
    """Deep linker for discovering websites and company connections."""
    
    def __init__(self, config: Config):
        """Initialize deep linker.
        
        Args:
            config: Configuration object.
        """
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self._url_cache: Dict[str, WebsiteInfo] = {}
        
    async def __aenter__(self):
        """Async context manager entry."""
        # Create session with custom settings
        connector = aiohttp.TCPConnector(
            limit=50,
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True
        )
        
        timeout = aiohttp.ClientTimeout(
            total=self.config.deep_linker.timeout,
            connect=10,
            sock_read=10
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": self.config.deep_linker.user_agent}
        )
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text content.
        
        Args:
            text: Text to extract URLs from.
            
        Returns:
            List of discovered URLs.
        """
        # URL patterns
        url_patterns = [
            r'https?://[^\s<>"{}|\\^`[\]]+',  # Standard HTTP URLs
            r'www\.[^\s<>"{}|\\^`[\]]+',      # www URLs without protocol
        ]
        
        urls = []
        for pattern in url_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Clean up URL
                url = match.rstrip('.,;:!?)]')
                
                # Add protocol if missing
                if url.startswith('www.'):
                    url = 'https://' + url
                
                if validate_url(url) and url not in urls:
                    urls.append(url)
        
        return urls
    
    def _extract_urls_from_html(self, html: str, base_url: str) -> List[str]:
        """Extract URLs from HTML content.
        
        Args:
            html: HTML content.
            base_url: Base URL for resolving relative links.
            
        Returns:
            List of discovered URLs.
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')
            urls = []
            
            # Extract from various HTML elements
            for tag in soup.find_all(['a', 'link', 'meta']):
                href = None
                
                if tag.name == 'a':
                    href = tag.get('href')
                elif tag.name == 'link':
                    href = tag.get('href')
                elif tag.name == 'meta':
                    # Check for og:url or similar
                    property_val = tag.get('property') or tag.get('name')
                    if property_val in ['og:url', 'canonical', 'alternate']:
                        href = tag.get('content')
                
                if href:
                    # Resolve relative URLs
                    absolute_url = urljoin(base_url, href)
                    
                    if validate_url(absolute_url) and absolute_url not in urls:
                        urls.append(absolute_url)
            
            return urls
        
        except Exception as e:
            logger.debug(f"Error parsing HTML: {e}")
            return []
    
    def _calculate_favicon_hash(self, favicon_data: bytes) -> str:
        """Calculate hash of favicon data.
        
        Args:
            favicon_data: Favicon image data.
            
        Returns:
            SHA-256 hash of favicon.
        """
        return hashlib.sha256(favicon_data).hexdigest()[:16]
    
    async def _fetch_favicon(self, base_url: str) -> Optional[str]:
        """Fetch and hash favicon from website.
        
        Args:
            base_url: Base URL of website.
            
        Returns:
            Favicon hash or None if not found.
        """
        if not self.session:
            return None
        
        # Common favicon paths
        favicon_paths = [
            '/favicon.ico',
            '/favicon.png',
            '/apple-touch-icon.png',
            '/android-chrome-192x192.png'
        ]
        
        for path in favicon_paths:
            try:
                favicon_url = urljoin(base_url, path)
                
                async with self.session.get(favicon_url) as response:
                    if response.status == 200:
                        content_type = response.headers.get('content-type', '')
                        if 'image' in content_type:
                            favicon_data = await response.read()
                            if len(favicon_data) > 100:  # Minimum size check
                                return self._calculate_favicon_hash(favicon_data)
            
            except Exception:
                continue
        
        return None
    
    async def _resolve_ip_info(self, domain: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Resolve IP and organization info for domain.
        
        Args:
            domain: Domain to resolve.
            
        Returns:
            Tuple of (ip_address, organization, country).
        """
        try:
            import socket
            
            # Get IP address
            ip_address = socket.gethostbyname(domain)
            
            # Use external services for organization/country info if API keys available
            organization = None
            country = None
            
            # IPInfo.io integration
            if self.config.ipinfo_token and self.session:
                try:
                    url = f"https://ipinfo.io/{ip_address}/json"
                    headers = {"Authorization": f"Bearer {self.config.ipinfo_token}"}
                    
                    async with self.session.get(url, headers=headers) as response:
                        if response.status == 200:
                            data = await response.json()
                            organization = data.get('org')
                            country = data.get('country')
                
                except Exception as e:
                    logger.debug(f"IPInfo lookup failed: {e}")
            
            # Shodan integration
            elif self.config.shodan_api_key and self.session:
                try:
                    url = f"https://api.shodan.io/shodan/host/{ip_address}"
                    params = {"key": self.config.shodan_api_key}
                    
                    async with self.session.get(url, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            organization = data.get('org')
                            country = data.get('country_name')
                
                except Exception as e:
                    logger.debug(f"Shodan lookup failed: {e}")
            
            return ip_address, organization, country
        
        except Exception as e:
            logger.debug(f"IP resolution failed for {domain}: {e}")
            return None, None, None
    
    def _detect_technologies(self, html: str, headers: Dict[str, str]) -> List[str]:
        """Detect technologies used by website.
        
        Args:
            html: HTML content.
            headers: HTTP response headers.
            
        Returns:
            List of detected technologies.
        """
        technologies = []
        
        # Check headers
        server = headers.get('server', '').lower()
        if 'nginx' in server:
            technologies.append('Nginx')
        elif 'apache' in server:
            technologies.append('Apache')
        elif 'cloudflare' in server:
            technologies.append('Cloudflare')
        
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        elif 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        
        # Check HTML content
        html_lower = html.lower()
        
        # JavaScript frameworks
        js_frameworks = {
            'react': ['react', 'jsx'],
            'vue': ['vue.js', 'vuejs'],
            'angular': ['angular', 'ng-'],
            'jquery': ['jquery'],
            'bootstrap': ['bootstrap'],
            'webpack': ['webpack']
        }
        
        for framework, indicators in js_frameworks.items():
            if any(indicator in html_lower for indicator in indicators):
                technologies.append(framework.title())
        
        # CMS detection
        cms_indicators = {
            'WordPress': ['wp-content', 'wp-includes'],
            'Drupal': ['/sites/default/', 'drupal'],
            'Joomla': ['/components/', 'joomla'],
            'Shopify': ['shopify', 'shop.js']
        }
        
        for cms, indicators in cms_indicators.items():
            if any(indicator in html_lower for indicator in indicators):
                technologies.append(cms)
        
        return list(set(technologies))
    
    async def _analyze_website(self, url: str) -> WebsiteInfo:
        """Analyze a website and gather information.
        
        Args:
            url: Website URL to analyze.
            
        Returns:
            Website information.
        """
        if url in self._url_cache:
            return self._url_cache[url]
        
        if not self.session:
            raise RuntimeError("Session not initialized")
        
        logger.debug(f"Analyzing website: {url}")
        
        website_info = WebsiteInfo(url=url)
        redirect_chain = []
        
        try:
            start_time = asyncio.get_event_loop().time()
            
            async with self.session.get(
                url,
                allow_redirects=True,
                max_redirects=self.config.deep_linker.max_redirects
            ) as response:
                
                response_time = asyncio.get_event_loop().time() - start_time
                
                # Track redirects
                if hasattr(response, 'history'):
                    redirect_chain = [str(resp.url) for resp in response.history]
                    redirect_chain.append(str(response.url))
                
                website_info.status_code = response.status
                website_info.redirect_chain = redirect_chain
                website_info.response_time = response_time
                website_info.content_type = response.headers.get('content-type')
                website_info.server = response.headers.get('server')
                
                if response.status == 200:
                    # Get content
                    content = await response.text(errors='ignore')
                    
                    # Parse HTML for title and description
                    try:
                        soup = BeautifulSoup(content, 'html.parser')
                        
                        # Extract title
                        title_tag = soup.find('title')
                        if title_tag:
                            website_info.title = title_tag.get_text().strip()
                        
                        # Extract description
                        desc_tag = soup.find('meta', attrs={'name': 'description'})
                        if desc_tag:
                            website_info.description = desc_tag.get('content', '').strip()
                        
                        # Extract Open Graph description as fallback
                        if not website_info.description:
                            og_desc = soup.find('meta', attrs={'property': 'og:description'})
                            if og_desc:
                                website_info.description = og_desc.get('content', '').strip()
                    
                    except Exception as e:
                        logger.debug(f"Error parsing HTML for {url}: {e}")
                    
                    # Detect technologies
                    website_info.technologies = self._detect_technologies(content, response.headers)
                    
                    # Get favicon
                    domain = extract_domain(url)
                    if domain:
                        favicon_hash = await self._fetch_favicon(f"https://{domain}")
                        website_info.favicon_hash = favicon_hash
                        
                        # Get IP and organization info
                        ip_address, organization, country = await self._resolve_ip_info(domain)
                        website_info.ip_address = ip_address
                        website_info.organization = organization
                        website_info.country = country
        
        except asyncio.TimeoutError:
            website_info.status_code = 408  # Request Timeout
        except Exception as e:
            logger.debug(f"Error analyzing website {url}: {e}")
            website_info.status_code = 0
        
        # Cache result
        self._url_cache[url] = website_info
        return website_info
    
    async def _discover_urls_from_repo(self, repo: RepoInfo) -> List[str]:
        """Discover URLs from repository information.
        
        Args:
            repo: Repository information.
            
        Returns:
            List of discovered URLs.
        """
        discovered_urls = []
        
        # Add homepage URL if available
        if repo.homepage and validate_url(repo.homepage):
            discovered_urls.append(repo.homepage)
        
        # Extract URLs from description
        if repo.description:
            description_urls = self._extract_urls_from_text(repo.description)
            discovered_urls.extend(description_urls)
        
        # Try to fetch README and extract URLs
        if self.session:
            try:
                # Try common README paths
                readme_paths = self.config.deep_linker.check_common_paths
                
                for readme_path in readme_paths:
                    try:
                        readme_url = f"https://raw.githubusercontent.com/{repo.full_name}/{repo.default_branch}/{readme_path}"
                        
                        async with self.session.get(readme_url) as response:
                            if response.status == 200:
                                content = await response.text()
                                readme_urls = self._extract_urls_from_text(content)
                                discovered_urls.extend(readme_urls)
                                break  # Found a README, stop looking
                    
                    except Exception:
                        continue
            
            except Exception as e:
                logger.debug(f"Error fetching README for {repo.full_name}: {e}")
        
        # Remove duplicates and invalid URLs
        unique_urls = []
        seen = set()
        
        for url in discovered_urls:
            if url not in seen and validate_url(url):
                # Filter out GitHub URLs and other repository hosts
                domain = extract_domain(url)
                if domain and not any(host in domain for host in ['github.com', 'gitlab.com', 'bitbucket.org']):
                    unique_urls.append(url)
                    seen.add(url)
        
        return unique_urls
    
    async def deep_link_repository(self, repo: RepoInfo) -> DeepLinkResult:
        """Perform deep linking analysis on a repository.
        
        Args:
            repo: Repository to analyze.
            
        Returns:
            Deep linking result.
        """
        logger.debug(f"Deep linking repository: {repo.full_name}")
        
        result = DeepLinkResult(repo=repo)
        
        try:
            # Discover URLs from repository
            discovered_urls = await self._discover_urls_from_repo(repo)
            result.discovered_urls = discovered_urls
            
            if not discovered_urls:
                result.analysis_notes.append("No URLs discovered")
                return result
            
            # Analyze discovered websites
            website_analyses = []
            
            # Limit concurrent website analyses
            semaphore = asyncio.Semaphore(3)
            
            async def analyze_with_semaphore(url: str) -> WebsiteInfo:
                async with semaphore:
                    return await async_retry(
                        self._analyze_website,
                        url,
                        max_retries=2,
                        base_delay=1.0
                    )
            
            tasks = [analyze_with_semaphore(url) for url in discovered_urls[:10]]  # Limit to 10 URLs
            website_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for i, website_result in enumerate(website_results):
                if isinstance(website_result, WebsiteInfo):
                    if website_result.status_code == 200:
                        website_analyses.append(website_result)
                elif isinstance(website_result, Exception):
                    logger.debug(f"Failed to analyze {discovered_urls[i]}: {website_result}")
            
            if website_analyses:
                # Sort by response time and status
                website_analyses.sort(key=lambda w: (w.status_code != 200, w.response_time))
                
                # Set primary website (best responding one)
                result.primary_website = website_analyses[0]
                
                # Set additional websites
                if len(website_analyses) > 1:
                    result.additional_websites = website_analyses[1:]
                
                # Add analysis notes
                result.analysis_notes.append(f"Analyzed {len(website_analyses)} websites")
                
                if result.primary_website.organization:
                    result.analysis_notes.append(f"Organization: {result.primary_website.organization}")
                
                if result.primary_website.technologies:
                    result.analysis_notes.append(f"Technologies: {', '.join(result.primary_website.technologies)}")
            
            else:
                result.analysis_notes.append("No accessible websites found")
        
        except Exception as e:
            logger.error(f"Error deep linking {repo.full_name}: {e}")
            result.analysis_notes.append(f"Analysis error: {e}")
        
        return result
    
    async def deep_link_repositories(
        self,
        repositories: List[RepoInfo],
        max_concurrent: int = None
    ) -> List[DeepLinkResult]:
        """Perform deep linking analysis on multiple repositories.
        
        Args:
            repositories: List of repositories to analyze.
            max_concurrent: Maximum concurrent analyses.
            
        Returns:
            List of deep linking results.
        """
        if not self.config.deep_linker.enable:
            logger.info("Deep linking is disabled")
            return [DeepLinkResult(repo=repo, analysis_notes=["Deep linking disabled"]) for repo in repositories]
        
        max_concurrent = max_concurrent or min(5, len(repositories))
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def deep_link_with_semaphore(repo: RepoInfo) -> DeepLinkResult:
            async with semaphore:
                return await self.deep_link_repository(repo)
        
        logger.info(f"Deep linking {len(repositories)} repositories with max_concurrent={max_concurrent}")
        
        tasks = [deep_link_with_semaphore(repo) for repo in repositories]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and log errors
        deep_link_results = []
        for i, result in enumerate(results):
            if isinstance(result, DeepLinkResult):
                deep_link_results.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Failed to deep link repository {repositories[i].full_name}: {result}")
                # Create error result
                error_result = DeepLinkResult(
                    repo=repositories[i],
                    analysis_notes=[f"Deep linking failed: {result}"]
                )
                deep_link_results.append(error_result)
        
        websites_found = sum(1 for result in deep_link_results if result.primary_website)
        logger.info(f"Deep linking completed: {websites_found}/{len(deep_link_results)} repositories have websites")
        
        return deep_link_results


async def deep_link_repositories(
    repositories: List[RepoInfo],
    config: Config,
    max_concurrent: int = None
) -> List[DeepLinkResult]:
    """Convenience function to perform deep linking on repositories.
    
    Args:
        repositories: List of repositories to analyze.
        config: Configuration object.
        max_concurrent: Maximum concurrent analyses.
        
    Returns:
        List of deep linking results.
    """
    async with DeepLinker(config) as deep_linker:
        return await deep_linker.deep_link_repositories(repositories, max_concurrent)
