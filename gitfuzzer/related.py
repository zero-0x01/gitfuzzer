"""
Related entity detection for repositories.
Maps repositories to their upstream websites, SaaS products, or organizations
using URL/domain heuristics, README badges, copyright lines, and WHOIS.
"""

import re
import asyncio
import aiohttp
import logging
from typing import Optional, Dict, List, Set
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import json
import yaml
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class RelatedEntity:
    """Represents a related entity found for a repository."""
    domain: str
    url: str
    ip: Optional[str] = None
    organization: Optional[str] = None
    confidence: float = 0.0
    sources: List[str] = None
    
    def __post_init__(self):
        if self.sources is None:
            self.sources = []


class RelatedEntityDetector:
    """Detects related entities for repositories using multiple heuristics."""
    
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.domain_cache: Dict[str, Dict] = {}
        
    async def find_related(self, repo: Dict, content_root: Optional[Path] = None) -> Optional[RelatedEntity]:
        """
        Find related entity for a repository.
        
        Args:
            repo: Repository metadata dict
            content_root: Path to cloned repository content (optional)
            
        Returns:
            RelatedEntity if confidence >= 0.6, None otherwise
        """
        candidates = []
        
        # Source 1: Repository homepage field
        if repo.get('homepage'):
            candidates.extend(await self._extract_from_homepage(repo))
        
        # Source 2: GitHub Pages detection
        candidates.extend(await self._detect_github_pages(repo))
        
        # Source 3: README analysis (if content available)
        if content_root:
            candidates.extend(await self._analyze_readme(content_root))
            candidates.extend(await self._analyze_package_metadata(content_root))
            candidates.extend(await self._analyze_code_constants(content_root))
        
        # Source 4: Repository description URLs
        candidates.extend(await self._extract_from_description(repo))
        
        # Find best candidate
        best_candidate = await self._select_best_candidate(candidates, repo)
        
        if best_candidate and best_candidate.confidence >= 0.6:
            return best_candidate
        
        return None
    
    async def _extract_from_homepage(self, repo: Dict) -> List[RelatedEntity]:
        """Extract candidate from repository homepage field."""
        homepage = repo.get('homepage', '').strip()
        if not homepage or not homepage.startswith(('http://', 'https://')):
            return []
        
        domain = self._extract_domain(homepage)
        if not domain:
            return []
        
        confidence = 0.4  # Base confidence for homepage field
        
        # Boost confidence if domain matches repo name or owner
        repo_name = repo.get('name', '').lower()
        owner_name = repo.get('owner', {}).get('login', '').lower()
        
        if repo_name in domain or owner_name in domain:
            confidence += 0.3
        
        candidate = RelatedEntity(
            domain=domain,
            url=homepage,
            confidence=confidence,
            sources=['homepage']
        )
        
        return [candidate]
    
    async def _detect_github_pages(self, repo: Dict) -> List[RelatedEntity]:
        """Detect GitHub Pages sites."""
        candidates = []
        
        owner = repo.get('owner', {}).get('login', '')
        repo_name = repo.get('name', '')
        
        if not owner or not repo_name:
            return candidates
        
        # Check for GitHub Pages patterns
        pages_urls = [
            f"https://{owner}.github.io/{repo_name}",
            f"https://{owner}.github.io"
        ]
        
        for url in pages_urls:
            if await self._check_url_exists(url):
                domain = self._extract_domain(url)
                candidate = RelatedEntity(
                    domain=domain,
                    url=url,
                    confidence=0.5,  # Medium confidence for GitHub Pages
                    sources=['github_pages']
                )
                candidates.append(candidate)
        
        return candidates
    
    async def _analyze_readme(self, content_root: Path) -> List[RelatedEntity]:
        """Analyze README files for related URLs."""
        candidates = []
        
        readme_files = [
            'README.md', 'README.rst', 'README.txt', 'README',
            'readme.md', 'readme.rst', 'readme.txt', 'readme'
        ]
        
        for readme_name in readme_files:
            readme_path = content_root / readme_name
            if readme_path.exists():
                try:
                    content = readme_path.read_text(encoding='utf-8', errors='ignore')
                    candidates.extend(await self._extract_urls_from_text(content, 'readme'))
                    break  # Use first README found
                except Exception as e:
                    logger.debug(f"Error reading {readme_path}: {e}")
        
        return candidates
    
    async def _analyze_package_metadata(self, content_root: Path) -> List[RelatedEntity]:
        """Analyze package metadata files for homepage URLs."""
        candidates = []
        
        # package.json
        package_json = content_root / 'package.json'
        if package_json.exists():
            try:
                data = json.loads(package_json.read_text(encoding='utf-8'))
                homepage = data.get('homepage')
                if homepage:
                    domain = self._extract_domain(homepage)
                    if domain:
                        candidates.append(RelatedEntity(
                            domain=domain,
                            url=homepage,
                            confidence=0.3,
                            sources=['package.json']
                        ))
            except Exception as e:
                logger.debug(f"Error parsing package.json: {e}")
        
        # pyproject.toml
        pyproject_toml = content_root / 'pyproject.toml'
        if pyproject_toml.exists():
            try:
                # Try tomllib (Python 3.11+) or tomli fallback
                try:
                    import tomllib
                except ImportError:
                    try:
                        import tomli as tomllib
                    except ImportError:
                        logger.debug("Neither tomllib nor tomli available for pyproject.toml parsing")
                        return candidates
                        
                data = tomllib.loads(pyproject_toml.read_text(encoding='utf-8'))
                urls = data.get('project', {}).get('urls', {})
                homepage = urls.get('homepage') or urls.get('Homepage')
                if homepage:
                    domain = self._extract_domain(homepage)
                    if domain:
                        candidates.append(RelatedEntity(
                            domain=domain,
                            url=homepage,
                            confidence=0.3,
                            sources=['pyproject.toml']
                        ))
            except Exception as e:
                logger.debug(f"Error parsing pyproject.toml: {e}")
        
        # setup.py
        setup_py = content_root / 'setup.py'
        if setup_py.exists():
            try:
                content = setup_py.read_text(encoding='utf-8', errors='ignore')
                # Look for url= parameter
                url_match = re.search(r'url\s*=\s*["\']([^"\']+)["\']', content)
                if url_match:
                    url = url_match.group(1)
                    domain = self._extract_domain(url)
                    if domain:
                        candidates.append(RelatedEntity(
                            domain=domain,
                            url=url,
                            confidence=0.25,
                            sources=['setup.py']
                        ))
            except Exception as e:
                logger.debug(f"Error parsing setup.py: {e}")
        
        return candidates
    
    async def _analyze_code_constants(self, content_root: Path) -> List[RelatedEntity]:
        """Analyze code files for URL constants."""
        candidates = []
        
        # Common patterns for URL constants
        url_patterns = [
            r'BASE_URL\s*=\s*["\']([^"\']+)["\']',
            r'API_ENDPOINT\s*=\s*["\']([^"\']+)["\']',
            r'WEBSITE\s*=\s*["\']([^"\']+)["\']',
            r'HOMEPAGE\s*=\s*["\']([^"\']+)["\']',
            r'API_BASE\s*=\s*["\']([^"\']+)["\']',
        ]
        
        # Look in common configuration files
        config_files = [
            'config.py', 'settings.py', 'constants.py',
            'config.js', 'constants.js', 'env.js',
            'config.yaml', 'config.yml', '.env.example'
        ]
        
        for config_file in config_files:
            file_path = content_root / config_file
            if file_path.exists():
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    for pattern in url_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for url in matches:
                            if url.startswith(('http://', 'https://')):
                                domain = self._extract_domain(url)
                                if domain:
                                    candidates.append(RelatedEntity(
                                        domain=domain,
                                        url=url,
                                        confidence=0.2,
                                        sources=[f'code_constants:{config_file}']
                                    ))
                except Exception as e:
                    logger.debug(f"Error reading {file_path}: {e}")
        
        return candidates
    
    async def _extract_from_description(self, repo: Dict) -> List[RelatedEntity]:
        """Extract URLs from repository description."""
        candidates = []
        
        description = repo.get('description', '')
        if description:
            candidates.extend(await self._extract_urls_from_text(description, 'description'))
        
        return candidates
    
    async def _extract_urls_from_text(self, text: str, source: str) -> List[RelatedEntity]:
        """Extract URLs from text content."""
        candidates = []
        
        # URL patterns
        url_patterns = [
            r'https?://[^\s\)\]\}]+',  # Basic HTTP URLs
            r'\[([^\]]+)\]\(https?://([^\)]+)\)',  # Markdown links
            r'website:\s*(https?://[^\s]+)',  # Website: declarations
            r'homepage:\s*(https?://[^\s]+)',  # Homepage: declarations
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            
            for match in matches:
                if isinstance(match, tuple):
                    # Markdown link - use the URL part
                    url = f"https://{match[1]}" if not match[1].startswith('http') else match[1]
                else:
                    url = match
                
                url = url.rstrip('.,!?;)')  # Clean trailing punctuation
                
                if self._is_valid_url(url):
                    domain = self._extract_domain(url)
                    if domain:
                        confidence = 0.3 if 'readme' in source else 0.2
                        
                        # Boost confidence for website/homepage declarations
                        if any(keyword in text.lower() for keyword in ['website:', 'homepage:', 'visit:']):
                            confidence += 0.1
                        
                        candidates.append(RelatedEntity(
                            domain=domain,
                            url=url,
                            confidence=confidence,
                            sources=[source]
                        ))
        
        return candidates
    
    async def _select_best_candidate(self, candidates: List[RelatedEntity], repo: Dict) -> Optional[RelatedEntity]:
        """Select the best candidate from all found candidates."""
        if not candidates:
            return None
        
        # Group by domain and merge
        domain_groups = {}
        for candidate in candidates:
            domain = candidate.domain
            if domain not in domain_groups:
                domain_groups[domain] = candidate
            else:
                # Merge sources and take max confidence
                existing = domain_groups[domain]
                existing.confidence = max(existing.confidence, candidate.confidence)
                existing.sources.extend(candidate.sources)
                if candidate.url and not existing.url:
                    existing.url = candidate.url
        
        # Apply additional scoring
        for domain, candidate in domain_groups.items():
            candidate.confidence += await self._calculate_additional_score(candidate, repo)
        
        # Return highest confidence candidate
        best = max(domain_groups.values(), key=lambda c: c.confidence)
        
        # Enrich with additional data
        await self._enrich_candidate(best)
        
        return best
    
    async def _calculate_additional_score(self, candidate: RelatedEntity, repo: Dict) -> float:
        """Calculate additional confidence score based on various factors."""
        additional_score = 0.0
        
        repo_name = repo.get('name', '').lower()
        owner_name = repo.get('owner', {}).get('login', '').lower()
        domain = candidate.domain.lower()
        
        # Domain matches repo name or owner
        if repo_name in domain or domain in repo_name:
            additional_score += 0.3
        if owner_name in domain or domain in owner_name:
            additional_score += 0.2
        
        # Multiple sources boost confidence
        if len(set(candidate.sources)) > 1:
            additional_score += 0.1
        
        # Check if URL is actually reachable
        if await self._check_url_exists(candidate.url):
            additional_score += 0.1
        
        return additional_score
    
    async def _enrich_candidate(self, candidate: RelatedEntity):
        """Enrich candidate with additional metadata."""
        try:
            # Try to get IP and organization info
            domain_info = await self._get_domain_info(candidate.domain)
            if domain_info:
                candidate.ip = domain_info.get('ip')
                candidate.organization = domain_info.get('org')
        except Exception as e:
            logger.debug(f"Error enriching candidate {candidate.domain}: {e}")
    
    async def _get_domain_info(self, domain: str) -> Optional[Dict]:
        """Get domain information (IP, organization) from external services."""
        if domain in self.domain_cache:
            return self.domain_cache[domain]
        
        try:
            # Simple DNS lookup approach
            import socket
            ip = socket.gethostbyname(domain)
            
            info = {'ip': ip}
            self.domain_cache[domain] = info
            return info
            
        except Exception as e:
            logger.debug(f"DNS lookup failed for {domain}: {e}")
            return None
    
    async def _check_url_exists(self, url: str) -> bool:
        """Check if URL exists and returns 200 OK."""
        try:
            async with self.session.head(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                return response.status == 200
        except Exception:
            return False
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove www prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain if domain else None
        except Exception:
            return None
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid and not a known false positive."""
        if not url or not url.startswith(('http://', 'https://')):
            return False
        
        # Filter out common false positives
        false_positive_patterns = [
            r'example\.(com|org)',
            r'localhost',
            r'127\.0\.0\.1',
            r'your-domain\.com',
            r'your-website\.com',
            r'placeholder\.',
        ]
        
        for pattern in false_positive_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False
        
        return True


# Export main class
__all__ = ['RelatedEntityDetector', 'RelatedEntity']
