"""Endpoint and service discovery for GitFuzzer.

This module extracts URLs, IPs, domains, and emails from repository content
and validates their liveness and accessibility.
"""

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import aiohttp
import dns.resolver
from dns.exception import DNSException


@dataclass
class EndpointMatch:
    """Represents a discovered endpoint."""
    url: str
    endpoint_type: str  # 'url', 'domain', 'ip', 'email'
    file_path: str
    line_no: int
    is_live: bool = False
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    tls_cert_cn: Optional[str] = None
    response_time_ms: Optional[float] = None
    final_url: Optional[str] = None
    relation_to_repo: str = 'unknown'  # 'homepage', 'api', 'third-party'
    
    @property
    def domain(self) -> Optional[str]:
        """Extract domain from URL."""
        if self.endpoint_type == 'url':
            parsed = urlparse(self.url)
            return parsed.netloc
        elif self.endpoint_type == 'domain':
            return self.url
        return None


class EndpointExtractor:
    """Extracts and validates endpoints from repository content."""
    
    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        """Initialize endpoint extractor.
        
        Args:
            session: HTTP session for validation requests
        """
        self.session = session
        self._init_patterns()
        self.validation_cache = {}
        
        # Timeout settings
        self.validation_timeout = 5.0
        self.max_redirects = 3
        
        # DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 5
    
    def _init_patterns(self):
        """Initialize regex patterns for endpoint extraction."""
        # Full URLs (based on RFC 3986 with practical modifications)
        self.url_pattern = re.compile(
            r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            re.IGNORECASE | re.MULTILINE
        )
        
        # WebSocket URLs
        self.ws_pattern = re.compile(
            r'wss?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            re.IGNORECASE | re.MULTILINE
        )
        
        # Domain patterns (more permissive than RFC)
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\b',
            re.IGNORECASE | re.MULTILINE
        )
        
        # IPv4 addresses
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # IPv6 addresses (simplified)
        self.ipv6_pattern = re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
            r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,7}::\b'
        )
        
        # Email addresses
        self.email_pattern = re.compile(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        )
        
        # Common TLDs for domain validation
        self.valid_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'ai',
            'app', 'dev', 'tech', 'cloud', 'api', 'web', 'site', 'online', 'live',
            'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'ru', 'br', 'in'
        }
    
    def extract_from_content(self, content: str, file_path: str) -> List[EndpointMatch]:
        """Extract all endpoints from file content.
        
        Args:
            content: File content to scan
            file_path: Path of the file being scanned
            
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        lines = content.split('\n')
        
        for line_no, line in enumerate(lines, 1):
            # Skip comments and empty lines
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith(('#', '//', '/*', '*')):
                continue
            
            # Extract URLs
            for match in self.url_pattern.finditer(line):
                url = match.group(0)
                if self._is_valid_url(url):
                    endpoints.append(EndpointMatch(
                        url=url,
                        endpoint_type='url',
                        file_path=file_path,
                        line_no=line_no
                    ))
            
            # Extract WebSocket URLs
            for match in self.ws_pattern.finditer(line):
                url = match.group(0)
                endpoints.append(EndpointMatch(
                    url=url,
                    endpoint_type='url',
                    file_path=file_path,
                    line_no=line_no
                ))
            
            # Extract IPv4 addresses
            for match in self.ipv4_pattern.finditer(line):
                ip = match.group(0)
                if self._is_valid_ipv4(ip):
                    endpoints.append(EndpointMatch(
                        url=ip,
                        endpoint_type='ip',
                        file_path=file_path,
                        line_no=line_no
                    ))
            
            # Extract IPv6 addresses
            for match in self.ipv6_pattern.finditer(line):
                ip = match.group(0)
                if self._is_valid_ipv6(ip):
                    endpoints.append(EndpointMatch(
                        url=ip,
                        endpoint_type='ip',
                        file_path=file_path,
                        line_no=line_no
                    ))
            
            # Extract domains
            for match in self.domain_pattern.finditer(line):
                domain = match.group(0)
                if self._is_valid_domain(domain):
                    endpoints.append(EndpointMatch(
                        url=domain,
                        endpoint_type='domain',
                        file_path=file_path,
                        line_no=line_no
                    ))
            
            # Extract email addresses
            for match in self.email_pattern.finditer(line):
                email = match.group(0)
                endpoints.append(EndpointMatch(
                    url=email,
                    endpoint_type='email',
                    file_path=file_path,
                    line_no=line_no
                ))
        
        return self._deduplicate_endpoints(endpoints)
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format and content.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL appears valid
        """
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return False
            
            # Skip obvious false positives
            if any(ext in url.lower() for ext in ['.jpg', '.png', '.gif', '.css', '.js']):
                return False
            
            # Skip localhost (but allow example.com for testing)
            if any(local in parsed.netloc.lower() for local in ['localhost', '127.0.0.1']):
                return False
            
            return True
        except Exception:
            return False
    
    def _is_valid_ipv4(self, ip: str) -> bool:
        """Validate IPv4 address.
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid IPv4
        """
        try:
            addr = ipaddress.IPv4Address(ip)
            # Skip private/reserved ranges
            return not (addr.is_private or addr.is_multicast or addr.is_reserved or addr.is_loopback)
        except ipaddress.AddressValueError:
            return False
    
    def _is_valid_ipv6(self, ip: str) -> bool:
        """Validate IPv6 address.
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid IPv6
        """
        try:
            addr = ipaddress.IPv6Address(ip)
            return not (addr.is_private or addr.is_multicast or addr.is_reserved or addr.is_loopback)
        except ipaddress.AddressValueError:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            True if domain appears valid
        """
        # Basic format checks
        if len(domain) > 253 or not domain:
            return False
        
        # Check for valid TLD
        tld = domain.split('.')[-1].lower()
        if tld not in self.valid_tlds:
            return False
        
        # Skip common false positives
        false_positives = {'file.txt', 'image.png', 'script.js', 'style.css'}
        if domain.lower() in false_positives:
            return False
        
        # Must have at least one dot
        if '.' not in domain:
            return False
        
        return True
    
    def _deduplicate_endpoints(self, endpoints: List[EndpointMatch]) -> List[EndpointMatch]:
        """Remove duplicate endpoints.
        
        Args:
            endpoints: List of endpoints to deduplicate
            
        Returns:
            Deduplicated list
        """
        seen = set()
        unique_endpoints = []
        
        for endpoint in endpoints:
            key = (endpoint.url, endpoint.endpoint_type)
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(endpoint)
        
        return unique_endpoints
    
    async def validate_endpoint(self, endpoint: EndpointMatch) -> EndpointMatch:
        """Validate a single endpoint's liveness.
        
        Args:
            endpoint: Endpoint to validate
            
        Returns:
            Updated endpoint with validation results
        """
        if endpoint.url in self.validation_cache:
            cached_result = self.validation_cache[endpoint.url]
            endpoint.is_live = cached_result['is_live']
            endpoint.status_code = cached_result.get('status_code')
            endpoint.content_type = cached_result.get('content_type')
            endpoint.response_time_ms = cached_result.get('response_time_ms')
            endpoint.final_url = cached_result.get('final_url')
            return endpoint
        
        if endpoint.endpoint_type == 'url':
            await self._validate_url(endpoint)
        elif endpoint.endpoint_type == 'domain':
            await self._validate_domain(endpoint)
        elif endpoint.endpoint_type == 'ip':
            await self._validate_ip(endpoint)
        elif endpoint.endpoint_type == 'email':
            await self._validate_email_domain(endpoint)
        
        # Cache result
        self.validation_cache[endpoint.url] = {
            'is_live': endpoint.is_live,
            'status_code': endpoint.status_code,
            'content_type': endpoint.content_type,
            'response_time_ms': endpoint.response_time_ms,
            'final_url': endpoint.final_url
        }
        
        return endpoint
    
    async def _validate_url(self, endpoint: EndpointMatch):
        """Validate URL by making HTTP request.
        
        Args:
            endpoint: Endpoint to validate
        """
        if not self.session:
            return
        
        start_time = asyncio.get_event_loop().time()
        
        try:
            async with self.session.head(
                endpoint.url,
                timeout=aiohttp.ClientTimeout(total=self.validation_timeout),
                allow_redirects=True,
                max_redirects=self.max_redirects,
                ssl=False  # Don't verify SSL for discovery
            ) as response:
                end_time = asyncio.get_event_loop().time()
                
                endpoint.is_live = True
                endpoint.status_code = response.status
                endpoint.content_type = response.headers.get('content-type')
                endpoint.response_time_ms = (end_time - start_time) * 1000
                endpoint.final_url = str(response.url)
                
                # Try to extract TLS certificate CN for HTTPS
                if endpoint.url.startswith('https://'):
                    try:
                        # This is a simplified approach - in production you'd want
                        # to extract the actual certificate
                        parsed = urlparse(endpoint.url)
                        endpoint.tls_cert_cn = parsed.netloc
                    except Exception:
                        pass
                
        except asyncio.TimeoutError:
            endpoint.is_live = False
        except Exception:
            endpoint.is_live = False
    
    async def _validate_domain(self, endpoint: EndpointMatch):
        """Validate domain by DNS lookup.
        
        Args:
            endpoint: Endpoint to validate
        """
        try:
            # Try DNS resolution
            answers = await asyncio.get_event_loop().run_in_executor(
                None, self.resolver.resolve, endpoint.domain, 'A'
            )
            if answers:
                endpoint.is_live = True
                # Try HTTP on the domain
                if self.session:
                    test_url = f"http://{endpoint.domain}"
                    temp_endpoint = EndpointMatch(
                        url=test_url,
                        endpoint_type='url',
                        file_path=endpoint.file_path,
                        line_no=endpoint.line_no
                    )
                    await self._validate_url(temp_endpoint)
                    if temp_endpoint.is_live:
                        endpoint.status_code = temp_endpoint.status_code
                        endpoint.content_type = temp_endpoint.content_type
                        endpoint.response_time_ms = temp_endpoint.response_time_ms
        except DNSException:
            endpoint.is_live = False
    
    async def _validate_ip(self, endpoint: EndpointMatch):
        """Validate IP by attempting connection.
        
        Args:
            endpoint: Endpoint to validate
        """
        try:
            # Try common ports
            common_ports = [80, 443, 22, 21, 25, 53, 993, 995]
            
            for port in common_ports:
                try:
                    # Use asyncio.wait_for with socket connection
                    future = asyncio.get_event_loop().run_in_executor(
                        None, socket.create_connection, (endpoint.url, port), 2
                    )
                    sock = await asyncio.wait_for(future, timeout=2)
                    sock.close()
                    endpoint.is_live = True
                    break
                except (OSError, asyncio.TimeoutError):
                    continue
            
        except Exception:
            endpoint.is_live = False
    
    async def _validate_email_domain(self, endpoint: EndpointMatch):
        """Validate email domain part.
        
        Args:
            endpoint: Endpoint to validate
        """
        try:
            domain = endpoint.url.split('@')[1]
            answers = await asyncio.get_event_loop().run_in_executor(
                None, self.resolver.resolve, domain, 'MX'
            )
            endpoint.is_live = len(answers) > 0
        except (DNSException, IndexError):
            endpoint.is_live = False
    
    async def validate_endpoints(self, urls: List[str]) -> Dict[str, bool]:
        """Validate multiple endpoints concurrently.
        
        Args:
            urls: List of URLs to validate
            
        Returns:
            Dictionary mapping URLs to their live status
        """
        # Create temporary endpoints for validation
        temp_endpoints = []
        for url in urls:
            if url.startswith(('http://', 'https://')):
                endpoint_type = 'url'
            elif '@' in url:
                endpoint_type = 'email'
            elif self._is_valid_ipv4(url) or self._is_valid_ipv6(url):
                endpoint_type = 'ip'
            else:
                endpoint_type = 'domain'
            
            temp_endpoints.append(EndpointMatch(
                url=url,
                endpoint_type=endpoint_type,
                file_path='',
                line_no=0
            ))
        
        # Validate concurrently with semaphore
        semaphore = asyncio.Semaphore(10)
        
        async def validate_with_semaphore(endpoint):
            async with semaphore:
                return await self.validate_endpoint(endpoint)
        
        validated_endpoints = await asyncio.gather(
            *[validate_with_semaphore(ep) for ep in temp_endpoints],
            return_exceptions=True
        )
        
        # Build result dictionary
        result = {}
        for i, endpoint in enumerate(validated_endpoints):
            if isinstance(endpoint, EndpointMatch):
                result[urls[i]] = endpoint.is_live
            else:
                result[urls[i]] = False
        
        return result
    
    def classify_endpoint_relation(self, endpoint: EndpointMatch, repo_url: str) -> str:
        """Classify endpoint's relation to repository.
        
        Args:
            endpoint: Endpoint to classify
            repo_url: Repository URL
            
        Returns:
            Relation classification: 'homepage', 'api', 'third-party'
        """
        try:
            repo_parsed = urlparse(repo_url)
            repo_parts = repo_parsed.path.strip('/').split('/')
            repo_owner = repo_parts[0] if repo_parts else ''
            repo_name = repo_parts[1] if len(repo_parts) > 1 else ''
            
            endpoint_domain = endpoint.domain
            if not endpoint_domain:
                return 'unknown'
            
            # Check if it's the same domain as repo (e.g., GitHub Pages)
            if repo_owner.lower() in endpoint_domain.lower():
                return 'homepage'
            
            if repo_name.lower() in endpoint_domain.lower():
                return 'homepage'
            
            # Check for API patterns
            if any(api_term in endpoint.url.lower() for api_term in ['api', 'rest', 'graphql', 'endpoint']):
                return 'api'
            
            # Check file path for context
            file_lower = endpoint.file_path.lower()
            if any(config_file in file_lower for config_file in ['readme', 'config', 'package.json', 'setup.py']):
                return 'homepage'
            
            return 'third-party'
            
        except Exception:
            return 'unknown'
