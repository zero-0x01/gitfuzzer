"""Organization inference for GitFuzzer.

This module attempts to identify the organization or company
associated with a repository using various heuristics.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
import aiohttp

from .secret_rules import SecretMatch
from .endpoint_extractor import EndpointMatch


@dataclass
class OrganizationInfo:
    """Information about an inferred organization."""
    name: str
    confidence: float  # 0.0 to 1.0
    source: str  # 'github', 'email', 'domain', 'whois', 'mixed'
    domains: Set[str]
    emails: Set[str]
    github_org: Optional[str] = None
    website: Optional[str] = None
    description: Optional[str] = None


class OrganizationInferrer:
    """Infers organization information from repository metadata and content."""
    
    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        """Initialize organization inferrer.
        
        Args:
            session: HTTP session for external lookups
        """
        self.session = session
        
        # Common organization patterns
        self.org_patterns = {
            'company': re.compile(r'\b(inc|corp|ltd|llc|corporation|company|co\.)\b', re.IGNORECASE),
            'tech': re.compile(r'\b(tech|technology|technologies|systems|solutions|software|labs?)\b', re.IGNORECASE),
            'opensource': re.compile(r'\b(foundation|project|community|org|organization)\b', re.IGNORECASE)
        }
        
        # Email domain patterns that suggest organizations
        self.corporate_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com',
            'icloud.com', 'aol.com', 'live.com', 'msn.com'
        }
        
        # Known organization domains
        self.known_orgs = {
            'google.com': 'Google',
            'microsoft.com': 'Microsoft',
            'amazon.com': 'Amazon',
            'apple.com': 'Apple',
            'facebook.com': 'Meta',
            'meta.com': 'Meta',
            'netflix.com': 'Netflix',
            'uber.com': 'Uber',
            'airbnb.com': 'Airbnb',
            'github.com': 'GitHub',
            'gitlab.com': 'GitLab',
            'atlassian.com': 'Atlassian',
            'slack.com': 'Slack',
            'shopify.com': 'Shopify',
            'stripe.com': 'Stripe',
            'twilio.com': 'Twilio',
            'sendgrid.com': 'SendGrid',
            'mailgun.com': 'Mailgun',
            'cloudflare.com': 'Cloudflare',
            'aws.amazon.com': 'Amazon Web Services',
            'googleapis.com': 'Google',
            'azure.com': 'Microsoft Azure'
        }
    
    async def infer_from_repository(self, 
                                   repo_url: str,
                                   secret_matches: List[SecretMatch],
                                   endpoint_matches: List[EndpointMatch]) -> Optional[OrganizationInfo]:
        """Infer organization from repository and its contents.
        
        Args:
            repo_url: Repository URL
            secret_matches: Found secret matches
            endpoint_matches: Found endpoint matches
            
        Returns:
            Inferred organization info or None
        """
        candidates = []
        
        # Extract from GitHub metadata
        github_org = await self._infer_from_github_metadata(repo_url)
        if github_org:
            candidates.append(github_org)
        
        # Extract from email domains
        email_org = self._infer_from_emails(secret_matches, endpoint_matches)
        if email_org:
            candidates.append(email_org)
        
        # Extract from domains
        domain_org = self._infer_from_domains(endpoint_matches)
        if domain_org:
            candidates.append(domain_org)
        
        # Extract from content patterns
        content_org = self._infer_from_content_patterns(secret_matches, endpoint_matches)
        if content_org:
            candidates.append(content_org)
        
        # Choose best candidate
        return self._choose_best_candidate(candidates)
    
    async def _infer_from_github_metadata(self, repo_url: str) -> Optional[OrganizationInfo]:
        """Infer organization from GitHub repository metadata.
        
        Args:
            repo_url: Repository URL
            
        Returns:
            Organization info from GitHub metadata
        """
        if not repo_url.startswith('https://github.com/'):
            return None
        
        try:
            # Extract owner from URL
            path_parts = repo_url.replace('https://github.com/', '').split('/')
            if len(path_parts) < 2:
                return None
            
            owner = path_parts[0]
            
            # If session available, try to get more info from GitHub API
            if self.session:
                api_url = f"https://api.github.com/users/{owner}"
                try:
                    async with self.session.get(api_url) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            # Check if it's an organization
                            if data.get('type') == 'Organization':
                                return OrganizationInfo(
                                    name=data.get('name') or owner,
                                    confidence=0.9,
                                    source='github',
                                    domains=set(),
                                    emails=set(),
                                    github_org=owner,
                                    website=data.get('blog'),
                                    description=data.get('bio')
                                )
                            elif data.get('type') == 'User':
                                # Individual user - lower confidence
                                return OrganizationInfo(
                                    name=data.get('name') or owner,
                                    confidence=0.4,
                                    source='github',
                                    domains=set(),
                                    emails=set(),
                                    github_org=owner,
                                    website=data.get('blog'),
                                    description=data.get('bio')
                                )
                except aiohttp.ClientError:
                    pass
            
            # Fallback to owner name
            confidence = 0.7 if self._looks_like_organization(owner) else 0.3
            return OrganizationInfo(
                name=owner,
                confidence=confidence,
                source='github',
                domains=set(),
                emails=set(),
                github_org=owner
            )
        
        except Exception:
            return None
    
    def _infer_from_emails(self, 
                          secret_matches: List[SecretMatch],
                          endpoint_matches: List[EndpointMatch]) -> Optional[OrganizationInfo]:
        """Infer organization from email domains.
        
        Args:
            secret_matches: Secret matches that might contain emails
            endpoint_matches: Endpoint matches including emails
            
        Returns:
            Organization info from email domains
        """
        email_domains = set()
        
        # Extract emails from endpoint matches
        for match in endpoint_matches:
            if match.endpoint_type == 'email':
                domain = match.url.split('@')[1].lower()
                if domain not in self.corporate_domains:
                    email_domains.add(domain)
        
        # Extract emails from secret content (basic pattern)
        email_pattern = re.compile(r'\\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})\\b')
        for match in secret_matches:
            for email_match in email_pattern.finditer(match.snippet):
                domain = email_match.group(1).lower()
                if domain not in self.corporate_domains:
                    email_domains.add(domain)
        
        if not email_domains:
            return None
        
        # Find most common domain
        domain_counts = {}
        for domain in email_domains:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        
        most_common_domain = max(domain_counts, key=domain_counts.get)
        
        # Check if it's a known organization
        org_name = self.known_orgs.get(most_common_domain)
        if org_name:
            confidence = 0.8
        else:
            # Try to extract organization name from domain
            org_name = self._extract_org_from_domain(most_common_domain)
            confidence = 0.6
        
        return OrganizationInfo(
            name=org_name,
            confidence=confidence,
            source='email',
            domains=email_domains,
            emails=set()
        )
    
    def _infer_from_domains(self, endpoint_matches: List[EndpointMatch]) -> Optional[OrganizationInfo]:
        """Infer organization from discovered domains.
        
        Args:
            endpoint_matches: Endpoint matches containing domains
            
        Returns:
            Organization info from domains
        """
        domains = set()
        
        for match in endpoint_matches:
            domain = match.domain
            if domain and domain not in ['github.com', 'githubusercontent.com']:
                domains.add(domain.lower())
        
        if not domains:
            return None
        
        # Check for known organizations
        for domain in domains:
            if domain in self.known_orgs:
                return OrganizationInfo(
                    name=self.known_orgs[domain],
                    confidence=0.8,
                    source='domain',
                    domains=domains,
                    emails=set()
                )
        
        # Try to find organizational domain patterns
        org_domains = []
        for domain in domains:
            if self._looks_like_org_domain(domain):
                org_domains.append(domain)
        
        if org_domains:
            # Use the most "organizational" looking domain
            best_domain = max(org_domains, key=lambda d: self._calculate_org_score(d))
            org_name = self._extract_org_from_domain(best_domain)
            
            return OrganizationInfo(
                name=org_name,
                confidence=0.7,
                source='domain',
                domains=domains,
                emails=set()
            )
        
        return None
    
    def _infer_from_content_patterns(self,
                                   secret_matches: List[SecretMatch],
                                   endpoint_matches: List[EndpointMatch]) -> Optional[OrganizationInfo]:
        """Infer organization from content patterns.
        
        Args:
            secret_matches: Secret matches to analyze
            endpoint_matches: Endpoint matches to analyze
            
        Returns:
            Organization info from content patterns
        """
        # Look for organization patterns in file paths and content
        org_indicators = []
        
        # Check file paths for organization names
        for match in secret_matches + endpoint_matches:
            file_path = getattr(match, 'file_path', '')
            
            # Look for README files which often contain org info
            if 'readme' in file_path.lower():
                # In a real implementation, you'd read the README content
                # For now, we'll just note that it exists
                org_indicators.append('readme_found')
            
            # Look for configuration files
            if any(config in file_path.lower() for config in ['config', 'package.json', 'setup.py']):
                org_indicators.append('config_found')
        
        # This is a simplified implementation - in practice you'd analyze
        # actual file contents for organization names
        if org_indicators:
            return OrganizationInfo(
                name='Unknown Organization',
                confidence=0.3,
                source='content',
                domains=set(),
                emails=set()
            )
        
        return None
    
    def _looks_like_organization(self, name: str) -> bool:
        """Check if a name looks like an organization.
        
        Args:
            name: Name to check
            
        Returns:
            True if name looks organizational
        """
        name_lower = name.lower()
        
        # Check for organization patterns
        for pattern in self.org_patterns.values():
            if pattern.search(name_lower):
                return True
        
        # Check if it's all lowercase (often indicates org)
        if name.islower() and len(name) > 3:
            return True
        
        # Check for hyphen/underscore (common in org names)
        if '-' in name or '_' in name:
            return True
        
        return False
    
    def _looks_like_org_domain(self, domain: str) -> bool:
        """Check if domain looks organizational.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain looks organizational
        """
        # Skip common personal domains
        if domain in self.corporate_domains:
            return False
        
        # Skip obvious CDN/infrastructure domains
        infrastructure_patterns = ['cdn', 'aws', 'azure', 'gcp', 'herokuapp', 'netlify', 'vercel']
        if any(pattern in domain for pattern in infrastructure_patterns):
            return False
        
        # Look for organizational indicators
        domain_lower = domain.lower()
        for pattern in self.org_patterns.values():
            if pattern.search(domain_lower):
                return True
        
        # Custom TLDs often indicate organizations
        if domain.endswith(('.io', '.co', '.ai', '.tech', '.dev')):
            return True
        
        return True
    
    def _calculate_org_score(self, domain: str) -> float:
        """Calculate organizational score for a domain.
        
        Args:
            domain: Domain to score
            
        Returns:
            Organizational score (higher = more likely to be org)
        """
        score = 0.0
        domain_lower = domain.lower()
        
        # Check patterns
        for pattern in self.org_patterns.values():
            if pattern.search(domain_lower):
                score += 1.0
        
        # Custom TLD bonus
        if domain.endswith(('.io', '.co', '.ai', '.tech', '.dev')):
            score += 0.5
        
        # Length bonus (shorter domains often more valuable/organizational)
        if len(domain) < 15:
            score += 0.3
        
        return score
    
    def _extract_org_from_domain(self, domain: str) -> str:
        """Extract organization name from domain.
        
        Args:
            domain: Domain to extract from
            
        Returns:
            Extracted organization name
        """
        # Remove TLD
        parts = domain.split('.')
        if len(parts) > 1:
            base = parts[0]
        else:
            base = domain
        
        # Clean up common prefixes/suffixes
        base = re.sub(r'^(www|api|app|web)[-.]?', '', base, flags=re.IGNORECASE)
        base = re.sub(r'[-.]?(inc|corp|ltd|llc|co)$', '', base, flags=re.IGNORECASE)
        
        # Capitalize appropriately
        if base.islower():
            return base.title()
        
        return base
    
    def _choose_best_candidate(self, candidates: List[OrganizationInfo]) -> Optional[OrganizationInfo]:
        """Choose the best organization candidate from multiple options.
        
        Args:
            candidates: List of candidate organizations
            
        Returns:
            Best candidate or None
        """
        if not candidates:
            return None
        
        if len(candidates) == 1:
            return candidates[0]
        
        # Sort by confidence
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        
        # If top candidate has significantly higher confidence, use it
        best = candidates[0]
        if best.confidence > 0.6:
            return best
        
        # Otherwise, try to merge information from multiple candidates
        merged_domains = set()
        merged_emails = set()
        sources = []
        
        for candidate in candidates:
            merged_domains.update(candidate.domains)
            merged_emails.update(candidate.emails)
            sources.append(candidate.source)
        
        # Use the name from highest confidence candidate
        return OrganizationInfo(
            name=best.name,
            confidence=min(best.confidence + 0.1, 1.0),  # Small boost for multiple sources
            source='mixed',
            domains=merged_domains,
            emails=merged_emails,
            github_org=best.github_org,
            website=best.website,
            description=best.description
        )
