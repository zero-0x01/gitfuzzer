"""Repository scanner for GitFuzzer fuzz module.

This module downloads and scans repository contents for secrets,
endpoints, and other sensitive information.
"""

import asyncio
import mimetypes
import os
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional, Set, Tuple
import aiohttp
import aiofiles

from .secret_rules import SecretRuleEngine, SecretMatch
from .endpoint_extractor import EndpointExtractor, EndpointMatch
from .org_infer import OrganizationInferrer, OrganizationInfo
from .score import RiskScorer, RiskAssessment


class RepositoryScanner:
    """Scanner for repository contents using GitHub archive API."""
    
    def __init__(self, 
                 secret_engine: Optional[SecretRuleEngine] = None,
                 endpoint_extractor: Optional[EndpointExtractor] = None,
                 org_inferrer: Optional[OrganizationInferrer] = None,
                 risk_scorer: Optional[RiskScorer] = None):
        """Initialize repository scanner.
        
        Args:
            secret_engine: Secret detection engine
            endpoint_extractor: Endpoint extraction engine
            org_inferrer: Organization inference engine
            risk_scorer: Risk scoring engine
        """
        self.secret_engine = secret_engine or SecretRuleEngine()
        self.endpoint_extractor = endpoint_extractor or EndpointExtractor()
        self.org_inferrer = org_inferrer or OrganizationInferrer()
        self.risk_scorer = risk_scorer or RiskScorer()
        
        # Directories to skip
        self.skip_dirs = {
            'node_modules', 'vendor', 'venv', '.git', '.svn', 'dist', 'build',
            'target', 'out', 'bin', 'obj', '__pycache__', '.pytest_cache',
            '.coverage', 'coverage', 'logs', 'log', 'tmp', 'temp', '.tmp',
            '.vscode', '.idea', '.vs', 'bower_components', 'jspm_packages'
        }
        
        # File extensions to skip
        self.skip_extensions = {
            '.pyc', '.pyo', '.pyd', '.class', '.jar', '.war', '.ear',
            '.exe', '.dll', '.so', '.dylib', '.a', '.lib', '.o', '.obj',
            '.bin', '.dat', '.db', '.sqlite', '.sqlite3',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.ico',
            '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
            '.min.js', '.min.css'
        }
        
        # Maximum file size to scan (5MB)
        self.max_file_size = 5 * 1024 * 1024
    
    async def download_repository(self, repo_url: str, session: aiohttp.ClientSession, 
                                 temp_dir: Optional[str] = None) -> str:
        """Download repository as ZIP archive.
        
        Args:
            repo_url: Repository URL (e.g., 'https://github.com/owner/repo')
            session: HTTP session for downloads
            temp_dir: Temporary directory path
            
        Returns:
            Path to extracted repository directory
            
        Raises:
            aiohttp.ClientError: If download fails
        """
        # Parse repository URL
        if not repo_url.startswith('https://github.com/'):
            raise ValueError(f"Invalid GitHub repository URL: {repo_url}")
        
        # Extract owner and repo name
        path_parts = repo_url.replace('https://github.com/', '').split('/')
        if len(path_parts) < 2:
            raise ValueError(f"Invalid repository path: {repo_url}")
        
        owner, repo = path_parts[0], path_parts[1]
        
        # Construct archive URL
        archive_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
        
        # Create temp directory
        if temp_dir is None:
            temp_dir = tempfile.mkdtemp(prefix='gitfuzzer_')
        
        zip_path = os.path.join(temp_dir, f"{owner}_{repo}.zip")
        extract_path = os.path.join(temp_dir, f"{owner}_{repo}")
        
        # Download archive
        async with session.get(archive_url) as response:
            response.raise_for_status()
            
            async with aiofiles.open(zip_path, 'wb') as f:
                async for chunk in response.content.iter_chunked(8192):
                    await f.write(chunk)
        
        # Extract archive
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        
        # Find the actual repository directory (GitHub creates a subdirectory)
        for item in os.listdir(extract_path):
            item_path = os.path.join(extract_path, item)
            if os.path.isdir(item_path):
                return item_path
        
        raise RuntimeError(f"No directory found in extracted archive: {extract_path}")
    
    def should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped based on path and extension.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file should be skipped
        """
        # Check if any parent directory should be skipped
        for part in file_path.parts:
            if part in self.skip_dirs:
                return True
        
        # Check file extension
        if file_path.suffix.lower() in self.skip_extensions:
            return True
        
        # Check file size
        try:
            if file_path.stat().st_size > self.max_file_size:
                return True
        except (OSError, FileNotFoundError):
            return True
        
        # Check if it's a binary file using MIME type
        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type and not mime_type.startswith('text/'):
            # Allow some specific binary types that might contain secrets
            allowed_types = {
                'application/json', 'application/xml', 'application/yaml',
                'application/x-yaml', 'application/javascript'
            }
            if mime_type not in allowed_types:
                return True
        
        return False
    
    async def scan_file_content(self, file_path: Path) -> Tuple[List[SecretMatch], List[EndpointMatch]]:
        """Scan a single file for secrets and endpoints.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            Tuple of (secret matches, endpoint matches)
        """
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = await f.read()
        except (UnicodeDecodeError, OSError):
            # Skip files that can't be read as text
            return [], []
        
        # Scan for secrets
        secret_matches = self.secret_engine.scan_content(content, str(file_path))
        
        # Extract endpoints
        endpoint_matches = self.endpoint_extractor.extract_from_content(content, str(file_path))
        
        return secret_matches, endpoint_matches
    
    async def stream_repository_files(self, repo_path: str) -> AsyncGenerator[Path, None]:
        """Stream files from repository directory.
        
        Args:
            repo_path: Path to repository directory
            
        Yields:
            Path objects for files to scan
        """
        repo_root = Path(repo_path)
        
        for file_path in repo_root.rglob('*'):
            if file_path.is_file() and not self.should_skip_file(file_path):
                yield file_path
    
    async def scan_repository_content(self, repo_path: str) -> Tuple[List[SecretMatch], List[EndpointMatch]]:
        """Scan all files in a repository for secrets and endpoints.
        
        Args:
            repo_path: Path to repository directory
            
        Returns:
            Tuple of (all secret matches, all endpoint matches)
        """
        all_secret_matches = []
        all_endpoint_matches = []
        
        # Process files concurrently with semaphore to limit memory usage
        semaphore = asyncio.Semaphore(10)
        
        async def scan_file(file_path: Path) -> Tuple[List[SecretMatch], List[EndpointMatch]]:
            async with semaphore:
                return await self.scan_file_content(file_path)
        
        # Collect all scan tasks
        tasks = []
        async for file_path in self.stream_repository_files(repo_path):
            task = asyncio.create_task(scan_file(file_path))
            tasks.append(task)
        
        # Process results as they complete
        for completed_task in asyncio.as_completed(tasks):
            try:
                secret_matches, endpoint_matches = await completed_task
                all_secret_matches.extend(secret_matches)
                all_endpoint_matches.extend(endpoint_matches)
            except Exception as e:
                # Log error but continue processing other files
                continue
        
        return all_secret_matches, all_endpoint_matches


class FuzzResult:
    """Complete fuzz scan result for a repository."""
    
    def __init__(self,
                 repo_url: str,
                 secret_matches: List[SecretMatch],
                 endpoint_matches: List[EndpointMatch],
                 organization: Optional[OrganizationInfo],
                 risk_assessment: RiskAssessment):
        self.repo_url = repo_url
        self.secret_matches = secret_matches
        self.endpoint_matches = endpoint_matches
        self.organization = organization
        self.risk_assessment = risk_assessment
        self.scan_timestamp = asyncio.get_event_loop().time()
    
    @property
    def secrets_found(self) -> int:
        """Number of secrets found."""
        return len(self.secret_matches)
    
    @property
    def endpoints_found(self) -> int:
        """Number of endpoints found."""
        return len(self.endpoint_matches)
    
    @property
    def live_endpoints(self) -> List[EndpointMatch]:
        """List of live endpoints."""
        return [ep for ep in self.endpoint_matches if ep.is_live]
    
    @property
    def high_confidence_secrets(self) -> List[SecretMatch]:
        """List of high confidence secrets."""
        return [secret for secret in self.secret_matches if secret.confidence > 0.8]


async def fuzz_repo(repo_url: str, 
                   session: Optional[aiohttp.ClientSession] = None,
                   config: Optional[Dict] = None) -> FuzzResult:
    """Main function to fuzz a repository for secrets and endpoints.
    
    Args:
        repo_url: Repository URL to scan
        session: HTTP session (created if not provided)
        config: Configuration dictionary
        
    Returns:
        FuzzResult containing all findings
        
    Raises:
        Exception: If scanning fails
    """
    config = config or {}
    close_session = session is None
    
    if session is None:
        timeout = aiohttp.ClientTimeout(total=30)
        session = aiohttp.ClientSession(timeout=timeout)
    
    try:
        # Initialize components
        secret_engine = SecretRuleEngine(config.get('custom_rules'))
        endpoint_extractor = EndpointExtractor(session)
        org_inferrer = OrganizationInferrer(session)
        risk_scorer = RiskScorer(config.get('scoring', {}))
        
        scanner = RepositoryScanner(
            secret_engine=secret_engine,
            endpoint_extractor=endpoint_extractor,
            org_inferrer=org_inferrer,
            risk_scorer=risk_scorer
        )
        
        # Download repository
        with tempfile.TemporaryDirectory(prefix='gitfuzzer_') as temp_dir:
            repo_path = await scanner.download_repository(repo_url, session, temp_dir)
            
            # Scan repository content
            secret_matches, endpoint_matches = await scanner.scan_repository_content(repo_path)
            
            # Validate endpoints
            await endpoint_extractor.validate_endpoints([ep.url for ep in endpoint_matches])
            
            # Infer organization
            organization = await org_inferrer.infer_from_repository(repo_url, secret_matches, endpoint_matches)
            
            # Calculate risk score
            risk_assessment = risk_scorer.assess_risk(secret_matches, endpoint_matches, organization)
            
            return FuzzResult(
                repo_url=repo_url,
                secret_matches=secret_matches,
                endpoint_matches=endpoint_matches,
                organization=organization,
                risk_assessment=risk_assessment
            )
    
    finally:
        if close_session and session:
            await session.close()
