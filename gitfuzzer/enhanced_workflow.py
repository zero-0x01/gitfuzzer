"""Enhanced GitFuzzer workflow with relationship discovery and advanced Telegram reporting."""

import asyncio
import logging
from typing import List, Dict, Any
import httpx

from .gh_scanner import GitHubScanner
from .analyzer import analyze_repository
from .keyword_gen import generate
from .config import Settings

logger = logging.getLogger(__name__)


async def run_enhanced_scan(keywords: str, config: Settings):
    """Run enhanced GitFuzzer scan with all new features."""
    
    print("🚀 GITFUZZER ENHANCED SCAN")
    print("=" * 80)
    print(f"🔍 Keywords: {keywords}")
    print(f"📊 Analysis count: {config.analysis_count}")
    if config.language_filter:
        print(f"🗣️ Language filter: {config.language_filter}")
    if config.specific_repo:
        print(f"🎯 Specific repository: {config.specific_repo}")
    if config.extended_files:
        print(f"📁 Extended file scanning: 40+ files")
    if config.whole_code:
        print(f"💾 Whole code scanning: All repository files")
    if config.must_have_relationships:
        print(f"🔗 Filtering by organizational relationships")
    print("=" * 80)
    
    # Handle specific repository mode
    if config.specific_repo:
        return await run_specific_repo_scan(config.specific_repo, config)
    
    # Phase 1: Enhanced GitHub scanning
    print("\n🔍 PHASE 1: ENHANCED GITHUB SCANNING")
    print("-" * 60)
    
    # Create a complete config object for the scanner
    class NestedConfig:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)
    
    class ScannerConfig:
        def __init__(self, tokens):
            self.gh_tokens = tokens
            
            # Scanner configuration
            self.scanner = NestedConfig(
                timeout=30,
                per_page=100,
                retry_attempts=3,
                max_results=1000,
                max_concurrency=5,
                slice_days=7,
                max_age_days=365
            )
            
            # Analyzer configuration  
            self.analyzer = NestedConfig(
                min_stars=0,
                max_age_days=365
            )
            
            # Deep linker configuration
            self.deep_linker = NestedConfig(
                user_agent="GitFuzzer/1.0"
            )
    
    scanner_config = ScannerConfig(config.github_tokens)
    
    # Generate enhanced keywords
    enhanced_keywords = await generate(keywords, count=10)
    print(f"📝 Generated keywords: {', '.join(enhanced_keywords[:5])}...")
    
    # Enhanced repository discovery with proper async context
    repositories = []
    async with GitHubScanner(scanner_config) as scanner:
        if getattr(config, 'code_search', False):
            print("🔍 Using CODE SEARCH mode - searching through actual source code files")
            repos = await scanner.search_code(
                enhanced_keywords[:3],  # Limit keywords for code search
                language=config.language_filter,
                max_results=config.analysis_count * 2,  # Get extra to account for filtering
                created_after=getattr(config, 'created_after', None),
                pushed_after=getattr(config, 'pushed_after', None)
            )
            repositories.extend(repos)
            print(f"📊 Code search found {len(repos)} repositories with code matches")
        else:
            print("🔍 Using REPOSITORY SEARCH mode - searching repository names/descriptions/READMEs")
            # Calculate how many repos to get per keyword to reach target count
            keywords_to_use = min(5, len(enhanced_keywords))
            repos_per_keyword = max(1, (config.analysis_count + keywords_to_use - 1) // keywords_to_use)  # Ceiling division
            
            print(f"🎯 Target: {config.analysis_count} repos, using {keywords_to_use} keywords, {repos_per_keyword} repos per keyword")
            
            for i, keyword in enumerate(enhanced_keywords[:keywords_to_use]):
                print(f"🔍 Keyword {i+1}/{keywords_to_use}: '{keyword}'")
                
                # Each keyword should try to get enough repos to meet our target
                repos = await scanner.search_repositories_enhanced(
                    keyword, 
                    count=repos_per_keyword,
                    language=config.language_filter
                )
                repositories.extend(repos)
                print(f"   📊 Found {len(repos)} repositories for '{keyword}'")
    
    # Remove duplicates
    unique_repos = {}
    for repo in repositories:
        unique_repos[repo['full_name']] = repo
    repositories = list(unique_repos.values())
    
    print(f"📊 Found {len(repositories)} unique repositories")
    
    # Phase 2: Enhanced secret detection
    print("\n🔍 PHASE 2: ENHANCED SECRET DETECTION")
    print("-" * 60)
    
    analyzed_repos = []
    secrets_found = 0
    
    for i, repo in enumerate(repositories[:config.analysis_count]):
        print(f"📁 Analyzing repository {i+1}/{min(len(repositories), config.analysis_count)}: {repo['full_name']}")
        
        # Create a simple object that supports both dict access and attribute access
        class RepoObj:
            def __init__(self, repo_dict):
                self.__dict__.update(repo_dict)
                self.full_name = repo_dict['full_name']
                self.description = repo_dict.get('description', '')
                self.stars = repo_dict.get('stargazers_count', 0)
                self.forks = repo_dict.get('forks_count', 0)
                self.language = repo_dict.get('language', '')
                self.created_at = repo_dict.get('created_at')
                self.updated_at = repo_dict.get('updated_at')
        
        repo_obj = RepoObj(repo)
        
        # Determine scan mode based on config
        scan_mode = "standard"
        if config.whole_code:
            scan_mode = "whole"
        elif config.extended_files:
            scan_mode = "extended"
        
        try:
            analysis_result = await analyze_repository(repo_obj, config.github_tokens[0], scan_mode)
            if analysis_result and hasattr(analysis_result, 'secrets_found') and analysis_result.secrets_found:
                secrets_found += len(analysis_result.secrets_found)
                analyzed_repos.append({
                    'repo': repo,
                    'analysis': analysis_result
                })
                print(f"   🚨 Found {len(analysis_result.secrets_found)} secrets!")
            else:
                print(f"   ✅ No secrets found")
        except Exception as e:
            logger.error(f"Error analyzing {repo['full_name']}: {e}")
            print(f"   ❌ Analysis failed: {e}")
    
    print(f"\n📊 SUMMARY: {len(analyzed_repos)} repos with secrets, {secrets_found} total secrets found")
    
    # Phase 3: Relationship discovery (ALWAYS RUN)
    print("\n🔍 PHASE 3: RELATIONSHIP DISCOVERY")
    print("-" * 60)
    
    all_relationships = []
    repos_with_relationships = []
    
    # Discover relationships for all analyzed repos
    for repo_data in analyzed_repos:
        relationships = await discover_relationships(repo_data['repo'], config)
        if relationships:
            all_relationships.extend(relationships)
            repo_data['relationships'] = relationships
            repos_with_relationships.append(repo_data)
    
    print(f"📊 Found organizational relationships for {len(repos_with_relationships)} repositories")
    
    # Filter by relationships if required
    if config.must_have_relationships:
        filtered_repos = repos_with_relationships
        print(f"🔗 Filtered to {len(filtered_repos)} repositories with organizational relationships")
    else:
        filtered_repos = analyzed_repos
        print(f"📋 Including all {len(filtered_repos)} repositories (relationships optional)")
    
    # Phase 4: Enhanced Telegram reporting
    if config.telegram_enabled and filtered_repos:
        print("\n📱 PHASE 4: ENHANCED TELEGRAM REPORTING")
        print("-" * 60)
        
        # Validate Telegram configuration
        if not config.telegram_bot_token or not config.telegram_bot_token.strip():
            print("❌ Telegram bot token not configured. Set TELEGRAM_BOT_TOKEN environment variable.")
            print("💡 To get a bot token:")
            print("   1. Message @BotFather on Telegram")
            print("   2. Use /newbot command")
            print("   3. Follow instructions to create your bot")
            print("   4. Copy the token and set: export TELEGRAM_BOT_TOKEN='your_token'")
        elif not config.telegram_chat_id or not config.telegram_chat_id.strip():
            print("❌ Telegram chat ID not configured. Set TELEGRAM_CHAT_ID environment variable.")
            print("💡 To get your chat ID:")
            print("   1. Start a chat with your bot")
            print("   2. Send any message")
            print("   3. Visit: https://api.telegram.org/bot{TOKEN}/getUpdates")
            print("   4. Look for 'chat':{'id': YOUR_CHAT_ID}")
        else:
            try:
                from .enhanced_telegram_reporter_new import EnhancedTelegramReporter
                report_mode = "all_in_one" if config.in_one_message else "one_by_one"
                reporter = EnhancedTelegramReporter(
                    config.telegram_bot_token,
                    config.telegram_chat_id,
                    report_mode
                )
                
                # Convert AnalysisResult objects to dictionaries for Telegram reporter
                telegram_data = []
                for repo_analysis in filtered_repos:
                    if isinstance(repo_analysis, dict) and 'repo' in repo_analysis and 'analysis' in repo_analysis:
                        repo = repo_analysis['repo']  # This is a dictionary
                        analysis = repo_analysis['analysis']  # This is an AnalysisResult object
                        
                        # Extract repository info (repo is already a dict)
                        repo_dict = {
                            'full_name': repo.get('full_name', ''),
                            'html_url': repo.get('html_url', ''),
                            'stargazers_count': repo.get('stargazers_count', 0),
                            'language': repo.get('language', 'Unknown'),
                            'pushed_at': repo.get('pushed_at', ''),
                            'default_branch': repo.get('default_branch', 'main'),
                            'owner': repo.get('owner', {}),
                            'description': repo.get('description', '')
                        }
                        
                        # Convert AnalysisResult to dictionary
                        analysis_dict = {
                            'secrets': getattr(analysis, 'secrets_found', []),
                            'has_secrets': getattr(analysis, 'has_secrets', False),
                            'risk_score': getattr(analysis, 'risk_score', 0)
                        }
                        
                        telegram_data.append({
                            'repo': repo_dict,
                            'analysis': analysis_dict,
                            'relationships': repo_analysis.get('relationships', [])
                        })
                    else:
                        print(f"🔍 Debug: Unexpected repo_analysis structure: {type(repo_analysis)}")
                
                print(f"🔍 Debug: Prepared {len(telegram_data)} repositories for Telegram reporting")
                
                # Determine scan type for reporting
                scan_type = "codebase" if config.code_search else "repository"
                
                # Send enhanced Telegram report (mode is set in reporter initialization)
                await reporter.send_enhanced_report(telegram_data, ', '.join(keywords), scan_type)
                print("✅ Enhanced Telegram report sent successfully!")
                
            except Exception as e:
                logger.error(f"Telegram reporting failed: {e}")
                print(f"❌ Telegram reporting failed: {e}")
                print("💡 Check your Telegram bot token and chat ID configuration")
    
    # Final summary
    print("\n🏁 ENHANCED SCAN COMPLETE")
    print("=" * 80)
    print(f"📊 Repositories analyzed: {len(repositories)}")
    print(f"🚨 Repositories with secrets: {len(analyzed_repos)}")
    print(f"🔍 Total secrets found: {secrets_found}")
    if config.must_have_relationships:
        print(f"🔗 Repositories with relationships: {len(analyzed_repos)}")
    print("=" * 80)


async def run_specific_repo_scan(repo_name: str, config: Settings):
    """Run enhanced scan on a specific repository."""
    
    print("🎯 SPECIFIC REPOSITORY SCAN")
    print("=" * 80)
    print(f"📁 Repository: {repo_name}")
    if config.extended_files:
        print(f"📁 Extended file scanning: 40+ files")
    if config.whole_code:
        print(f"💾 Whole code scanning: All repository files")
    print("=" * 80)
    
    # Create repository object
    repo = {
        'full_name': repo_name,
        'name': repo_name.split('/')[-1],
        'html_url': f"https://github.com/{repo_name}",
        'description': f"Specific scan of {repo_name}",
        'owner': {'login': repo_name.split('/')[0]},
        'stargazers_count': 0,
        'forks_count': 0,
        'language': None,
        'created_at': None,
        'updated_at': None,
        'pushed_at': None,
        'default_branch': 'main',
        'topics': []
    }
    
    # Phase 2: Enhanced secret detection
    print("\n🔍 PHASE 2: ENHANCED SECRET DETECTION")
    print("-" * 60)
    
    class RepoObj:
        def __init__(self, repo_dict):
            self.__dict__.update(repo_dict)
            self.full_name = repo_dict['full_name']
            self.description = repo_dict.get('description', '')
            self.stars = repo_dict.get('stargazers_count', 0)
            self.forks = repo_dict.get('forks_count', 0)
            self.language = repo_dict.get('language', '')
            self.created_at = repo_dict.get('created_at')
            self.updated_at = repo_dict.get('updated_at')
    
    repo_obj = RepoObj(repo)
    
    # Determine scan mode
    scan_mode = "standard"
    if config.whole_code:
        scan_mode = "whole"
    elif config.extended_files:
        scan_mode = "extended"
    
    try:
        analysis_result = await analyze_repository(repo_obj, config.github_tokens[0], scan_mode)
        
        if analysis_result and hasattr(analysis_result, 'secrets_found') and analysis_result.secrets_found:
            print(f"🚨 Found {len(analysis_result.secrets_found)} secrets!")
            analyzed_repos = [{
                'repo': repo,
                'analysis': analysis_result
            }]
        else:
            print("✅ No secrets found")
            analyzed_repos = []
            
    except Exception as e:
        logger.error(f"Error analyzing {repo_name}: {e}")
        print(f"❌ Analysis failed: {e}")
        analyzed_repos = []
    
    # Phase 3: Relationship discovery (ALWAYS RUN)
    print("\n🔍 PHASE 3: RELATIONSHIP DISCOVERY")
    print("-" * 60)
    
    relationships = await discover_relationships(repo, config)
    if relationships:
        print(f"🔗 Found {len(relationships)} organizational relationships")
        if analyzed_repos:
            analyzed_repos[0]['relationships'] = relationships
    else:
        print("❌ No organizational relationships found")
    
    # Phase 4: Enhanced Telegram reporting
    if config.telegram_enabled and analyzed_repos:
        print("\n📱 PHASE 4: ENHANCED TELEGRAM REPORTING")
        print("-" * 60)
        
        # Validate Telegram configuration
        if not config.telegram_bot_token or not config.telegram_bot_token.strip():
            print("❌ Telegram bot token not configured. Set TELEGRAM_BOT_TOKEN environment variable.")
            print("💡 To get a bot token:")
            print("   1. Message @BotFather on Telegram")
            print("   2. Use /newbot command")
            print("   3. Follow instructions to create your bot")
            print("   4. Copy the token and set: export TELEGRAM_BOT_TOKEN='your_token'")
        elif not config.telegram_chat_id or not config.telegram_chat_id.strip():
            print("❌ Telegram chat ID not configured. Set TELEGRAM_CHAT_ID environment variable.")
            print("💡 To get your chat ID:")
            print("   1. Start a chat with your bot")
            print("   2. Send any message")
            print("   3. Visit: https://api.telegram.org/bot{TOKEN}/getUpdates")
            print("   4. Look for 'chat':{'id': YOUR_CHAT_ID}")
        else:
            try:
                from .enhanced_telegram_reporter_new import EnhancedTelegramReporter
                report_mode = "all_in_one" if config.in_one_message else "one_by_one"
                reporter = EnhancedTelegramReporter(
                    config.telegram_bot_token,
                    config.telegram_chat_id,
                    report_mode
                )
                
                # Convert AnalysisResult objects to dictionaries for Telegram reporter
                telegram_data = []
                for repo_data in analyzed_repos:
                    if isinstance(repo_data, dict) and 'repo' in repo_data and 'analysis' in repo_data:
                        # Check if analysis is an AnalysisResult object
                        analysis = repo_data['analysis']
                        if hasattr(analysis, 'secrets_found'):
                            # Convert AnalysisResult to dict
                            analysis_dict = {
                                'secrets': getattr(analysis, 'secrets_found', []),
                                'has_secrets': getattr(analysis, 'has_secrets', False),
                                'risk_score': getattr(analysis, 'risk_score', 0)
                            }
                            telegram_data.append({
                                'repo': repo_data['repo'],
                                'analysis': analysis_dict
                            })
                        else:
                            # Already a dict
                            telegram_data.append(repo_data)
                            
                # Determine scan type for reporting
                scan_type = "repository"  # Single repo analysis is always repository mode
                
                await reporter.send_enhanced_report(telegram_data, repo_name, scan_type)
                print("✅ Enhanced Telegram report sent successfully!")
                
            except Exception as e:
                logger.error(f"Telegram reporting failed: {e}")
                print(f"❌ Telegram reporting failed: {e}")
                print("💡 Check your Telegram bot token and chat ID configuration")
    
    # Final summary
    print("\n🏁 SPECIFIC REPOSITORY SCAN COMPLETE")
    print("=" * 80)
    print(f"📁 Repository: {repo_name}")
    print(f"🚨 Secrets found: {len(analyzed_repos[0]['analysis'].secrets_found) if analyzed_repos else 0}")
    print(f"🔗 Relationships found: {len(relationships) if relationships else 0}")
    print("=" * 80)


async def discover_relationships(repo: Dict[str, Any], config: Settings) -> List[Dict[str, Any]]:
    """Discover organizational relationships for a repository."""
    
    relationships = []
    
    try:
        # Extract potential domains and IPs from repository metadata
        repo_info = {
            'owner': repo.get('owner', {}).get('login', ''),
            'name': repo.get('name', ''),
            'description': repo.get('description', ''),
            'homepage': repo.get('homepage', ''),
            'topics': repo.get('topics', [])
        }
        
        # Look for domain patterns
        import re
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        
        text_to_search = f"{repo_info['description']} {repo_info['homepage']} {' '.join(repo_info['topics'])}"
        domains = re.findall(domain_pattern, text_to_search)
        
        # Add domain relationships
        for domain in domains[:3]:  # Limit to prevent spam
            relationships.append({
                'type': 'domain',
                'value': domain,
                'source': 'repository_metadata'
            })
        
        # Use Shodan API if available
        if hasattr(config, 'shodan_api_key') and config.shodan_api_key:
            shodan_relationships = await discover_shodan_relationships(repo_info, config.shodan_api_key)
            relationships.extend(shodan_relationships)
        
        # Look for organizational indicators
        org_indicators = [
            'company', 'corp', 'inc', 'ltd', 'llc', 'org', 'enterprise', 'business'
        ]
        
        owner_name = repo_info['owner'].lower()
        for indicator in org_indicators:
            if indicator in owner_name:
                relationships.append({
                    'type': 'organization',
                    'value': repo_info['owner'],
                    'source': 'owner_name_analysis'
                })
                break
        
    except Exception as e:
        logger.error(f"Error discovering relationships: {e}")
    
    return relationships


async def discover_shodan_relationships(repo_info: Dict[str, Any], shodan_api_key: str) -> List[Dict[str, Any]]:
    """Use Shodan API to discover infrastructure relationships."""
    
    relationships = []
    
    try:
        # Extract domains for Shodan lookup
        import re
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        
        text_to_search = f"{repo_info.get('description', '')} {repo_info.get('homepage', '')}"
        domains = re.findall(domain_pattern, text_to_search)
        
        # Query Shodan for each domain
        async with httpx.AsyncClient(timeout=10.0) as client:
            for domain in domains[:2]:  # Limit API calls
                try:
                    response = await client.get(
                        f"https://api.shodan.io/shodan/host/search",
                        params={
                            'key': shodan_api_key,
                            'query': f'hostname:{domain}',
                            'limit': 1
                        }
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('matches'):
                            match = data['matches'][0]
                            relationships.append({
                                'type': 'ip_address',
                                'value': match.get('ip_str'),
                                'source': 'shodan_api',
                                'domain': domain,
                                'organization': match.get('org', 'Unknown')
                            })
                            
                except Exception as e:
                    logger.debug(f"Shodan lookup failed for {domain}: {e}")
                    continue
    
    except Exception as e:
        logger.error(f"Shodan relationship discovery failed: {e}")
    
    return relationships
