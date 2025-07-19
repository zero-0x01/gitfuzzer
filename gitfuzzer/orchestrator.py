"""
GitFuzzer Orchestrator - Main generation workflow coordinator
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set

from .config import Settings
from .keyword_gen import generate as generate_keywords
from .gh_scanner import scan_github_repositories as github_search  
from .analyzer import analyze_repository
from .enhanced_telegram_reporter_new import EnhancedTelegramReporter

logger = logging.getLogger(__name__)


class GitFuzzerOrchestrator:
    """Main orchestrator for GitFuzzer generation workflow."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.telegram = EnhancedTelegramReporter(
            settings.telegram_bot_token, 
            settings.telegram_chat_id
        ) if settings.telegram_bot_token and settings.telegram_chat_id else None
        
    async def run_generation(self, subject: str, chat_id: Optional[int] = None) -> Dict:
        """Run a complete generation cycle."""
        generation_id = f"gen_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        logger.info(f"Starting generation {generation_id} for subject: {subject}")
        
        try:
            # Generate keywords
            logger.info(f"Generating keywords for subject: {subject}")
            keywords = await generate_keywords(subject, count=self.settings.keywords, hf_token=self.settings.hf_token or "")
            
            logger.info(f"Generated {len(keywords)} keywords: {keywords}")
            
            # Search repositories
            logger.info(f"Searching GitHub with keywords: {keywords}")
            repos = await github_search(
                keywords,
                self.settings,
                language=getattr(self.settings, 'language_filter', None),
                max_results=self.settings.analysis_count * len(keywords)
            )
            
            logger.info(f"Found {len(repos)} repositories")
            
            # Analyze repositories for secrets
            analyzed_repos = []
            interesting_count = 0
            
            for repo in repos[:self.settings.analysis_count]:
                logger.info(f"Analyzing repository: {repo.full_name}")
                
                analysis = await analyze_repository(repo, self.settings.github_token)
                
                analyzed_repos.append({
                    'repo': repo,
                    'analysis': analysis
                })
                
                if analysis.has_secrets:
                    interesting_count += 1
                    logger.info(f"Found {len(analysis.secrets)} secrets in {repo.full_name}")
                    
                    # Send individual reports via Telegram
                    if self.telegram and chat_id:
                        await self.telegram.send_enhanced_report(repo, analysis, chat_id)
            
            # Send Telegram summary if configured
            if self.telegram and chat_id:
                logger.info("Sending Telegram summary...")
                await self.telegram.send_message(
                    f"🚀 **GitFuzzer Generation Complete**\n\n"
                    f"📊 **Results:**\n"
                    f"🔤 Subject: `{subject}`\n"
                    f"🔍 Keywords: {len(keywords)}\n"
                    f"📁 Repositories found: {len(repos)}\n"
                    f"🚨 Repositories with secrets: {interesting_count}\n"
                    f"📅 Generation ID: `{generation_id}`"
                )
            
            return {
                'generation_id': generation_id,
                'subject': subject,
                'keywords': keywords,
                'total_repos': len(repos),
                'new_repos': len(repos),  # All are considered new in this simple implementation
                'interesting_repos': interesting_count,
                'analyzed_repos': len(analyzed_repos)
            }
            
        except Exception as e:
            logger.error(f"Generation {generation_id} failed: {e}")
            raise


async def run_generation_single(subject: str, settings: Settings, verbose: bool = False) -> Dict:
    """Single-shot generation run (CLI interface)."""
    
    if verbose:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    orchestrator = GitFuzzerOrchestrator(settings)
    
    # Use Telegram chat from settings if available
    chat_id = None
    if settings.telegram_bot_token and settings.telegram_chat_id:
        try:
            chat_id = int(settings.telegram_chat_id)
        except (ValueError, TypeError):
            logger.warning("Invalid telegram_chat_id in settings")
    
    return await orchestrator.run_generation(subject, chat_id)
