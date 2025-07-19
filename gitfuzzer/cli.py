"""CLI interface for GitFuzzer."""

import typer
import asyncio
import os
import logging
from pathlib import Path

from .config import Settings
from .enhanced_workflow import run_enhanced_scan
from .orchestrator import run_generation_single

app = typer.Typer(help="GitFuzzer - AI-powered GitHub repository discovery and analysis tool")

def setup_logging(level: str = "INFO"):
    """Setup basic logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )


@app.command()
def scan(
    keywords: str = typer.Argument(..., help="Search keywords (e.g., 'internal config', 'private api')"),
    config_file: str = typer.Option(None, "--config", "-c", help="Path to config file"),
    count: int = typer.Option(20, "--count", help="Number of repositories to analyze"),
    telegram: bool = typer.Option(False, "--telegram", help="Enable Telegram reporting"),
    lang: str = typer.Option(None, "--lang", help="Filter by programming language (e.g., python, javascript)"),
    must_relative: bool = typer.Option(False, "--must-relative", help="Only report repos with organizational relationships"),
    repo: str = typer.Option(None, "--repo", help="Analyze specific repository (e.g., 'owner/repo')"),
    extended_files: bool = typer.Option(False, "--extended-files", help="Scan extended list of files (40+ files)"),
    whole_code: bool = typer.Option(False, "--whole-code", help="Scan entire repository code (all files)"),
    code_search: bool = typer.Option(False, "--code-search", help="Search through actual code files (not just repo names/descriptions)"),
    in_one: bool = typer.Option(False, "--in-one", help="Send all Telegram findings in one consolidated message"),
    created_after: str = typer.Option(None, "--created-after", help="Filter repos created after date (YYYY-MM-DD)"),
    pushed_after: str = typer.Option(None, "--pushed-after", help="Filter repos pushed after date (YYYY-MM-DD)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """Enhanced GitHub repository discovery and secret analysis."""
    
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    setup_logging(log_level)
    
    logger = logging.getLogger(__name__)
    logger.info(f"GitFuzzer Enhanced starting with keywords: '{keywords}'")
    
    # Load configuration
    config = Settings.load(config_file)
    
    # Override settings from CLI
    config.analysis_count = count
    config.telegram_enabled = telegram
    config.language_filter = lang
    config.must_have_relationships = must_relative
    
    # New settings for enhanced scanning
    config.specific_repo = repo
    config.extended_files = extended_files
    config.whole_code = whole_code
    config.code_search = code_search
    config.in_one_message = in_one
    config.created_after = created_after
    config.pushed_after = pushed_after
    
    # Run enhanced scanning
    asyncio.run(run_enhanced_scan(keywords, config))


@app.command()
def run(
    subject: str = typer.Argument(..., help="Subject to search for (e.g., 'internal config', 'private api')"),
    config_file: str = typer.Option(None, "--config", "-c", help="Path to config file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """Run GitFuzzer orchestrator for a subject."""
    
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    setup_logging(log_level)
    
    logger = logging.getLogger(__name__)
    logger.info(f"GitFuzzer orchestrator starting for subject: '{subject}'")
    
    # Load configuration  
    config = Settings.load(config_file)
    
    # Run orchestrator
    result = asyncio.run(run_generation_single(subject, config, verbose))
    
    # Display results
    typer.echo(f"\n✅ Generation {result['generation_id']} completed!")
    typer.echo(f"Subject: {result['subject']}")
    typer.echo(f"Keywords: {', '.join(result['keywords'])}")
    typer.echo(f"Total repos found: {result['total_repos']}")
    typer.echo(f"New repos analyzed: {result['new_repos']}")
    typer.echo(f"Interesting repos: {result['interesting_repos']}")
    typer.echo(f"Analyzed repos: {result['analyzed_repos']}")


@app.command()
def config():
    """Show current configuration."""
    config = Settings.load()
    
    typer.echo("Current Configuration:")
    typer.echo(f"  Keywords per generation: {config.keywords}")
    typer.echo(f"  Repository freshness: {config.days} days")
    typer.echo(f"  Analysis count: {config.analysis_count}")
    typer.echo()
    
    typer.echo("API Tokens:")
    env_vars = [
        ("GH_TOKEN", config.github_token),
        ("TELEGRAM_BOT_TOKEN", config.telegram_bot_token),
        ("TELEGRAM_CHAT_ID", config.telegram_chat_id),
        ("HF_TOKEN", config.hf_token),
    ]
    
    for var_name, value in env_vars:
        status = "✅ Set" if value else "❌ Not set"
        typer.echo(f"  {var_name}: {status}")


if __name__ == "__main__":
    app()
