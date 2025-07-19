# GitFuzzer

**AI-powered GitHub repository discovery and analysis tool** with automated security scanning and Telegram reporting.

## Overview

GitFuzzer implements a **generation-based workflow** that continuously discovers and analyzes GitHub repositories:

1. **🧠 AI Keyword Generation** - Generates relevant search keywords using HuggingFace models
2. **🔍 Repository Discovery** - Searches GitHub with automatic pagination bypass (>1000 results)
3. **⚡ Smart Analysis** - Filters real projects and scans for secrets/vulnerabilities  
4. **📱 Telegram Reporting** - Sends concise reports with interactive buttons
5. **🔄 Continuous Loop** - Interactive workflow with "Run Next", "New Subject", "Stop" options

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set Environment Variables

```bash
# Required
export GH_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Optional (for Telegram reports)
export TG_TOKEN="123456789:ABC-DEF1234..."
export TG_CHAT="-1000000000000"
```

### 3. Run a Generation

```bash
python -m gitfuzzer run "crypto wallet"
```

## Configuration

Copy `config.example.yml` to `config.yml` and customize:

```yaml
keywords: 5         # Keywords per generation
days: 30           # Repository freshness window
telegram_token: "" # Telegram bot token
telegram_chat: ""  # Telegram chat ID
github_token: ""   # GitHub token
min_stars: 0       # Minimum stars filter
```

## Features

### 🎯 Generation-Based Workflow

Each "generation" is a complete discovery cycle:
- Generates N keywords for your subject
- Searches GitHub for each keyword
- Combines results into a unique repository set
- Analyzes each repo for secrets and related URLs
- Sends Telegram reports for interesting findings
- Offers interactive continuation options

### 🚀 1000+ Result Bypass

Automatically slices large result sets by date ranges to bypass GitHub's 1000-result API limit.

### 🔒 Security Scanning

Detects potential secrets using:
- Regex patterns for common secret types
- Shannon entropy analysis
- Base64/hex string detection
- API key patterns

### 📊 State Management

Tracks processed repositories in SQLite to avoid duplicates across generations.

### 🤖 Telegram Integration

Interactive bot with inline keyboards:
- Real-time generation status
- Individual repository reports
- "Run Next" / "New Subject" / "Stop" buttons

## Usage Examples

```bash
# Basic usage
python -m gitfuzzer run "password manager"

# With custom config
python -m gitfuzzer run "api framework" --config my-config.yml

# Show current configuration
python -m gitfuzzer config

# Verbose output
python -m gitfuzzer run "cryptocurrency" --verbose
```

## Architecture

```
gitfuzzer/
├── cli.py           # Command-line interface
├── config.py        # Configuration management  
├── state.py         # SQLite state persistence
├── keyword_gen.py   # AI-powered keyword generation
├── gh_scan.py       # GitHub API with pagination bypass
├── analyzer.py      # Repository analysis & secret detection
├── reporter.py      # Telegram reporting
├── orchestrator.py  # Main generation workflow
└── utils/
    ├── dateparse.py # Date parsing utilities
    └── rate_limit.py # API rate limiting
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GH_TOKEN` | GitHub personal access token | ✅ |
| `TG_TOKEN` | Telegram bot token | ❌ |
| `TG_CHAT` | Telegram chat ID | ❌ |
| `HF_TOKEN` | HuggingFace API token | ❌ |

## Development

### Testing

```bash
# Run with dry-run mode
python -m gitfuzzer run "test subject" --verbose

# Check configuration
python -m gitfuzzer config
```

### State Management

GitFuzzer maintains state in `state.sqlite`:
- Generation history
- Processed repository cache
- Duplicate prevention

## License

MIT License - see LICENSE file for details.
