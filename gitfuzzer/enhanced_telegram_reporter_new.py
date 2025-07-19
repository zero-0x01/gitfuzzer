"""
Enhanced GitFuzzer Telegram Reporter with clickable secret links and Shodan integration
"""
import asyncio
import json
import logging
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import socket

import aiohttp
import httpx

logger = logging.getLogger(__name__)


class EnhancedTelegramReporter:
    """Enhanced Telegram reporter with clickable secret links and relationship discovery."""
    
    def __init__(self, bot_token: str, chat_id: str, report_mode: str = "one_by_one"):
        """
        Initialize enhanced Telegram reporter.
        
        Args:
            bot_token: Telegram bot token
            chat_id: Telegram chat ID
            report_mode: "one_by_one" or "all_in_one" for secret reporting
        """
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.report_mode = report_mode
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        
    async def send_message(self, text: str, parse_mode: str = "Markdown") -> bool:
        """Send message to Telegram."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                data = {
                    "chat_id": self.chat_id,
                    "text": text,
                    "parse_mode": parse_mode,
                    "disable_web_page_preview": True
                }
                
                response = await client.post(f"{self.base_url}/sendMessage", json=data)
                
                if response.status_code == 200:
                    result = response.json()
                    return result.get('ok', False)
                else:
                    logger.error(f"Telegram API error {response.status_code}: {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
            return False

    async def send_enhanced_report(self, analyzed_repos: List[Dict[str, Any]], keywords: str, scan_type: str = "REPOSITORY SEARCH") -> bool:
        """Send enhanced report with clickable secret links and relationship discovery."""
        
        total_secrets = sum(len(repo['analysis'].get('secrets', [])) for repo in analyzed_repos)
        
        # Send summary first
        summary = f"""🚀 **GitFuzzer Enhanced Report**
        
📊 **Scan Summary:**
Scan type: {scan_type.lower()}
🔍 Keywords: {keywords}
📁 Repositories analyzed: {len(analyzed_repos)}
🚨 Total secrets found: {total_secrets}
📅 Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🔗 **Detailed findings below...**"""
        
        await self.send_message(summary)
        
        # Send detailed findings based on mode
        if self.report_mode == "one_by_one":
            return await self._send_detailed_findings(analyzed_repos)
        else:
            return await self._send_all_in_one_report(analyzed_repos)
    
    async def _send_detailed_findings(self, analyzed_repos: List[Dict[str, Any]]) -> bool:
        """Send detailed findings one by one with clickable links."""
        
        try:
            repos_with_secrets = [repo for repo in analyzed_repos if repo['analysis'].get('secrets', [])]
            
            for i, repo_data in enumerate(repos_with_secrets, 1):
                repo = repo_data['repo']
                analysis = repo_data['analysis']
                secrets = analysis.get('secrets', [])
                
                # Sort secrets by severity (critical to low)
                severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
                sorted_secrets = sorted(secrets, key=lambda x: severity_order.get(x.get('severity', 'MEDIUM').upper(), 2))
                
                # Repository header
                repo_url = repo.get('html_url', f"https://github.com/{repo['full_name']}")
                last_push = repo.get('pushed_at', 'Unknown')
                if last_push != 'Unknown':
                    try:
                        from dateutil import parser
                        push_date = parser.parse(last_push)
                        last_push = push_date.strftime('%Y-%m-%d %H:%M')
                    except:
                        pass

                # Build complete repository message with all secrets
                repo_message = f"""------------------------------
**Repo name**: [{repo['full_name']}]({repo_url})
**Last pushed**: {last_push}
**Secrets** (from critical to low):"""
                
                # Add all secrets to the same message
                for j, secret in enumerate(sorted_secrets, 1):
                    secret_info = await self._format_secret_inline(secret, repo, j)
                    repo_message += f"\n\n{secret_info}"
                
                # Add relationships
                relationships_msg = await self._format_relationships(repo_data.get('relationships', []), repo)
                if relationships_msg:
                    repo_message += f"\n\n{relationships_msg}"
                else:
                    repo_message += f"\n\n**Relations**: None"
                
                # Send the complete repository message
                await self.send_message(repo_message)
                
                # Small delay between repositories
                await asyncio.sleep(0.5)
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending detailed findings: {e}")
            return False
    
    async def _format_secret_with_link(self, secret: Dict[str, Any], repo: Dict[str, Any], index: int) -> str:
        """Format secret with clickable GitHub file link."""
        
        # Create direct link to file on GitHub
        file_path = secret.get('file', '')
        line_number = secret.get('line', 1)
        
        # Construct GitHub blob URL with line number
        repo_url = repo.get('html_url', f"https://github.com/{repo['full_name']}")
        default_branch = repo.get('default_branch', 'main')
        
        if file_path:
            # Remove leading slash if present
            clean_path = file_path.lstrip('/')
            file_url = f"{repo_url}/blob/{default_branch}/{clean_path}"
            if line_number > 1:
                file_url += f"#L{line_number}"
        else:
            file_url = repo_url
        
        # Format secret info with severity emoji
        severity = secret.get('severity', 'MEDIUM').upper()
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🔵'
        }.get(severity, '⚪')
        
        secret_type = secret.get('type', 'unknown').replace('_', ' ').title()
        secret_value = secret.get('value', '')
        
        # Truncate long secrets
        if len(secret_value) > 50:
            secret_value = secret_value[:47] + "..."
        
        secret_msg = f"""🚨 **Secret {index}** {severity_emoji} {severity}

🔑 Type: `{secret_type}`
💾 Value: `{secret_value}`
📄 Location: [{file_path}]({file_url})
📍 Line: {line_number}"""
        
        return secret_msg

    async def _format_secret_inline(self, secret: Dict[str, Any], repo: Dict[str, Any], index: int) -> str:
        """Format secret for inline display within repository message."""
        
        # Create direct link to file on GitHub
        file_path = secret.get('file', '')
        line_number = secret.get('line', 1)
        
        # Construct GitHub blob URL with line number
        repo_url = repo.get('html_url', f"https://github.com/{repo['full_name']}")
        default_branch = repo.get('default_branch', 'main')
        
        if file_path:
            # Remove leading slash if present
            clean_path = file_path.lstrip('/')
            file_url = f"{repo_url}/blob/{default_branch}/{clean_path}"
            if line_number > 1:
                file_url += f"#L{line_number}"
        else:
            file_url = repo_url
        
        # Format secret info with severity emoji
        severity = secret.get('severity', 'MEDIUM').upper()
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🔵'
        }.get(severity, '⚪')
        
        secret_type = secret.get('type', 'unknown').replace('_', ' ').title()
        secret_value = secret.get('value', '')
        
        # Truncate long secrets
        if len(secret_value) > 50:
            secret_value = secret_value[:47] + "..."
        
        secret_msg = f"""🚨 **Secret {index}** {severity_emoji} {severity}
🔑 Type: `{secret_type}` | 💾 Value: `{secret_value}`
📄 Location: [{file_path}]({file_url}) | 📍 Line: {line_number}"""
        
        return secret_msg

    async def _format_relationships(self, relationships: List[Dict[str, Any]], repo: Dict[str, Any]) -> str:
        """Format organizational relationships."""
        
        if not relationships:
            return ""
        
        msg = f"""**Relations**:
📊 Found {len(relationships)} connections:"""
        
        for rel in relationships:
            rel_type = rel.get('type', 'unknown').title()
            rel_value = rel.get('value', 'Unknown')
            rel_source = rel.get('source', 'unknown')
            
            # Add appropriate emoji for relationship type
            type_emoji = {
                'domain': '🌐',
                'ip_address': '📍',
                'organization': '🏢',
                'website': '🔗'
            }.get(rel.get('type'), '📌')
            
            msg += f"\n{type_emoji} {rel_type}: `{rel_value}`"
            
            # Add additional info for Shodan results
            if rel_source == 'shodan_api' and 'organization' in rel:
                msg += f" (Org: {rel['organization']})"
        
        # Add Shodan search links for further investigation
        owner_name = repo.get('owner', {}).get('login', '')
        if owner_name:
            shodan_search_url = f"https://www.shodan.io/search?query=org%3A{owner_name}"
            msg += f"\n\n🔍 [Search {owner_name} on Shodan]({shodan_search_url})"
        
        return msg

    async def _send_all_in_one_report(self, analyzed_repos: List[Dict[str, Any]]) -> bool:
        """Send all findings in one comprehensive report."""
        
        try:
            report_parts = []
            repos_with_secrets = [repo for repo in analyzed_repos if repo['analysis'].get('secrets', [])]
            
            for i, repo_data in enumerate(repos_with_secrets, 1):
                repo = repo_data['repo']
                analysis = repo_data['analysis']
                secrets = analysis.get('secrets', [])
                
                # Sort secrets by severity
                severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
                sorted_secrets = sorted(secrets, key=lambda x: severity_order.get(x.get('severity', 'MEDIUM').upper(), 2))
                
                # Repository info
                repo_url = repo.get('html_url', f"https://github.com/{repo['full_name']}")
                last_push = repo.get('pushed_at', 'Unknown')
                if last_push != 'Unknown':
                    try:
                        from dateutil import parser
                        push_date = parser.parse(last_push)
                        last_push = push_date.strftime('%Y-%m-%d %H:%M')
                    except:
                        pass
                
                part = f"""------------------------------
**Repo name**: [{repo['full_name']}]({repo_url})
**Last pushed**: {last_push}
**Secrets** (from critical to low):"""
                
                # Add secret summaries with severity indicators
                for j, secret in enumerate(sorted_secrets[:10], 1):  # Limit to first 10 secrets for space
                    secret_type = secret.get('type', 'unknown').replace('_', ' ').title()
                    severity = secret.get('severity', 'MEDIUM').upper()
                    severity_emoji = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠', 
                        'MEDIUM': '🟡',
                        'LOW': '🔵'
                    }.get(severity, '⚪')
                    
                    file_path = secret.get('file', '')
                    
                    # Create clickable link
                    if file_path:
                        clean_path = file_path.lstrip('/')
                        file_url = f"{repo_url}/blob/{repo.get('default_branch', 'main')}/{clean_path}"
                        if secret.get('line', 1) > 1:
                            file_url += f"#L{secret.get('line', 1)}"
                        part += f"\n  {severity_emoji} [{secret_type}]({file_url})"
                    else:
                        part += f"\n  {severity_emoji} {secret_type}"
                
                if len(sorted_secrets) > 10:
                    part += f"\n  • ... and {len(sorted_secrets) - 10} more"
                
                # Add relationships
                relationships = repo_data.get('relationships', [])
                if relationships:
                    part += f"\n**Relations**: {len(relationships)} connections found"
                    for rel in relationships[:2]:  # Show first 2 relations
                        rel_type = rel.get('type', 'unknown').title()
                        rel_value = rel.get('value', 'Unknown')
                        part += f"\n  📌 {rel_type}: `{rel_value}`"
                    if len(relationships) > 2:
                        part += f"\n  • ... and {len(relationships) - 2} more"
                else:
                    part += f"\n**Relations**: None"
                
                report_parts.append(part)
            
            # Combine all parts
            full_report = "\n".join(report_parts)
            
            # Split into chunks if too long for Telegram
            max_length = 4000
            if len(full_report) > max_length:
                chunks = [full_report[i:i+max_length] for i in range(0, len(full_report), max_length)]
                for chunk in chunks:
                    await self.send_message(chunk)
                    await asyncio.sleep(1)
            else:
                await self.send_message(full_report)
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending all-in-one report: {e}")
            return False

    async def discover_shodan_relationships(self, repositories: List[Dict[str, Any]], shodan_api_key: str) -> List[Dict[str, Any]]:
        """Use Shodan API to discover infrastructure relationships."""
        
        relationships = []
        
        if not shodan_api_key:
            return relationships
        
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                for repo in repositories[:5]:  # Limit API calls
                    # Extract domains from repository metadata
                    domains = []
                    
                    # Check homepage
                    if repo.get('homepage'):
                        domain = self._extract_domain(repo['homepage'])
                        if domain:
                            domains.append(domain)
                    
                    # Check description for domains
                    if repo.get('description'):
                        import re
                        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
                        found_domains = re.findall(domain_pattern, repo['description'])
                        domains.extend(found_domains[:2])
                    
                    # Query Shodan for each domain
                    for domain in domains[:2]:  # Limit to 2 domains per repo
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
                                        'repo': repo['full_name'],
                                        'type': 'ip_address',
                                        'value': match.get('ip_str'),
                                        'source': 'shodan_api',
                                        'domain': domain,
                                        'organization': match.get('org', 'Unknown'),
                                        'country': match.get('location', {}).get('country_name', 'Unknown')
                                    })
                                    
                        except Exception as e:
                            logger.debug(f"Shodan lookup failed for {domain}: {e}")
                            continue
                        
                        # Small delay between API calls
                        await asyncio.sleep(0.5)
        
        except Exception as e:
            logger.error(f"Shodan relationship discovery failed: {e}")
        
        return relationships

    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return None
