"""Telegram reporter for GitFuzzer fuzz results.

This module formats and sends fuzz results to Telegram with
proper Markdown V2 formatting and interactive buttons.
"""

import asyncio
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote
import aiohttp

from .scanner import FuzzResult
from .score import RiskLevel
from .secret_rules import SecretMatch
from .endpoint_extractor import EndpointMatch


class TelegramReporter:
    """Formats and sends fuzz results to Telegram."""
    
    def __init__(self, bot_token: str, chat_id: str):
        """Initialize Telegram reporter.
        
        Args:
            bot_token: Telegram bot token
            chat_id: Telegram chat ID
        """
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_base = f"https://api.telegram.org/bot{bot_token}"
        self.max_message_length = 4096
        self.max_buttons = 5
    
    def escape_markdown_v2(self, text: str) -> str:
        """Escape text for Telegram Markdown V2.
        
        Args:
            text: Text to escape
            
        Returns:
            Escaped text
        """
        # Characters that need escaping in Markdown V2
        special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
        
        for char in special_chars:
            text = text.replace(char, f'\\{char}')
        
        return text
    
    def format_fuzz_alert(self, fuzz_result: FuzzResult) -> Tuple[str, List[Dict]]:
        """Format fuzz result as Telegram alert.
        
        Args:
            fuzz_result: Fuzz scan result
            
        Returns:
            Tuple of (formatted message, inline keyboard buttons)
        """
        # Extract repository name from URL
        repo_name = fuzz_result.repo_url.replace('https://github.com/', '')
        
        # Risk level emoji
        risk_emojis = {
            RiskLevel.LOW: '🟢',
            RiskLevel.MEDIUM: '🟡', 
            RiskLevel.HIGH: '🔴',
            RiskLevel.CRITICAL: '🚨'
        }
        
        risk_emoji = risk_emojis.get(fuzz_result.risk_assessment.risk_level, '❓')
        
        # Build message parts
        message_parts = []
        
        # Header
        header = f"{risk_emoji} *GitFuzzer Alert*"
        message_parts.append(header)
        
        # Repository info
        repo_line = f"Repo: `{self.escape_markdown_v2(repo_name)}`"
        message_parts.append(repo_line)
        
        # Risk assessment
        risk_line = f"Risk: *{fuzz_result.risk_assessment.risk_level.value}* " \
                   f"\\({fuzz_result.risk_assessment.total_score}/100\\)"
        message_parts.append(risk_line)
        
        # Secrets summary
        if fuzz_result.secret_matches:
            high_conf_secrets = fuzz_result.high_confidence_secrets
            secrets_line = f"Secrets: {len(fuzz_result.secret_matches)} potential keys"
            if high_conf_secrets:
                secrets_line += f" \\({len(high_conf_secrets)} high confidence\\)"
            message_parts.append(secrets_line)
        
        # Endpoints summary
        if fuzz_result.endpoint_matches:
            live_endpoints = fuzz_result.live_endpoints
            endpoints_line = f"Endpoints: {len(fuzz_result.endpoint_matches)} discovered"
            if live_endpoints:
                endpoints_line += f" \\({len(live_endpoints)} live\\)"
            message_parts.append(endpoints_line)
        
        # Live endpoints detail (up to 3)
        if fuzz_result.live_endpoints:
            message_parts.append("")
            message_parts.append("*Live Endpoints:*")
            for i, endpoint in enumerate(fuzz_result.live_endpoints[:3]):
                status_text = f"{endpoint.status_code}" if endpoint.status_code else "Unknown"
                endpoint_line = f" • `{self.escape_markdown_v2(endpoint.url)}` → {status_text}"
                message_parts.append(endpoint_line)
            
            if len(fuzz_result.live_endpoints) > 3:
                more_count = len(fuzz_result.live_endpoints) - 3
                message_parts.append(f" • \\+{more_count} more endpoints")
        
        # IP intelligence
        live_ips = [ep for ep in fuzz_result.live_endpoints if ep.endpoint_type == 'ip']
        if live_ips:
            message_parts.append("")
            ip_line = f"IP Intel: {len(live_ips)} addresses with open ports"
            message_parts.append(ip_line)
            
            # Show first IP
            if live_ips:
                first_ip = live_ips[0]
                ip_detail = f" • {self.escape_markdown_v2(first_ip.url)}"
                message_parts.append(ip_detail)
        
        # Organization info
        if fuzz_result.organization and fuzz_result.organization.confidence > 0.5:
            message_parts.append("")
            org_line = f"Org: {self.escape_markdown_v2(fuzz_result.organization.name)}"
            message_parts.append(org_line)
        
        # Risk factors (top 3)
        if fuzz_result.risk_assessment.factors:
            message_parts.append("")
            message_parts.append("*Key Findings:*")
            for factor in fuzz_result.risk_assessment.factors[:3]:
                factor_line = f" • {self.escape_markdown_v2(factor)}"
                message_parts.append(factor_line)
        
        # Timestamp
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
        message_parts.append("")
        message_parts.append(f"_Reported at {timestamp}_")
        
        # Join message
        full_message = "\\n".join(message_parts)
        
        # Generate buttons
        buttons = self._generate_buttons(fuzz_result)
        
        return full_message, buttons
    
    def _generate_buttons(self, fuzz_result: FuzzResult) -> List[Dict]:
        """Generate inline keyboard buttons for fuzz result.
        
        Args:
            fuzz_result: Fuzz scan result
            
        Returns:
            List of button rows for inline keyboard
        """
        buttons = []
        
        # Repository button (always first)
        repo_button = {
            "text": "🔗 Open Repo",
            "url": fuzz_result.repo_url
        }
        buttons.append([repo_button])
        
        # Live endpoints buttons (up to 3)
        endpoint_buttons = []
        for endpoint in fuzz_result.live_endpoints[:3]:
            if endpoint.endpoint_type == 'url' and endpoint.status_code == 200:
                button_text = self._truncate_button_text(endpoint.url)
                endpoint_buttons.append({
                    "text": f"🌐 {button_text}",
                    "url": endpoint.url
                })
        
        if endpoint_buttons:
            # Add endpoints as separate rows (max 1 per row for readability)
            for button in endpoint_buttons[:2]:  # Limit to 2 endpoint buttons
                buttons.append([button])
        
        # Shodan buttons for IPs
        live_ips = [ep for ep in fuzz_result.live_endpoints if ep.endpoint_type == 'ip']
        if live_ips and len(buttons) < self.max_buttons:
            first_ip = live_ips[0]
            shodan_url = f"https://www.shodan.io/host/{first_ip.url}"
            shodan_button = {
                "text": f"🔍 Shodan: {first_ip.url}",
                "url": shodan_url
            }
            buttons.append([shodan_button])
        
        # Risk level mute button (callback for future implementation)
        if fuzz_result.risk_assessment.risk_level == RiskLevel.LOW and len(buttons) < self.max_buttons:
            mute_button = {
                "text": "🔇 Mute LOW alerts",
                "callback_data": "mute_low_risk"
            }
            buttons.append([mute_button])
        
        return buttons
    
    def _truncate_button_text(self, text: str, max_length: int = 20) -> str:
        """Truncate text for button labels.
        
        Args:
            text: Text to truncate
            max_length: Maximum length
            
        Returns:
            Truncated text
        """
        if len(text) <= max_length:
            return text
        
        return text[:max_length-3] + "..."
    
    def split_long_message(self, message: str) -> List[str]:
        """Split long message into multiple parts.
        
        Args:
            message: Message to split
            
        Returns:
            List of message parts
        """
        if len(message) <= self.max_message_length:
            return [message]
        
        parts = []
        lines = message.split('\\n')
        current_part = ""
        
        for line in lines:
            # Check if adding this line would exceed limit
            test_part = current_part + "\\n" + line if current_part else line
            
            if len(test_part) > self.max_message_length:
                # If current_part is not empty, save it and start new part
                if current_part:
                    parts.append(current_part)
                    current_part = line
                else:
                    # Single line is too long, force split
                    if len(line) > self.max_message_length:
                        chunks = [line[i:i+self.max_message_length-100] 
                                for i in range(0, len(line), self.max_message_length-100)]
                        parts.extend(chunks[:-1])
                        current_part = chunks[-1]
                    else:
                        current_part = line
            else:
                current_part = test_part
        
        if current_part:
            parts.append(current_part)
        
        return parts
    
    async def send_alert(self, 
                        session: aiohttp.ClientSession,
                        fuzz_result: FuzzResult) -> bool:
        """Send fuzz alert to Telegram.
        
        Args:
            session: HTTP session
            fuzz_result: Fuzz result to send
            
        Returns:
            True if sent successfully
        """
        try:
            # Format message and buttons
            message, buttons = self.format_fuzz_alert(fuzz_result)
            
            # Split message if too long
            message_parts = self.split_long_message(message)
            
            # Send first part with buttons
            success = await self._send_message_part(
                session, 
                message_parts[0], 
                buttons if len(message_parts) == 1 else None
            )
            
            if not success:
                return False
            
            # Send remaining parts without buttons
            for part in message_parts[1:]:
                success = await self._send_message_part(session, part, None)
                if not success:
                    return False
                
                # Small delay between messages
                await asyncio.sleep(0.5)
            
            # Send buttons on last message if message was split
            if len(message_parts) > 1 and buttons:
                button_message = "🔗 *Quick Actions:*"
                await self._send_message_part(session, button_message, buttons)
            
            return True
            
        except Exception as e:
            # Log error (in production, use proper logging)
            print(f"Failed to send Telegram alert: {e}")
            return False
    
    async def _send_message_part(self,
                               session: aiohttp.ClientSession,
                               text: str,
                               buttons: Optional[List[Dict]] = None) -> bool:
        """Send a single message part to Telegram.
        
        Args:
            session: HTTP session
            text: Message text
            buttons: Optional inline keyboard buttons
            
        Returns:
            True if sent successfully
        """
        url = f"{self.api_base}/sendMessage"
        
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "MarkdownV2",
            "disable_web_page_preview": True
        }
        
        if buttons:
            payload["reply_markup"] = {
                "inline_keyboard": buttons
            }
        
        max_retries = 3
        retry_delay = 1.0
        
        for attempt in range(max_retries):
            try:
                async with session.post(url, json=payload, timeout=10) as response:
                    if response.status == 200:
                        return True
                    elif response.status == 429:
                        # Rate limited - extract retry_after from response
                        try:
                            error_data = await response.json()
                            retry_after = error_data.get('parameters', {}).get('retry_after', 60)
                            await asyncio.sleep(retry_after)
                            continue
                        except:
                            await asyncio.sleep(retry_delay)
                    else:
                        # Other error - log and retry
                        error_text = await response.text()
                        print(f"Telegram API error {response.status}: {error_text}")
                        
                        if attempt < max_retries - 1:
                            await asyncio.sleep(retry_delay)
                            retry_delay *= 2
                        
            except asyncio.TimeoutError:
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
            except Exception as e:
                print(f"Error sending to Telegram: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
        
        return False
    
    async def send_summary_report(self,
                                session: aiohttp.ClientSession,
                                results: List[FuzzResult],
                                scan_duration: float) -> bool:
        """Send summary report for multiple fuzz results.
        
        Args:
            session: HTTP session
            results: List of fuzz results
            scan_duration: Total scan duration in seconds
            
        Returns:
            True if sent successfully
        """
        if not results:
            return True
        
        # Count results by risk level
        risk_counts = {level: 0 for level in RiskLevel}
        total_secrets = 0
        total_endpoints = 0
        
        for result in results:
            risk_counts[result.risk_assessment.risk_level] += 1
            total_secrets += len(result.secret_matches)
            total_endpoints += len(result.endpoint_matches)
        
        # Format summary
        message_parts = [
            "📊 *GitFuzzer Scan Summary*",
            "",
            f"Repositories scanned: {len(results)}",
            f"Total secrets found: {total_secrets}",
            f"Total endpoints found: {total_endpoints}",
            f"Scan duration: {scan_duration:.1f}s",
            "",
            "*Risk Distribution:*"
        ]
        
        for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            count = risk_counts[level]
            if count > 0:
                emoji = {'CRITICAL': '🚨', 'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
                message_parts.append(f" • {emoji.get(level.value, '❓')} {level.value}: {count}")
        
        # Add timestamp
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
        message_parts.extend(["", f"_Completed at {timestamp}_"])
        
        message = "\\n".join(message_parts)
        
        return await self._send_message_part(session, message, None)
