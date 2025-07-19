"""
Enhanced GitFuzzer Telegram Reporter - Real interactive reporting system
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional

import httpx

logger = logging.getLogger(__name__)


class TelegramBot:
    """Enhanced Telegram bot for interactive GitFuzzer reporting."""
    
    def __init__(self, settings):
        self.settings = settings
        self.token = settings.telegram_token
        self.base_url = f"https://api.telegram.org/bot{self.token}" if self.token else None
        
    async def send_message(self, chat_id: int, text: str, reply_markup: Optional[Dict] = None):
        """Send enhanced message to Telegram chat."""
        
        if not self.token:
            logger.info(f"[TELEGRAM SIMULATION] Would send to {chat_id}: {text}")
            return True
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                data = {
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": True
                }
                
                if reply_markup:
                    data["reply_markup"] = reply_markup
                
                response = await client.post(f"{self.base_url}/sendMessage", json=data)
                
                if response.status_code == 200:
                    logger.debug(f"Telegram message sent successfully to {chat_id}")
                    return True
                else:
                    logger.error(f"Telegram API error {response.status_code}: {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
            return False
    
    async def send_generation_start(self, chat_id: int, subject: str, generation_id: int):
        """Send enhanced generation start notification."""
        
        text = f"""🚀 **GitFuzzer Generation Started**

📋 **Subject:** `{subject}`
🆔 **Generation ID:** `{generation_id}`
⏰ **Started:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🔍 Discovering repositories with enhanced keyword generation...
🔒 Will scan for secrets and vulnerabilities
📊 Results will be reported in real-time"""
        
        await self.send_message(chat_id, text)
    
    async def send_repo_report(self, chat_id: int, repo, analysis):
        """Send enhanced individual repository report."""
        
        # Only send if there are significant findings
        if not analysis.has_secrets and not analysis.related_urls and analysis.risk_score < 30:
            return
        
        # Determine risk level
        risk_emoji = "🟢" if analysis.risk_score < 30 else "🟡" if analysis.risk_score < 60 else "🔴"
        risk_level = "LOW" if analysis.risk_score < 30 else "MEDIUM" if analysis.risk_score < 60 else "HIGH"
        
        text = f"""{risk_emoji} **Security Finding - {risk_level} Risk**

📦 **Repository:** [`{repo.full_name}`]({repo.html_url})
⭐ **Stars:** {repo.stars}
💻 **Language:** {repo.language or 'Unknown'}
📊 **Risk Score:** {analysis.risk_score}/100

"""
        
        if repo.description:
            text += f"📝 **Description:** {repo.description[:150]}{'...' if len(repo.description) > 150 else ''}\n\n"
        
        if analysis.has_secrets:
            text += f"🔐 **Secrets Detected:** {len(analysis.secrets_found)}\n"
            
            # Group secrets by severity
            critical_secrets = [s for s in analysis.secrets_found if 'CRITICAL' in s]
            high_secrets = [s for s in analysis.secrets_found if 'HIGH' in s]
            medium_secrets = [s for s in analysis.secrets_found if 'MEDIUM' in s]
            
            if critical_secrets:
                text += f"🚨 **Critical:** {len(critical_secrets)} findings\n"
                for secret in critical_secrets[:2]:  # Show first 2
                    text += f"• `{secret}`\n"
            
            if high_secrets:
                text += f"⚠️ **High:** {len(high_secrets)} findings\n"
                for secret in high_secrets[:2]:
                    text += f"• `{secret}`\n"
            
            if medium_secrets:
                text += f"ℹ️ **Medium:** {len(medium_secrets)} findings\n"
                
            if len(analysis.secrets_found) > 4:
                text += f"• ... and {len(analysis.secrets_found) - 4} more\n"
            
            text += "\n"
        
        if analysis.related_urls:
            text += f"🌐 **Related URLs:** {len(analysis.related_urls)}\n"
            for url in analysis.related_urls[:3]:  # Show first 3
                text += f"• {url}\n"
            if len(analysis.related_urls) > 3:
                text += f"• ... and {len(analysis.related_urls) - 3} more\n"
            text += "\n"
        
        # Add action buttons for high-risk findings
        keyboard = None
        if analysis.risk_score >= 50:
            keyboard = {
                "inline_keyboard": [
                    [
                        {"text": "🔍 Investigate", "url": repo.html_url},
                        {"text": "📋 Copy Link", "callback_data": f"copy:{repo.full_name}"}
                    ]
                ]
            }
        
        text += f"⏰ **Scanned:** {datetime.now().strftime('%H:%M:%S')}"
        
        await self.send_message(chat_id, text, keyboard)
    
    async def send_generation_complete(self, chat_id: int, stats: Dict[str, Any]):
        """Send enhanced generation completion with detailed statistics."""
        
        # Calculate completion time if available
        completion_time = datetime.now().strftime('%H:%M:%S')
        
        text = f"""✅ **Generation Complete**

📊 **Final Statistics:**
• **Subject:** `{stats['subject']}`
• **Generation ID:** `{stats['generation_id']}`
• **Keywords Generated:** {len(stats['keywords'])}
• **Total Repositories Found:** {stats['total_repos']}
• **New Repositories Analyzed:** {stats['new_repos']}
• **Security Findings:** {stats['interesting_repos']}

🔤 **Keywords Used:**
{', '.join(f"`{k}`" for k in stats['keywords'])}

⏰ **Completed:** {completion_time}
"""
        
        # Add recommendations based on results
        if stats['interesting_repos'] > 0:
            text += f"\n🎯 **Recommendations:**\n"
            text += f"• Review the {stats['interesting_repos']} repositories with security findings\n"
            text += f"• Consider running follow-up scans on related keywords\n"
        else:
            text += f"\n💡 **No significant security findings detected**\n"
            text += f"• Try different keywords or broader search terms\n"
            text += f"• Consider lowering the minimum stars filter\n"
        
        # Enhanced interactive buttons
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "🔄 Run Next Generation", "callback_data": f"run_next:{stats['subject']}"},
                    {"text": "🎯 New Subject", "callback_data": "new_subject"}
                ],
                [
                    {"text": "📊 Detailed Stats", "callback_data": f"stats:{stats['generation_id']}"},
                    {"text": "⚙️ Settings", "callback_data": "settings"}
                ],
                [
                    {"text": "⏹️ Stop", "callback_data": "stop"},
                    {"text": "❓ Help", "callback_data": "help"}
                ]
            ]
        }
        
        await self.send_message(chat_id, text, keyboard)
    
    async def send_error_report(self, chat_id: int, error: str, context: str = ""):
        """Send error notification."""
        
        text = f"""❌ **GitFuzzer Error**

🚫 **Error:** {error}

"""
        
        if context:
            text += f"📍 **Context:** {context}\n"
        
        text += f"⏰ **Time:** {datetime.now().strftime('%H:%M:%S')}\n\n"
        text += f"💡 **Try:**\n"
        text += f"• Check your API tokens\n"
        text += f"• Verify network connectivity\n"
        text += f"• Restart with different parameters"
        
        await self.send_message(chat_id, text)
    
    async def send_status_update(self, chat_id: int, message: str):
        """Send quick status update."""
        
        if not self.token:
            logger.info(f"[STATUS] {message}")
            return
        
        text = f"ℹ️ **Status Update**\n\n{message}\n\n⏰ {datetime.now().strftime('%H:%M:%S')}"
        await self.send_message(chat_id, text)
