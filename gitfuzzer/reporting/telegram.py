"""Telegram bot interface for GitFuzzer control and reporting."""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import json

from telegram import (
    Update, Bot, InlineKeyboardButton, InlineKeyboardMarkup,
    ParseMode, BotCommand
)
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters
)

from gitfuzzer.config import TelegramConfig
from gitfuzzer.models import AnalysisResult

logger = logging.getLogger(__name__)


class TelegramReporter:
    """Telegram bot for GitFuzzer control and real-time reporting."""
    
    def __init__(self, config: TelegramConfig):
        self.config = config
        self.app: Optional[Application] = None
        self.bot: Optional[Bot] = None
        self.orchestrator_callback: Optional[Callable] = None
        
    async def initialize(self, orchestrator_callback: Callable = None):
        """Initialize the Telegram bot.
        
        Args:
            orchestrator_callback: Callback to orchestrator for handling commands
        """
        self.orchestrator_callback = orchestrator_callback
        
        # Create application
        self.app = Application.builder().token(self.config.bot_token).build()
        self.bot = self.app.bot
        
        # Register handlers
        await self._register_handlers()
        
        # Set bot commands
        await self._set_bot_commands()
        
        logger.info("Telegram bot initialized")
    
    async def _register_handlers(self):
        """Register command and message handlers."""
        # Command handlers
        self.app.add_handler(CommandHandler("start", self._handle_start))
        self.app.add_handler(CommandHandler("help", self._handle_help))
        self.app.add_handler(CommandHandler("gen", self._handle_generation))
        self.app.add_handler(CommandHandler("status", self._handle_status))
        self.app.add_handler(CommandHandler("stop", self._handle_stop_generation))
        self.app.add_handler(CommandHandler("config", self._handle_config))
        self.app.add_handler(CommandHandler("history", self._handle_history))
        
        # Callback query handler for inline keyboards
        self.app.add_handler(CallbackQueryHandler(self._handle_callback_query))
        
        # Message handler for new subject input
        self.app.add_handler(MessageHandler(
            filters.TEXT & ~filters.COMMAND, 
            self._handle_text_message
        ))
    
    async def _set_bot_commands(self):
        """Set bot command menu."""
        commands = [
            BotCommand("start", "Initialize GitFuzzer bot"),
            BotCommand("gen", "Start new generation: /gen <subject>"),
            BotCommand("status", "Show active generations"),
            BotCommand("stop", "Stop generation: /stop <id>"),
            BotCommand("config", "Show current configuration"),
            BotCommand("history", "Show generation history"),
            BotCommand("help", "Show help message"),
        ]
        
        await self.bot.set_my_commands(commands)
    
    async def _handle_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command."""
        if not self._is_authorized(update.effective_user.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        welcome_text = (
            "🔍 **GitFuzzer Bot Active**\n\n"
            "I help you discover and analyze repositories for security research.\n\n"
            "**Commands:**\n"
            "• `/gen <subject>` - Start new generation\n"
            "• `/status` - View active generations\n"
            "• `/stop <id>` - Stop a generation\n"
            "• `/history` - View past generations\n"
            "• `/config` - Show configuration\n"
            "• `/help` - Show detailed help\n\n"
            "**Example:** `/gen cryptocurrency wallet`"
        )
        
        await update.message.reply_text(welcome_text, parse_mode=ParseMode.MARKDOWN)
    
    async def _handle_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command."""
        if not self._is_authorized(update.effective_user.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        help_text = (
            "🔍 **GitFuzzer Bot Help**\n\n"
            "**Generation Workflow:**\n"
            "1. Use `/gen <subject>` to start\n"
            "2. Bot generates keywords using AI\n"
            "3. Searches GitHub repositories\n"
            "4. Performs deep code analysis\n"
            "5. Sends real-time security alerts\n"
            "6. Offers to run next generation\n\n"
            
            "**Commands:**\n"
            "• `/gen password manager` - Find password manager repos\n"
            "• `/gen cryptocurrency` - Find crypto-related code\n"
            "• `/gen oauth implementation` - Find OAuth code\n"
            "• `/status` - See running generations\n"
            "• `/stop 123` - Stop generation #123\n"
            "• `/history` - View past 10 generations\n"
            "• `/config` - Current search settings\n\n"
            
            "**Interactive Features:**\n"
            "• Real-time progress updates\n"
            "• Instant security alerts\n"
            "• One-click next generation\n"
            "• Generation chaining\n\n"
            
            "**Security Alerts:**\n"
            "🔴 **Critical** - Hardcoded secrets, private keys\n"
            "🟠 **High** - Weak crypto, exposed APIs\n"
            "🟡 **Medium** - Potential vulnerabilities\n\n"
            
            "**Tips:**\n"
            "• Be specific with subjects for better results\n"
            "• Use technical terms: 'JWT token', 'SQL injection'\n"
            "• Let generations complete for best results\n"
            "• Check /status to monitor progress"
        )
        
        await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)
    
    async def _handle_generation(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /gen command to start new generation."""
        if not self._is_authorized(update.effective_user.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        if not context.args:
            await update.message.reply_text(
                "Please provide a subject:\n`/gen <subject>`\n\n"
                "Examples:\n"
                "• `/gen cryptocurrency wallet`\n"
                "• `/gen oauth implementation`\n"
                "• `/gen password manager`",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        subject = " ".join(context.args)
        
        if len(subject) < 3:
            await update.message.reply_text("Subject must be at least 3 characters long")
            return
        
        if len(subject) > 100:
            await update.message.reply_text("Subject must be less than 100 characters")
            return
        
        # Start generation via orchestrator
        if self.orchestrator_callback:
            try:
                gen_id = await self.orchestrator_callback(
                    "start_generation",
                    subject=subject,
                    chat_id=update.effective_chat.id,
                    user_id=update.effective_user.id
                )
                
                await update.message.reply_text(
                    f"🚀 **Generation #{gen_id} started**\n"
                    f"Subject: `{subject}`\n\n"
                    f"I'll send updates as I work...",
                    parse_mode=ParseMode.MARKDOWN
                )
            except Exception as e:
                logger.exception("Failed to start generation")
                await update.message.reply_text(f"❌ Failed to start generation: {str(e)}")
        else:
            await update.message.reply_text("❌ Orchestrator not available")
    
    async def _handle_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command."""
        if not self._is_authorized(update.effective_user.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        if self.orchestrator_callback:
            try:
                status_data = await self.orchestrator_callback("get_active_generations")
                
                if not status_data:
                    await update.message.reply_text("No active generations")
                    return
                
                status_text = "📊 **Active Generations**\n\n"
                
                for gen_data in status_data:
                    gen_id = gen_data['id']
                    phase = gen_data.get('phase', 'unknown')
                    progress = gen_data.get('progress_percent', 0)
                    subject = gen_data['subject']
                    
                    status_text += (
                        f"**#{gen_id}** - {subject}\n"
                        f"Phase: `{phase}` ({progress:.0f}%)\n"
                        f"Started: {gen_data.get('created_at', 'unknown')}\n\n"
                    )
                
                await update.message.reply_text(status_text, parse_mode=ParseMode.MARKDOWN)
                
            except Exception as e:
                logger.exception("Failed to get status")
                await update.message.reply_text(f"❌ Failed to get status: {str(e)}")
        else:
            await update.message.reply_text("❌ Orchestrator not available")
    
    async def _handle_stop_generation(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /stop command."""
        if not self._is_authorized(update.effective_user.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        if not context.args:
            await update.message.reply_text(
                "Please provide generation ID:\n`/stop <id>`\n\n"
                "Use `/status` to see active generations",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        try:
            gen_id = int(context.args[0])
        except ValueError:
            await update.message.reply_text("Invalid generation ID")
            return
        
        if self.orchestrator_callback:
            try:
                success = await self.orchestrator_callback("stop_generation", gen_id=gen_id)
                
                if success:
                    await update.message.reply_text(f"⏹️ Generation #{gen_id} stopped")
                else:
                    await update.message.reply_text(f"❌ Generation #{gen_id} not found or not running")
                    
            except Exception as e:
                logger.exception("Failed to stop generation")
                await update.message.reply_text(f"❌ Failed to stop generation: {str(e)}")
        else:
            await update.message.reply_text("❌ Orchestrator not available")
    
    async def _handle_config(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /config command."""
        if not self._is_authorized(update.effective_user.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        if self.orchestrator_callback:
            try:
                config_data = await self.orchestrator_callback("get_config")
                
                config_text = (
                    "⚙️ **Current Configuration**\n\n"
                    f"**Keywords per generation:** {config_data.get('keyword_count', 'unknown')}\n"
                    f"**Max repositories:** {config_data.get('max_repos', 'unknown')}\n"
                    f"**Min stars:** {config_data.get('min_stars', 'unknown')}\n"
                    f"**Rate limit:** {config_data.get('rate_limit', 'unknown')}\n"
                    f"**Analysis depth:** {config_data.get('analysis_depth', 'unknown')}\n"
                    f"**GitHub tokens:** {config_data.get('token_count', 'unknown')} active\n"
                    f"**HuggingFace model:** {config_data.get('hf_model', 'unknown')}\n"
                )
                
                await update.message.reply_text(config_text, parse_mode=ParseMode.MARKDOWN)
                
            except Exception as e:
                logger.exception("Failed to get config")
                await update.message.reply_text(f"❌ Failed to get config: {str(e)}")
        else:
            await update.message.reply_text("❌ Orchestrator not available")
    
    async def _handle_history(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /history command."""
        if not self._is_authorized(update.effective_user.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        if self.orchestrator_callback:
            try:
                history_data = await self.orchestrator_callback("get_generation_history", limit=10)
                
                if not history_data:
                    await update.message.reply_text("No generation history")
                    return
                
                history_text = "📊 **Generation History**\n\n"
                
                for gen_data in history_data:
                    gen_id = gen_data['id']
                    status = gen_data['status']
                    subject = gen_data['subject']
                    created = gen_data.get('created_at', 'unknown')
                    
                    status_emoji = {
                        'completed': '✅',
                        'failed': '❌',
                        'running': '🔄',
                        'stopped': '⏹️'
                    }.get(status.lower(), '❓')
                    
                    history_text += f"{status_emoji} **#{gen_id}** - {subject}\n"
                    if 'alerts_count' in gen_data:
                        history_text += f"   Alerts: {gen_data['alerts_count']}, "
                    history_text += f"Created: {created}\n\n"
                
                await update.message.reply_text(history_text, parse_mode=ParseMode.MARKDOWN)
                
            except Exception as e:
                logger.exception("Failed to get history")
                await update.message.reply_text(f"❌ Failed to get history: {str(e)}")
        else:
            await update.message.reply_text("❌ Orchestrator not available")
    
    async def _handle_callback_query(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle inline keyboard button presses."""
        query = update.callback_query
        await query.answer()
        
        if not self._is_authorized(query.from_user.id):
            await query.edit_message_text("❌ Unauthorized access")
            return
        
        if self.orchestrator_callback:
            try:
                handled = await self.orchestrator_callback(
                    "handle_callback",
                    callback_data=query.data,
                    chat_id=query.message.chat_id,
                    user_id=query.from_user.id
                )
                
                if handled:
                    # Remove the keyboard after handling
                    await query.edit_message_reply_markup(reply_markup=None)
                    
            except Exception as e:
                logger.exception("Failed to handle callback")
                await query.edit_message_text(f"❌ Error: {str(e)}")
    
    async def _handle_text_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle text messages (for new subject input)."""
        if not self._is_authorized(update.effective_user.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        text = update.message.text.strip()
        
        if self.orchestrator_callback:
            try:
                handled = await self.orchestrator_callback(
                    "handle_new_subject",
                    subject=text,
                    chat_id=update.effective_chat.id,
                    user_id=update.effective_user.id
                )
                
                if not handled:
                    # Not expecting subject input, send help
                    await update.message.reply_text(
                        "Use `/gen <subject>` to start a new generation.\n"
                        "Send `/help` for more commands.",
                        parse_mode=ParseMode.MARKDOWN
                    )
                    
            except Exception as e:
                logger.exception("Failed to handle text message")
                await update.message.reply_text(f"❌ Error: {str(e)}")
    
    def _is_authorized(self, user_id: int) -> bool:
        """Check if user is authorized."""
        if not self.config.allowed_users:
            return True  # No restrictions
        return user_id in self.config.allowed_users
    
    async def start_bot(self):
        """Start the Telegram bot."""
        if not self.app:
            raise RuntimeError("Bot not initialized")
        
        logger.info("Starting Telegram bot...")
        await self.app.initialize()
        await self.app.start()
        await self.app.updater.start_polling()
        
        logger.info("Telegram bot started")
    
    async def stop_bot(self):
        """Stop the Telegram bot."""
        if self.app:
            logger.info("Stopping Telegram bot...")
            await self.app.updater.stop()
            await self.app.stop()
            await self.app.shutdown()
            logger.info("Telegram bot stopped")
    
    # Public API for orchestrator to send messages
    
    async def send_message(self, chat_id: int, text: str):
        """Send a text message."""
        if self.bot:
            await self.bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode=ParseMode.MARKDOWN,
                disable_web_page_preview=True
            )
    
    async def send_message_with_keyboard(self, chat_id: int, text: str, keyboard: List[List[tuple]]):
        """Send message with inline keyboard.
        
        Args:
            chat_id: Telegram chat ID
            text: Message text
            keyboard: List of button rows, each button is (text, callback_data)
        """
        if self.bot:
            reply_markup = InlineKeyboardMarkup([
                [InlineKeyboardButton(text=btn_text, callback_data=btn_data) 
                 for btn_text, btn_data in row]
                for row in keyboard
            ])
            
            await self.bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=reply_markup,
                disable_web_page_preview=True
            )
    
    async def send_generation_started(self, chat_id: int, gen_id: int, subject: str):
        """Send generation started notification."""
        text = (
            f"🚀 **Generation #{gen_id} Started**\n\n"
            f"**Subject:** {subject}\n"
            f"**Status:** Generating keywords...\n\n"
            f"I'll send updates as I progress through:\n"
            f"1️⃣ Keyword generation\n"
            f"2️⃣ Repository search\n"
            f"3️⃣ Code analysis\n"
            f"4️⃣ Security scanning\n"
            f"5️⃣ Report generation"
        )
        
        await self.send_message(chat_id, text)
    
    async def send_progress_update(self, chat_id: int, gen_id: int, phase: str, details: str):
        """Send progress update."""
        text = f"🔄 **Generation #{gen_id}** - {phase}\n{details}"
        await self.send_message(chat_id, text)
    
    async def send_security_alert(self, chat_id: int, result: AnalysisResult):
        """Send security alert for high-risk finding."""
        risk_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFO': 'ℹ️'
        }
        
        emoji = risk_emoji.get(result.risk_level, '❓')
        
        alert_text = (
            f"{emoji} **{result.risk_level} ALERT**\n\n"
            f"**Repository:** [{result.repository}]({result.repository_url})\n"
            f"**Issue:** {result.title}\n"
            f"**Details:** {result.description}\n"
        )
        
        if result.file_path:
            alert_text += f"**File:** `{result.file_path}`\n"
        
        if result.line_number:
            alert_text += f"**Line:** {result.line_number}\n"
        
        if result.code_snippet:
            alert_text += f"\n**Code:**\n```\n{result.code_snippet[:200]}{'...' if len(result.code_snippet) > 200 else ''}\n```"
        
        # Add action buttons for high-risk alerts
        if result.risk_level in ['CRITICAL', 'HIGH']:
            keyboard = [
                [("🔗 View Repository", f"view_repo_{result.repository}")],
                [("📋 Copy Details", f"copy_details_{result.id}")]
            ]
            await self.send_message_with_keyboard(chat_id, alert_text, keyboard)
        else:
            await self.send_message(chat_id, alert_text)
    
    async def send_error(self, chat_id: int, gen_id: int, error_message: str):
        """Send error notification."""
        text = (
            f"❌ **Generation #{gen_id} Error**\n\n"
            f"Error: {error_message}\n\n"
            f"Generation will continue if possible."
        )
        
        await self.send_message(chat_id, text)
