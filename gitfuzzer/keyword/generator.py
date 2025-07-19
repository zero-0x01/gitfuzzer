"""Advanced keyword generation using AI models with fallback mechanisms."""

import asyncio
import logging
import random
from typing import List, Optional, Dict, Any
import json
import re

import aiohttp
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
import torch

from gitfuzzer.config import Config

logger = logging.getLogger(__name__)


class KeywordGenerator:
    """AI-powered keyword generation with multiple fallback strategies."""
    
    def __init__(self, config: Config):
        self.config = config
        self.hf_model = None
        self.hf_tokenizer = None
        self.hf_pipeline = None
        self.session = None
        
        # Fallback keyword patterns
        self.tech_patterns = {
            'cryptocurrency': [
                'bitcoin', 'ethereum', 'blockchain', 'crypto', 'wallet', 'mining',
                'defi', 'smart contract', 'solidity', 'web3', 'metamask', 'ledger',
                'exchange', 'trading', 'altcoin', 'token', 'nft', 'dao'
            ],
            'authentication': [
                'oauth', 'jwt', 'saml', 'ldap', 'active directory', 'sso',
                'password', 'login', 'auth', 'session', 'token', 'bearer',
                'cookie', 'csrf', 'xsrf', 'two factor', '2fa', 'mfa'
            ],
            'database': [
                'sql', 'mysql', 'postgresql', 'mongodb', 'redis', 'sqlite',
                'orm', 'query', 'injection', 'connection', 'migration',
                'backup', 'restore', 'index', 'schema', 'transaction'
            ],
            'api': [
                'rest', 'graphql', 'endpoint', 'swagger', 'openapi', 'webhook',
                'microservice', 'gateway', 'proxy', 'load balancer',
                'rate limit', 'throttle', 'cors', 'json', 'xml'
            ],
            'security': [
                'encryption', 'decrypt', 'hash', 'salt', 'cipher', 'aes',
                'rsa', 'tls', 'ssl', 'certificate', 'key management',
                'vulnerability', 'exploit', 'penetration', 'security audit'
            ],
            'cloud': [
                'aws', 'azure', 'gcp', 'docker', 'kubernetes', 'terraform',
                'ansible', 'jenkins', 'ci cd', 'devops', 'container',
                'serverless', 'lambda', 'function', 'microservice'
            ],
            'mobile': [
                'android', 'ios', 'react native', 'flutter', 'xamarin',
                'mobile app', 'push notification', 'deep link', 'in app',
                'mobile security', 'device', 'biometric', 'fingerprint'
            ],
            'web': [
                'javascript', 'html', 'css', 'react', 'vue', 'angular',
                'node.js', 'express', 'webpack', 'babel', 'typescript',
                'spa', 'pwa', 'websocket', 'ajax', 'fetch'
            ]
        }
        
    async def initialize(self):
        """Initialize AI models and HTTP session."""
        # Initialize HTTP session
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
        
        # Try to initialize HuggingFace model
        if self.config.keyword.use_ai and self.config.keyword.hf_model:
            try:
                await self._initialize_hf_model()
            except Exception as e:
                logger.warning(f"Failed to initialize HuggingFace model: {e}")
        
        logger.info("Keyword generator initialized")
    
    async def _initialize_hf_model(self):
        """Initialize HuggingFace model for keyword generation."""
        try:
            model_name = self.config.keyword.hf_model
            
            # Load model and tokenizer
            self.hf_tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.hf_model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None
            )
            
            # Create text generation pipeline
            self.hf_pipeline = pipeline(
                "text-generation",
                model=self.hf_model,
                tokenizer=self.hf_tokenizer,
                max_length=200,
                do_sample=True,
                temperature=0.7,
                top_p=0.9,
                num_return_sequences=1
            )
            
            logger.info(f"HuggingFace model {model_name} loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load HuggingFace model: {e}")
            self.hf_model = None
            self.hf_tokenizer = None
            self.hf_pipeline = None
    
    async def generate_keywords(self, subject: str, count: int = 10) -> List[str]:
        """Generate keywords for a given subject.
        
        Args:
            subject: Subject to generate keywords for
            count: Number of keywords to generate
            
        Returns:
            List of generated keywords
        """
        keywords = []
        
        # Strategy 1: Try AI-powered generation
        if self.config.keyword.use_ai:
            ai_keywords = await self._generate_ai_keywords(subject, count)
            keywords.extend(ai_keywords)
        
        # Strategy 2: Use pattern-based generation
        pattern_keywords = self._generate_pattern_keywords(subject, count)
        keywords.extend(pattern_keywords)
        
        # Strategy 3: Use subject decomposition
        decomp_keywords = self._decompose_subject(subject)
        keywords.extend(decomp_keywords)
        
        # Strategy 4: Add related technical terms
        tech_keywords = self._get_technical_keywords(subject)
        keywords.extend(tech_keywords)
        
        # Clean and deduplicate
        keywords = self._clean_keywords(keywords)
        
        # Ensure we have enough keywords
        if len(keywords) < count:
            # Add more generic technical terms
            generic_keywords = self._get_generic_tech_terms(count - len(keywords))
            keywords.extend(generic_keywords)
        
        # Limit to requested count
        keywords = list(dict.fromkeys(keywords))[:count]  # Remove duplicates and limit
        
        logger.info(f"Generated {len(keywords)} keywords for subject: {subject}")
        return keywords
    
    async def _generate_ai_keywords(self, subject: str, count: int) -> List[str]:
        """Generate keywords using AI models."""
        keywords = []
        
        # Try HuggingFace API first
        if self.config.keyword.hf_api_key:
            hf_keywords = await self._generate_hf_api_keywords(subject, count)
            keywords.extend(hf_keywords)
        
        # Try local HuggingFace model
        if self.hf_pipeline and len(keywords) < count:
            local_keywords = await self._generate_local_hf_keywords(subject, count - len(keywords))
            keywords.extend(local_keywords)
        
        return keywords
    
    async def _generate_hf_api_keywords(self, subject: str, count: int) -> List[str]:
        """Generate keywords using HuggingFace API."""
        try:
            # Create prompt for keyword generation
            prompt = f"""Generate technical keywords related to "{subject}" for software development and security research.

Subject: {subject}

Related technical keywords and terms:
1."""
            
            headers = {
                "Authorization": f"Bearer {self.config.keyword.hf_api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "inputs": prompt,
                "parameters": {
                    "max_new_tokens": 150,
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "do_sample": True,
                    "return_full_text": False
                }
            }
            
            api_url = f"https://api-inference.huggingface.co/models/{self.config.keyword.hf_model}"
            
            async with self.session.post(api_url, headers=headers, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    if isinstance(result, list) and len(result) > 0:
                        generated_text = result[0].get('generated_text', '')
                        keywords = self._extract_keywords_from_text(generated_text)
                        
                        logger.info(f"Generated {len(keywords)} keywords via HuggingFace API")
                        return keywords[:count]
                else:
                    logger.warning(f"HuggingFace API error: {response.status}")
                    
        except Exception as e:
            logger.warning(f"HuggingFace API generation failed: {e}")
        
        return []
    
    async def _generate_local_hf_keywords(self, subject: str, count: int) -> List[str]:
        """Generate keywords using local HuggingFace model."""
        try:
            if not self.hf_pipeline:
                return []
            
            # Create prompt
            prompt = f"Technical keywords for {subject}: "
            
            # Generate in a separate thread to avoid blocking
            def generate():
                try:
                    result = self.hf_pipeline(
                        prompt,
                        max_new_tokens=100,
                        num_return_sequences=1,
                        temperature=0.7,
                        do_sample=True
                    )
                    return result[0]['generated_text']
                except Exception as e:
                    logger.warning(f"Local HF generation error: {e}")
                    return ""
            
            # Run in thread pool
            loop = asyncio.get_event_loop()
            generated_text = await loop.run_in_executor(None, generate)
            
            if generated_text:
                keywords = self._extract_keywords_from_text(generated_text)
                logger.info(f"Generated {len(keywords)} keywords via local HF model")
                return keywords[:count]
                
        except Exception as e:
            logger.warning(f"Local HuggingFace generation failed: {e}")
        
        return []
    
    def _extract_keywords_from_text(self, text: str) -> List[str]:
        """Extract keywords from generated text."""
        keywords = []
        
        # Split by common delimiters
        for delimiter in ['\n', ',', ';', '•', '-', '*']:
            text = text.replace(delimiter, '|')
        
        # Extract potential keywords
        parts = text.split('|')
        
        for part in parts:
            part = part.strip()
            
            # Clean up common prefixes/suffixes
            part = re.sub(r'^\d+\.?\s*', '', part)  # Remove numbering
            part = re.sub(r'^[^\w\s]*', '', part)   # Remove leading symbols
            part = re.sub(r'[^\w\s]*$', '', part)   # Remove trailing symbols
            part = part.strip().lower()
            
            # Validate keyword
            if self._is_valid_keyword(part):
                keywords.append(part)
        
        return keywords
    
    def _generate_pattern_keywords(self, subject: str, count: int) -> List[str]:
        """Generate keywords based on predefined patterns."""
        keywords = []
        subject_lower = subject.lower()
        
        # Find matching patterns
        for category, terms in self.tech_patterns.items():
            # Check if subject matches this category
            if any(term in subject_lower for term in category.split()):
                keywords.extend(terms)
            
            # Check for individual term matches
            for term in terms:
                if term in subject_lower:
                    # Add related terms from the same category
                    keywords.extend(random.sample(terms, min(3, len(terms))))
                    break
        
        return keywords[:count]
    
    def _decompose_subject(self, subject: str) -> List[str]:
        """Decompose subject into component keywords."""
        keywords = []
        
        # Split by common word separators
        words = re.split(r'[\s\-_]+', subject.lower())
        
        for word in words:
            word = word.strip()
            if self._is_valid_keyword(word):
                keywords.append(word)
                
                # Add variations
                keywords.extend(self._get_word_variations(word))
        
        return keywords
    
    def _get_word_variations(self, word: str) -> List[str]:
        """Get variations of a word."""
        variations = []
        
        # Common technical variations
        if word.endswith('ing'):
            variations.append(word[:-3])  # remove 'ing'
        
        if word.endswith('er'):
            variations.append(word[:-2])  # remove 'er'
            
        if word.endswith('ed'):
            variations.append(word[:-2])  # remove 'ed'
        
        # Add plural/singular forms
        if word.endswith('s') and len(word) > 3:
            variations.append(word[:-1])  # remove 's'
        else:
            variations.append(word + 's')  # add 's'
        
        # Common tech suffixes
        for suffix in ['lib', 'api', 'sdk', 'tool', 'util', 'helper']:
            variations.append(f"{word} {suffix}")
            variations.append(f"{word}{suffix}")
        
        return variations
    
    def _get_technical_keywords(self, subject: str) -> List[str]:
        """Get technical keywords related to the subject."""
        keywords = []
        subject_lower = subject.lower()
        
        # Common technical terms that often appear together
        tech_relationships = {
            'password': ['hash', 'salt', 'bcrypt', 'authentication', 'login', 'security'],
            'api': ['rest', 'endpoint', 'json', 'xml', 'http', 'request', 'response'],
            'crypto': ['encryption', 'key', 'algorithm', 'cipher', 'hash', 'signature'],
            'database': ['sql', 'query', 'connection', 'orm', 'migration', 'index'],
            'web': ['html', 'css', 'javascript', 'framework', 'library', 'frontend'],
            'mobile': ['app', 'ios', 'android', 'native', 'hybrid', 'react'],
            'cloud': ['aws', 'azure', 'docker', 'kubernetes', 'serverless', 'microservice'],
            'security': ['vulnerability', 'exploit', 'audit', 'penetration', 'test', 'scanner']
        }
        
        # Find related terms
        for key, related_terms in tech_relationships.items():
            if key in subject_lower:
                keywords.extend(related_terms)
        
        return keywords
    
    def _get_generic_tech_terms(self, count: int) -> List[str]:
        """Get generic technical terms as fallback."""
        generic_terms = [
            'config', 'settings', 'environment', 'production', 'development',
            'test', 'debug', 'log', 'error', 'exception', 'handler',
            'service', 'client', 'server', 'connection', 'session',
            'user', 'admin', 'role', 'permission', 'access', 'control',
            'data', 'model', 'controller', 'view', 'template', 'component',
            'module', 'package', 'library', 'framework', 'plugin',
            'interface', 'abstract', 'concrete', 'factory', 'pattern',
            'async', 'sync', 'thread', 'process', 'queue', 'cache',
            'storage', 'file', 'directory', 'path', 'url', 'uri'
        ]
        
        return random.sample(generic_terms, min(count, len(generic_terms)))
    
    def _clean_keywords(self, keywords: List[str]) -> List[str]:
        """Clean and validate keywords."""
        cleaned = []
        
        for keyword in keywords:
            keyword = keyword.strip().lower()
            
            if self._is_valid_keyword(keyword):
                cleaned.append(keyword)
        
        # Remove duplicates while preserving order
        return list(dict.fromkeys(cleaned))
    
    def _is_valid_keyword(self, keyword: str) -> bool:
        """Check if a keyword is valid for searching."""
        if not keyword or len(keyword) < 2:
            return False
        
        if len(keyword) > 50:  # Too long
            return False
        
        # Must contain alphanumeric characters
        if not re.search(r'[a-zA-Z0-9]', keyword):
            return False
        
        # Exclude common stop words
        stop_words = {
            'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were',
            'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did',
            'will', 'would', 'could', 'should', 'may', 'might', 'can',
            'this', 'that', 'these', 'those', 'it', 'its', 'they', 'them',
            'a', 'an', 'very', 'much', 'many', 'some', 'any', 'all'
        }
        
        if keyword in stop_words:
            return False
        
        return True
    
    async def close(self):
        """Clean up resources."""
        if self.session:
            await self.session.close()
        
        # Clear model references to free memory
        self.hf_model = None
        self.hf_tokenizer = None
        self.hf_pipeline = None
        
        logger.info("Keyword generator closed")


# Convenience function for the orchestrator
async def generate_keywords(subject: str, count: int, config: Config) -> List[str]:
    """Generate keywords for a subject.
    
    Args:
        subject: Subject to generate keywords for
        count: Number of keywords to generate
        config: Configuration object
        
    Returns:
        List of generated keywords
    """
    generator = KeywordGenerator(config)
    await generator.initialize()
    
    try:
        keywords = await generator.generate_keywords(subject, count)
        return keywords
    finally:
        await generator.close()
