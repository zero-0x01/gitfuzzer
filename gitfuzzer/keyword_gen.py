"""Simplified keyword generation utilities used in tests."""

import asyncio
import logging
import random
import re
from dataclasses import dataclass
from typing import List, Optional, Set

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class KeywordResponse:
    keywords: List[str]
    source: str
    model_used: Optional[str] = None


class KeywordGenerator:
    """Basic keyword generator with optional HuggingFace querying."""

    def __init__(self, config):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    # Utility methods -----------------------------------------------------
    def _create_prompt(self, subject: str, count: int, context: Optional[str] = None) -> str:
        prompt = f"Generate {count} programming-related keywords for GitHub repositories about {subject}."
        if context:
            prompt += f" Additional context: {context}"
        return prompt

    def _parse_keywords_from_text(self, text: str) -> List[str]:
        words = re.split(r"[\s,\n]+", text)
        return [w.strip().lower() for w in words if w.strip()]

    def _expand_keywords(self, keywords: List[str]) -> List[str]:
        expanded: Set[str] = set(keywords)
        for kw in keywords:
            expanded.add(kw.lower())
            expanded.add(kw.replace(" ", "_"))
            expanded.add(f"{kw}s")
        return list(expanded)

    def _get_fallback_keywords(self, subject: str, count: int) -> List[str]:
        base = [f"{subject} tool", f"{subject} library", f"{subject} api", f"{subject} sdk"]
        keywords = base[:count]
        if len(keywords) < count:
            keywords.extend([f"{subject}{i}" for i in range(count - len(keywords))])
        return keywords[:count]

    async def _query_huggingface(self, prompt: str) -> Optional[List[str]]:
        if not self.session:
            return None
        try:
            async with self.session.post("https://api-inference.huggingface.co/models/gpt2", json={"inputs": prompt}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if isinstance(data, list) and data:
                        text = data[0].get("generated_text", "")
                        return self._parse_keywords_from_text(text)
        except Exception as e:
            logger.warning(f"HF query failed: {e}")
        return None

    async def generate_keywords(self, subject: str, count: int, context: Optional[str] = None, expand: bool = True) -> KeywordResponse:
        prompt = self._create_prompt(subject, count, context)
        keywords = None
        if self.session:
            keywords = await self._query_huggingface(prompt)
        if keywords:
            source = "ai"
        else:
            keywords = self._get_fallback_keywords(subject, count)
            source = "fallback"
        if expand:
            keywords = self._expand_keywords(keywords)[:count]
            if source == "ai" and len(keywords) < count:
                keywords += self._get_fallback_keywords(subject, count - len(keywords))
                source = "hybrid" if source == "ai" else source
        return KeywordResponse(keywords=keywords[:count], source=source, model_used="gpt2" if source != "fallback" else None)


async def generate_keywords_for_subject(subject: str, config) -> KeywordResponse:
    async with KeywordGenerator(config) as gen:
        return await gen.generate_keywords(subject, config.keyword.count)
