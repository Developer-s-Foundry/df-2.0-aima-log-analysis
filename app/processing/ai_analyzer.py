"""AI-powered log analysis using LLMs for intent detection and recommendations."""

import asyncio
import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.log_entry import LogEntry

logger = get_logger(__name__)


class AIAnalyzer:
    """
    AI-powered log analyzer using LLMs for intelligent analysis.

    Features:
    - Intent detection (what is the log trying to communicate?)
    - Root cause analysis
    - Actionable recommendations
    - Severity assessment
    - Similar incident lookup
    """

    def __init__(self) -> None:
        """Initialize AI analyzer."""
        self.settings = get_settings()
        self._client = None
        self._cache: Dict[str, Dict[str, Any]] = {}

    async def analyze_log(
        self, log: LogEntry, context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive AI analysis on a log entry.

        Args:
            log: Log entry to analyze
            context: Additional context (recent logs, system state, etc.)

        Returns:
            Analysis results with intent, root cause, and recommendations
        """
        # Check if AI analysis is enabled
        if not self._is_ai_enabled():
            return self._fallback_analysis(log)

        # Only analyze logs above minimum severity
        if not self._should_analyze(log):
            return self._fallback_analysis(log)

        # Check cache first
        cache_key = self._generate_cache_key(log)
        if cache_key in self._cache:
            logger.info("ai_analysis_cache_hit", log_id=str(log.id))
            return self._cache[cache_key]

        try:
            # Perform AI analysis
            analysis = await self._perform_ai_analysis(log, context)

            # Cache the result
            if self.settings.ai_cache_enabled:
                self._cache[cache_key] = analysis

            logger.info(
                "ai_analysis_completed",
                log_id=str(log.id),
                intent=analysis.get("intent"),
                severity=analysis.get("severity"),
            )

            return analysis

        except Exception as e:
            logger.error("ai_analysis_failed", error=str(e), log_id=str(log.id), exc_info=True)
            return self._fallback_analysis(log)

    async def _perform_ai_analysis(
        self, log: LogEntry, context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Perform the actual AI analysis using configured LLM."""
        # Prepare the prompt
        prompt = self._build_analysis_prompt(log, context)

        # Choose the appropriate AI service
        if hasattr(self.settings, "enable_groq_analysis") and self.settings.enable_groq_analysis:
            return await self._analyze_with_groq(prompt, log)
        elif (
            hasattr(self.settings, "enable_openai_analysis")
            and self.settings.enable_openai_analysis
        ):
            return await self._analyze_with_openai(prompt, log)
        elif (
            hasattr(self.settings, "enable_claude_analysis")
            and self.settings.enable_claude_analysis
        ):
            return await self._analyze_with_claude(prompt, log)
        else:
            return self._fallback_analysis(log)

    async def _analyze_with_openai(self, prompt: str, log: LogEntry) -> Dict[str, Any]:
        """Analyze using OpenAI GPT-4."""
        try:
            import openai

            if not self._client:
                openai.api_key = getattr(self.settings, "openai_api_key", None)
                self._client = openai

            response = await asyncio.to_thread(
                openai.chat.completions.create,
                model=getattr(self.settings, "openai_model", "gpt-4-turbo-preview"),
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert DevOps engineer analyzing application logs. "
                        "Provide concise, actionable insights in JSON format.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=getattr(self.settings, "openai_temperature", 0.3),
                max_tokens=getattr(self.settings, "openai_max_tokens", 1000),
                response_format={"type": "json_object"},
            )

            result = json.loads(response.choices[0].message.content)

            return {
                "intent": result.get("intent", "Unknown"),
                "root_cause": result.get("root_cause", "Unable to determine"),
                "severity": result.get("severity", log.log_level),
                "impact": result.get("impact", "UNKNOWN"),
                "recommendations": result.get("recommendations", []),
                "estimated_resolution_time": result.get("estimated_resolution_time"),
                "confidence": result.get("confidence", 0.5),
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "analyzer": "openai-gpt4",
            }

        except ImportError:
            logger.error("openai_not_installed", message="Install with: pip install openai")
            return self._fallback_analysis(log)
        except Exception as e:
            logger.error("openai_analysis_error", error=str(e), exc_info=True)
            raise

    async def _analyze_with_groq(self, prompt: str, log: LogEntry) -> Dict[str, Any]:
        """Analyze using Groq AI (fast inference with Llama/Mixtral)."""
        try:
            from groq import Groq

            if not self._client:
                self._client = Groq(api_key=getattr(self.settings, "groq_api_key", None))

            # Groq supports Llama 3, Mixtral, and other models
            model = getattr(self.settings, "groq_model", "llama-3.1-70b-versatile")

            completion = await asyncio.to_thread(
                self._client.chat.completions.create,
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert DevOps engineer analyzing application logs. "
                        "Provide concise, actionable insights in JSON format.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=getattr(self.settings, "groq_temperature", 0.3),
                max_tokens=getattr(self.settings, "groq_max_tokens", 1000),
                response_format={"type": "json_object"},
            )

            result = json.loads(completion.choices[0].message.content)

            return {
                "intent": result.get("intent", "Unknown"),
                "root_cause": result.get("root_cause", "Unable to determine"),
                "severity": result.get("severity", log.log_level),
                "impact": result.get("impact", "UNKNOWN"),
                "recommendations": result.get("recommendations", []),
                "estimated_resolution_time": result.get("estimated_resolution_time"),
                "confidence": result.get("confidence", 0.5),
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "analyzer": f"groq-{model}",
            }

        except ImportError:
            logger.error("groq_not_installed", message="Install with: pip install groq")
            return self._fallback_analysis(log)
        except Exception as e:
            logger.error("groq_analysis_error", error=str(e), exc_info=True)
            raise

    async def _analyze_with_claude(self, prompt: str, log: LogEntry) -> Dict[str, Any]:
        """Analyze using Anthropic Claude."""
        try:
            import anthropic

            if not self._client:
                self._client = anthropic.Anthropic(
                    api_key=getattr(self.settings, "anthropic_api_key", None)
                )

            message = await asyncio.to_thread(
                self._client.messages.create,
                model=getattr(self.settings, "claude_model", "claude-3-5-sonnet-20241022"),
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}],
            )

            result = json.loads(message.content[0].text)

            return {
                "intent": result.get("intent", "Unknown"),
                "root_cause": result.get("root_cause", "Unable to determine"),
                "severity": result.get("severity", log.log_level),
                "impact": result.get("impact", "UNKNOWN"),
                "recommendations": result.get("recommendations", []),
                "estimated_resolution_time": result.get("estimated_resolution_time"),
                "confidence": result.get("confidence", 0.5),
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "analyzer": "claude-3.5-sonnet",
            }

        except ImportError:
            logger.error("anthropic_not_installed", message="Install with: pip install anthropic")
            return self._fallback_analysis(log)
        except Exception as e:
            logger.error("claude_analysis_error", error=str(e), exc_info=True)
            raise

    def _build_analysis_prompt(self, log: LogEntry, context: Optional[Dict[str, Any]]) -> str:
        """Build a comprehensive prompt for AI analysis."""
        prompt_parts = [
            "Analyze the following log entry and provide insights:\n",
            "\n**Log Details:**",
            f"- Service: {log.service_name}",
            f"- Level: {log.log_level}",
            f"- Timestamp: {log.timestamp}",
            f"- Message: {log.message}",
        ]

        if log.stack_trace:
            prompt_parts.append(f"- Stack Trace: {log.stack_trace[:500]}...")

        if log.metadata:
            prompt_parts.append(f"- Metadata: {log.metadata}")

        if context:
            prompt_parts.append("\n**Context:**")
            if "recent_logs" in context:
                prompt_parts.append(
                    f"- Recent similar logs: {len(context['recent_logs'])} occurrences"
                )
            if "system_state" in context:
                prompt_parts.append(f"- System state: {context['system_state']}")

        prompt_parts.extend(
            [
                "\n**Required Analysis:**",
                "Provide a JSON response with the following fields:",
                "1. `intent`: What is this log communicating? (1-2 sentences)",
                "2. `root_cause`: Most likely root cause (2-3 sentences)",
                "3. `severity`: Severity level (LOW/MEDIUM/HIGH/CRITICAL)",
                "4. `impact`: Impact on system/users (LOW/MEDIUM/HIGH)",
                "5. `recommendations`: Array of 3 specific actionable recommendations",
                "6. `estimated_resolution_time`: Estimated time to resolve (e.g., '15 minutes', '2 hours')",
                "7. `confidence`: Your confidence in this analysis (0.0 to 1.0)",
                "\nRespond with valid JSON only.",
            ]
        )

        return "\n".join(prompt_parts)

    def _fallback_analysis(self, log: LogEntry) -> Dict[str, Any]:
        """Fallback to rule-based analysis when AI is unavailable."""
        # Simple rule-based intent detection
        intent = self._detect_intent_rule_based(log.message, log.log_level)

        return {
            "intent": intent,
            "root_cause": "Rule-based analysis - no AI inference available",
            "severity": log.log_level,
            "impact": self._estimate_impact(log.log_level),
            "recommendations": self._generate_basic_recommendations(log),
            "estimated_resolution_time": None,
            "confidence": 0.3,
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "analyzer": "rule-based-fallback",
        }

    def _detect_intent_rule_based(self, message: str, level: str) -> str:
        """Simple rule-based intent detection."""
        message_lower = message.lower()

        intent_keywords = {
            "connection_error": ["connection", "refused", "timeout", "unreachable"],
            "authentication_error": ["authentication", "unauthorized", "forbidden", "permission"],
            "database_error": ["database", "sql", "query", "deadlock"],
            "resource_exhaustion": ["memory", "disk", "cpu", "resource", "limit"],
            "configuration_error": ["configuration", "config", "invalid", "missing"],
            "network_error": ["network", "dns", "socket", "host"],
        }

        for intent, keywords in intent_keywords.items():
            if any(keyword in message_lower for keyword in keywords):
                return intent.replace("_", " ").title()

        return f"{level} Event"

    def _estimate_impact(self, level: str) -> str:
        """Estimate impact based on log level."""
        impact_map = {
            "DEBUG": "LOW",
            "INFO": "LOW",
            "WARN": "MEDIUM",
            "WARNING": "MEDIUM",
            "ERROR": "HIGH",
            "CRITICAL": "CRITICAL",
            "FATAL": "CRITICAL",
        }
        return impact_map.get(level, "MEDIUM")

    def _generate_basic_recommendations(self, log: LogEntry) -> List[str]:
        """Generate basic recommendations based on log patterns."""
        recommendations = []
        message_lower = log.message.lower()

        if "connection" in message_lower or "timeout" in message_lower:
            recommendations.extend(
                [
                    "Check network connectivity",
                    "Verify service is running and accessible",
                    "Review connection pool settings",
                ]
            )
        elif "database" in message_lower:
            recommendations.extend(
                [
                    "Check database connection pool",
                    "Review slow query logs",
                    "Verify database server status",
                ]
            )
        elif "memory" in message_lower or "oom" in message_lower:
            recommendations.extend(
                [
                    "Increase memory allocation",
                    "Check for memory leaks",
                    "Review memory usage patterns",
                ]
            )
        else:
            recommendations.extend(
                [
                    "Review service logs for patterns",
                    "Check recent deployments",
                    "Verify system resources",
                ]
            )

        return recommendations[:3]

    def _generate_cache_key(self, log: LogEntry) -> str:
        """Generate cache key from log content."""
        # Normalize the message to group similar logs
        normalized = self._normalize_message(log.message)
        key_content = f"{log.service_name}:{log.log_level}:{normalized}"
        return hashlib.md5(key_content.encode()).hexdigest()

    def _normalize_message(self, message: str) -> str:
        """Normalize message by removing dynamic parts."""
        import re

        # Remove UUIDs
        message = re.sub(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{UUID}", message
        )
        # Remove numbers
        message = re.sub(r"\b\d+\b", "{NUM}", message)
        # Remove timestamps
        message = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", "{TIMESTAMP}", message)
        return message

    def _is_ai_enabled(self) -> bool:
        """Check if AI analysis is enabled in configuration."""
        return (
            getattr(self.settings, "ai_analysis_enabled", False)
            or getattr(self.settings, "enable_groq_analysis", False)
            or getattr(self.settings, "enable_openai_analysis", False)
            or getattr(self.settings, "enable_claude_analysis", False)
        )

    def _should_analyze(self, log: LogEntry) -> bool:
        """Determine if this log should be analyzed with AI."""
        min_severity = getattr(self.settings, "ai_analysis_min_severity", "ERROR")

        severity_levels = {
            "DEBUG": 0,
            "INFO": 1,
            "WARN": 2,
            "WARNING": 2,
            "ERROR": 3,
            "CRITICAL": 4,
            "FATAL": 5,
        }

        log_severity = severity_levels.get(log.log_level, 0)
        min_severity_level = severity_levels.get(min_severity, 3)

        return log_severity >= min_severity_level

    async def analyze_batch(
        self, logs: List[LogEntry], max_concurrent: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Analyze multiple logs concurrently.

        Args:
            logs: List of log entries to analyze
            max_concurrent: Maximum concurrent AI requests

        Returns:
            List of analysis results
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def analyze_with_semaphore(log: LogEntry):
            async with semaphore:
                return await self.analyze_log(log)

        tasks = [analyze_with_semaphore(log) for log in logs]
        return await asyncio.gather(*tasks, return_exceptions=True)

    def clear_cache(self) -> None:
        """Clear the analysis cache."""
        self._cache.clear()
        logger.info("ai_analysis_cache_cleared")


# Singleton instance
_ai_analyzer: Optional[AIAnalyzer] = None


def get_ai_analyzer() -> AIAnalyzer:
    """Get or create the AI analyzer singleton."""
    global _ai_analyzer
    if _ai_analyzer is None:
        _ai_analyzer = AIAnalyzer()
    return _ai_analyzer
