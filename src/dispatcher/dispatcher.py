"""
Intelligent task dispatcher for routing to appropriate AI models.

Based on project specifications:
- Analyzes task complexity to select the most efficient model
- Avoids using large models for trivial tasks
- Optimizes for speed vs accuracy based on task requirements
"""

import logging
import re
from enum import Enum
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass

from .model_registry import ModelRegistry, ModelConfig

logger = logging.getLogger(__name__)


class TaskComplexity(Enum):
    """Task complexity levels."""
    SIMPLE = 1      # Log parsing, basic classification
    MEDIUM = 2      # Nmap/Nessus analysis, summarization
    COMPLEX = 3     # MITRE correlation, detailed analysis
    VERY_COMPLEX = 4  # Exploit generation, code analysis


class TaskType(Enum):
    """Types of tasks the dispatcher handles."""
    LOG_PARSING = "log_parsing"
    NMAP_ANALYSIS = "nmap_analysis"
    NESSUS_ANALYSIS = "nessus_analysis"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    MITRE_CORRELATION = "mitre_correlation"
    REMEDIATION_PLANNING = "remediation_planning"
    RISK_ASSESSMENT = "risk_assessment"
    REPORT_GENERATION = "report_generation"
    EXPLOIT_ANALYSIS = "exploit_analysis"
    SCRIPT_GENERATION = "script_generation"
    CODE_REVIEW = "code_review"
    GENERAL = "general"


@dataclass
class DispatchResult:
    """Result of task dispatching."""
    model: ModelConfig
    task_type: TaskType
    complexity: TaskComplexity
    reasoning: str
    estimated_time_sec: float


class Dispatcher:
    """
    Intelligent dispatcher that routes tasks to the most appropriate AI model.

    Selection criteria:
    - Task complexity
    - Task type
    - Model capabilities
    - Performance requirements (speed vs accuracy)
    """

    # Keywords for task type detection
    TASK_KEYWORDS = {
        TaskType.LOG_PARSING: [
            "parse", "log", "extract", "read", "import"
        ],
        TaskType.NMAP_ANALYSIS: [
            "nmap", "port scan", "network scan", "host discovery",
            "service detection", "open ports"
        ],
        TaskType.NESSUS_ANALYSIS: [
            "nessus", "vulnerability scan", "security scan",
            "compliance scan", "plugin"
        ],
        TaskType.VULNERABILITY_ANALYSIS: [
            "vulnerability", "vuln", "cve", "weakness", "flaw",
            "security issue", "exploit"
        ],
        TaskType.MITRE_CORRELATION: [
            "mitre", "att&ck", "attack", "tactic", "technique",
            "threat", "ttp", "kill chain"
        ],
        TaskType.REMEDIATION_PLANNING: [
            "remediation", "fix", "patch", "mitigate", "resolve",
            "countermeasure", "hardening"
        ],
        TaskType.RISK_ASSESSMENT: [
            "risk", "impact", "likelihood", "severity", "priority",
            "business impact", "criticality"
        ],
        TaskType.REPORT_GENERATION: [
            "report", "summary", "executive", "technical report",
            "documentation", "findings"
        ],
        TaskType.EXPLOIT_ANALYSIS: [
            "exploit", "poc", "proof of concept", "payload",
            "attack vector", "exploitation"
        ],
        TaskType.SCRIPT_GENERATION: [
            "script", "code", "generate", "write code", "automation",
            "tool", "program"
        ],
        TaskType.CODE_REVIEW: [
            "review code", "code analysis", "static analysis",
            "security review", "audit code"
        ]
    }

    # Complexity indicators
    COMPLEXITY_INDICATORS = {
        TaskComplexity.SIMPLE: {
            "keywords": ["simple", "basic", "quick", "parse", "extract", "list"],
            "max_input_length": 5000,
            "single_item": True
        },
        TaskComplexity.MEDIUM: {
            "keywords": ["analyze", "summarize", "compare", "assess"],
            "max_input_length": 20000,
            "single_item": False
        },
        TaskComplexity.COMPLEX: {
            "keywords": ["correlate", "detailed", "comprehensive", "in-depth"],
            "max_input_length": 50000,
            "multiple_sources": True
        },
        TaskComplexity.VERY_COMPLEX: {
            "keywords": ["generate", "create", "exploit", "complex", "advanced"],
            "requires_code": True,
            "requires_reasoning": True
        }
    }

    def __init__(self, model_registry: Optional[ModelRegistry] = None):
        """
        Initialize the dispatcher.

        Args:
            model_registry: Optional custom model registry
        """
        self.registry = model_registry or ModelRegistry()
        self._dispatch_history: List[DispatchResult] = []

    def dispatch(
            self,
            task_description: str,
            input_data: Optional[str] = None,
            prefer_speed: bool = False,
            force_model: Optional[str] = None
    ) -> DispatchResult:
        """
        Dispatch a task to the most appropriate model.

        Args:
            task_description: Description of the task to perform
            input_data: Optional input data for complexity estimation
            prefer_speed: If True, prefer faster models
            force_model: Force a specific model (bypasses selection)

        Returns:
            DispatchResult with selected model and reasoning
        """
        # Detect task type
        task_type = self._detect_task_type(task_description)

        # Estimate complexity
        complexity = self._estimate_complexity(
            task_description,
            input_data,
            task_type
        )

        # Select model
        if force_model:
            model = self.registry.get_model(force_model)
            if not model:
                logger.warning(f"Forced model {force_model} not found, using auto-selection")
                model = None
        else:
            model = None

        if model is None:
            model = self.registry.get_best_model_for_task(
                task_type.value,
                complexity.value,
                prefer_speed
            )

        # Build reasoning
        reasoning = self._build_reasoning(task_type, complexity, model, prefer_speed)

        result = DispatchResult(
            model=model,
            task_type=task_type,
            complexity=complexity,
            reasoning=reasoning,
            estimated_time_sec=model.avg_response_time_sec if model else 30.0
        )

        self._dispatch_history.append(result)
        logger.info(f"Dispatched: {task_type.value} ({complexity.name}) -> {model.name if model else 'None'}")

        return result

    def _detect_task_type(self, description: str) -> TaskType:
        """Detect task type from description."""
        description_lower = description.lower()

        # Score each task type based on keyword matches
        scores: Dict[TaskType, int] = {}

        for task_type, keywords in self.TASK_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in description_lower)
            if score > 0:
                scores[task_type] = score

        if not scores:
            return TaskType.GENERAL

        # Return task type with highest score
        return max(scores, key=scores.get)

    def _estimate_complexity(
            self,
            description: str,
            input_data: Optional[str],
            task_type: TaskType
    ) -> TaskComplexity:
        """Estimate task complexity."""
        description_lower = description.lower()

        # Start with base complexity based on task type
        base_complexity = self._get_base_complexity(task_type)

        # Adjust based on keywords
        for complexity, indicators in self.COMPLEXITY_INDICATORS.items():
            keywords = indicators.get("keywords", [])
            if any(kw in description_lower for kw in keywords):
                if complexity.value > base_complexity.value:
                    base_complexity = complexity

        # Adjust based on input size
        if input_data:
            input_length = len(input_data)

            if input_length > 50000:
                base_complexity = TaskComplexity.VERY_COMPLEX
            elif input_length > 20000:
                if base_complexity.value < TaskComplexity.COMPLEX.value:
                    base_complexity = TaskComplexity.COMPLEX
            elif input_length > 5000:
                if base_complexity.value < TaskComplexity.MEDIUM.value:
                    base_complexity = TaskComplexity.MEDIUM

        # Check for complexity boosters
        complexity_boosters = [
            "multiple", "all", "comprehensive", "detailed",
            "correlate", "generate code", "exploit"
        ]
        if any(booster in description_lower for booster in complexity_boosters):
            if base_complexity.value < TaskComplexity.COMPLEX.value:
                base_complexity = TaskComplexity(base_complexity.value + 1)

        return base_complexity

    def _get_base_complexity(self, task_type: TaskType) -> TaskComplexity:
        """Get base complexity for a task type."""
        complexity_map = {
            TaskType.LOG_PARSING: TaskComplexity.SIMPLE,
            TaskType.NMAP_ANALYSIS: TaskComplexity.SIMPLE,
            TaskType.NESSUS_ANALYSIS: TaskComplexity.MEDIUM,
            TaskType.VULNERABILITY_ANALYSIS: TaskComplexity.MEDIUM,
            TaskType.MITRE_CORRELATION: TaskComplexity.COMPLEX,
            TaskType.REMEDIATION_PLANNING: TaskComplexity.MEDIUM,
            TaskType.RISK_ASSESSMENT: TaskComplexity.MEDIUM,
            TaskType.REPORT_GENERATION: TaskComplexity.MEDIUM,
            TaskType.EXPLOIT_ANALYSIS: TaskComplexity.COMPLEX,
            TaskType.SCRIPT_GENERATION: TaskComplexity.VERY_COMPLEX,
            TaskType.CODE_REVIEW: TaskComplexity.COMPLEX,
            TaskType.GENERAL: TaskComplexity.MEDIUM
        }
        return complexity_map.get(task_type, TaskComplexity.MEDIUM)

    def _build_reasoning(
            self,
            task_type: TaskType,
            complexity: TaskComplexity,
            model: Optional[ModelConfig],
            prefer_speed: bool
    ) -> str:
        """Build explanation for model selection."""
        if model is None:
            return "No suitable model found"

        reasons = []

        # Task type reasoning
        reasons.append(f"Task identified as: {task_type.value}")

        # Complexity reasoning
        complexity_desc = {
            TaskComplexity.SIMPLE: "simple (fast processing preferred)",
            TaskComplexity.MEDIUM: "medium (balance of speed and accuracy)",
            TaskComplexity.COMPLEX: "complex (accuracy prioritized)",
            TaskComplexity.VERY_COMPLEX: "very complex (specialized capabilities required)"
        }
        reasons.append(f"Complexity: {complexity_desc[complexity]}")

        # Model selection reasoning
        task_score = model.get_task_score(task_type.value)
        reasons.append(
            f"Selected {model.name}: task score={task_score:.2f}, "
            f"accuracy={model.accuracy_score:.2f}, "
            f"avg_time={model.avg_response_time_sec:.1f}s"
        )

        if prefer_speed:
            reasons.append("Speed optimized selection")

        return " | ".join(reasons)

    def get_dispatch_stats(self) -> Dict[str, Any]:
        """Get statistics about dispatching decisions."""
        if not self._dispatch_history:
            return {"total_dispatches": 0}

        model_counts = {}
        task_counts = {}
        complexity_counts = {}

        for result in self._dispatch_history:
            model_name = result.model.name if result.model else "None"
            model_counts[model_name] = model_counts.get(model_name, 0) + 1
            task_counts[result.task_type.value] = task_counts.get(result.task_type.value, 0) + 1
            complexity_counts[result.complexity.name] = complexity_counts.get(result.complexity.name, 0) + 1

        return {
            "total_dispatches": len(self._dispatch_history),
            "by_model": model_counts,
            "by_task_type": task_counts,
            "by_complexity": complexity_counts
        }

    def explain_selection(
            self,
            task_description: str,
            input_data: Optional[str] = None
    ) -> str:
        """
        Explain why a particular model would be selected.

        Useful for debugging and transparency.
        """
        result = self.dispatch(task_description, input_data)

        explanation = f"""
Task Analysis:
--------------
Description: {task_description[:100]}...
Detected Type: {result.task_type.value}
Estimated Complexity: {result.complexity.name}

Model Selection:
----------------
Selected Model: {result.model.name if result.model else 'None'}
Reasoning: {result.reasoning}
Estimated Time: {result.estimated_time_sec:.1f} seconds

Model Details:
--------------
"""
        if result.model:
            explanation += f"""
- Model ID: {result.model.model_id}
- API Type: {result.model.api_type}
- Accuracy Score: {result.model.accuracy_score:.2f}
- Task Score: {result.model.get_task_score(result.task_type.value):.2f}
- Complexity Range: {result.model.min_complexity} - {result.model.max_complexity}
"""
        return explanation
