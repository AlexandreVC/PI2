"""Model registry for managing available AI models."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ModelCapability(Enum):
    """Model capabilities enumeration."""
    TEXT_GENERATION = "text_generation"
    CODE_GENERATION = "code_generation"
    ANALYSIS = "analysis"
    SUMMARIZATION = "summarization"
    REASONING = "reasoning"
    CLASSIFICATION = "classification"


@dataclass
class ModelConfig:
    """Configuration for an AI model."""

    # Identification
    name: str
    model_id: str  # Actual model identifier for API calls

    # API configuration
    api_base: str = ""
    api_type: str = "openai"  # openai, ollama, huggingface, custom

    # Capabilities
    capabilities: List[ModelCapability] = field(default_factory=list)

    # Performance characteristics
    max_tokens: int = 4096
    context_window: int = 8192
    avg_response_time_sec: float = 10.0  # Average response time
    cost_per_1k_tokens: float = 0.0  # For cost optimization

    # Quality metrics (0-1 scale)
    accuracy_score: float = 0.8
    code_quality_score: float = 0.7

    # Complexity handling
    min_complexity: int = 1  # 1=simple, 2=medium, 3=complex, 4=very complex
    max_complexity: int = 4

    # Task-specific scores (0-1 scale)
    task_scores: Dict[str, float] = field(default_factory=dict)

    # Status
    is_available: bool = True
    requires_api_key: bool = False

    def supports_task(self, task_type: str) -> bool:
        """Check if model supports a specific task type."""
        return task_type in self.task_scores and self.task_scores[task_type] > 0

    def get_task_score(self, task_type: str) -> float:
        """Get model's score for a specific task type."""
        return self.task_scores.get(task_type, 0.5)


class ModelRegistry:
    """
    Registry for managing available AI models.

    Based on project requirements:
    - Phi-4: Simple tasks (log parsing, Nmap scans) - Fast (~13 sec)
    - Mistral Small: Medium complexity (Nessus analysis, MITRE correlation)
    - Qwen Coder 32B: Complex tasks (exploit/script generation)
    - gpt-oss-20b: Default model for general tasks
    """

    def __init__(self):
        """Initialize the model registry with default configurations."""
        self._models: Dict[str, ModelConfig] = {}
        self._initialize_default_models()

    def _initialize_default_models(self):
        """Initialize default model configurations based on project specs."""

        # Phi-4: Fast model for simple tasks
        self.register_model(ModelConfig(
            name="Phi-4",
            model_id="phi4:latest",
            api_type="ollama",
            capabilities=[
                ModelCapability.TEXT_GENERATION,
                ModelCapability.SUMMARIZATION,
                ModelCapability.CLASSIFICATION
            ],
            max_tokens=4096,
            context_window=16384,
            avg_response_time_sec=13.0,
            accuracy_score=0.75,
            code_quality_score=0.6,
            min_complexity=1,
            max_complexity=2,
            task_scores={
                "log_parsing": 0.9,
                "nmap_analysis": 0.85,
                "summarization": 0.8,
                "classification": 0.8,
                "simple_analysis": 0.85
            }
        ))

        # Mistral Small: Medium complexity tasks
        self.register_model(ModelConfig(
            name="Mistral Small",
            model_id="mistral-small:latest",
            api_type="ollama",
            capabilities=[
                ModelCapability.TEXT_GENERATION,
                ModelCapability.ANALYSIS,
                ModelCapability.REASONING,
                ModelCapability.SUMMARIZATION
            ],
            max_tokens=8192,
            context_window=32768,
            avg_response_time_sec=25.0,
            accuracy_score=0.85,
            code_quality_score=0.75,
            min_complexity=2,
            max_complexity=3,
            task_scores={
                "nessus_analysis": 0.9,
                "mitre_correlation": 0.9,
                "vulnerability_analysis": 0.85,
                "remediation_planning": 0.85,
                "risk_assessment": 0.85,
                "report_generation": 0.8
            }
        ))

        # Qwen Coder 30B: Complex code-related tasks
        self.register_model(ModelConfig(
            name="Qwen Coder 30B",
            model_id="qwen3-coder:30b",
            api_type="ollama",
            capabilities=[
                ModelCapability.CODE_GENERATION,
                ModelCapability.ANALYSIS,
                ModelCapability.REASONING
            ],
            max_tokens=16384,
            context_window=65536,
            avg_response_time_sec=45.0,
            accuracy_score=0.9,
            code_quality_score=0.95,
            min_complexity=3,
            max_complexity=4,
            task_scores={
                "exploit_analysis": 0.95,
                "script_generation": 0.95,
                "code_review": 0.9,
                "patch_generation": 0.9,
                "complex_analysis": 0.85
            }
        ))

        # gpt-oss-20b: Default general-purpose model
        self.register_model(ModelConfig(
            name="GPT-OSS-20B",
            model_id="gpt-oss:20b",
            api_type="ollama",
            capabilities=[
                ModelCapability.TEXT_GENERATION,
                ModelCapability.CODE_GENERATION,
                ModelCapability.ANALYSIS,
                ModelCapability.SUMMARIZATION,
                ModelCapability.REASONING,
                ModelCapability.CLASSIFICATION
            ],
            max_tokens=8192,
            context_window=32768,
            avg_response_time_sec=30.0,
            accuracy_score=0.85,
            code_quality_score=0.8,
            min_complexity=1,
            max_complexity=4,
            task_scores={
                "log_parsing": 0.8,
                "nmap_analysis": 0.8,
                "nessus_analysis": 0.85,
                "vulnerability_analysis": 0.85,
                "mitre_correlation": 0.8,
                "remediation_planning": 0.85,
                "risk_assessment": 0.85,
                "report_generation": 0.9,
                "exploit_analysis": 0.75,
                "script_generation": 0.75
            }
        ))

    def register_model(self, config: ModelConfig):
        """Register a new model configuration."""
        self._models[config.name] = config
        logger.info(f"Registered model: {config.name}")

    def get_model(self, name: str) -> Optional[ModelConfig]:
        """Get a model configuration by name."""
        return self._models.get(name)

    def get_all_models(self) -> List[ModelConfig]:
        """Get all registered models."""
        return list(self._models.values())

    def get_available_models(self) -> List[ModelConfig]:
        """Get all available (enabled) models."""
        return [m for m in self._models.values() if m.is_available]

    def get_models_for_task(self, task_type: str) -> List[ModelConfig]:
        """Get models that support a specific task type."""
        return [
            m for m in self.get_available_models()
            if m.supports_task(task_type)
        ]

    def get_models_for_complexity(self, complexity: int) -> List[ModelConfig]:
        """Get models that can handle a given complexity level."""
        return [
            m for m in self.get_available_models()
            if m.min_complexity <= complexity <= m.max_complexity
        ]

    def get_best_model_for_task(
            self,
            task_type: str,
            complexity: int,
            prefer_speed: bool = False
    ) -> Optional[ModelConfig]:
        """
        Get the best model for a given task and complexity.

        Args:
            task_type: Type of task to perform
            complexity: Task complexity (1-4)
            prefer_speed: If True, prefer faster models over accuracy

        Returns:
            Best matching model configuration or None
        """
        candidates = [
            m for m in self.get_available_models()
            if m.min_complexity <= complexity <= m.max_complexity
               and m.supports_task(task_type)
        ]

        if not candidates:
            # Fallback to any model that handles the complexity
            candidates = self.get_models_for_complexity(complexity)

        if not candidates:
            # Ultimate fallback to default model
            return self.get_model("GPT-OSS-20B")

        # Score and sort candidates
        def score_model(model: ModelConfig) -> float:
            task_score = model.get_task_score(task_type)
            if prefer_speed:
                # Normalize response time (lower is better)
                speed_score = 1.0 - (model.avg_response_time_sec / 60.0)
                return (task_score * 0.4) + (speed_score * 0.6)
            else:
                return (task_score * 0.7) + (model.accuracy_score * 0.3)

        candidates.sort(key=score_model, reverse=True)
        return candidates[0]

    def set_model_availability(self, name: str, available: bool):
        """Set a model's availability status."""
        if name in self._models:
            self._models[name].is_available = available
            logger.info(f"Model {name} availability set to {available}")

    def update_model_stats(
            self,
            name: str,
            response_time: Optional[float] = None,
            accuracy: Optional[float] = None
    ):
        """Update model statistics based on observed performance."""
        if name not in self._models:
            return

        model = self._models[name]

        if response_time is not None:
            # Exponential moving average
            alpha = 0.2
            model.avg_response_time_sec = (
                    alpha * response_time +
                    (1 - alpha) * model.avg_response_time_sec
            )

        if accuracy is not None:
            alpha = 0.1
            model.accuracy_score = (
                    alpha * accuracy +
                    (1 - alpha) * model.accuracy_score
            )
