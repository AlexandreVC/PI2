"""
Configuration settings for the Vulnerability Analysis Pipeline.

Based on ESILV PI2 Project specifications.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional
import os
import json
from pathlib import Path


@dataclass
class LLMSettings:
    """LLM configuration settings."""
    default_model: str = "gpt-oss:20b"
    ollama_url: str = "http://localhost:11434"
    temperature: float = 0.0  # Deterministic for reproducibility
    max_tokens: int = 4096
    timeout: int = 600  # 10 minutes pour les gros modèles

    # Model selection based on complexity (from project specs)
    model_routing: Dict[str, str] = field(default_factory=lambda: {
        "simple": "phi4:latest",          # Log parsing, Nmap analysis (~13 sec)
        "medium": "phi4:latest",          # Nessus analysis, synthesis
        "complex": "mistral-small:latest",  # MITRE correlation, contextual reasoning
        "very_complex": "qwen3-coder:30b"  # Exploit/script generation
    })


@dataclass
class ScanSettings:
    """Scan processing settings."""
    supported_nmap_formats: tuple = (".xml", ".json")
    supported_nessus_formats: tuple = (".nessus", ".xml", ".json")
    max_file_size_mb: int = 100


@dataclass
class EnrichmentSettings:
    """Enrichment module settings."""
    nvd_api_key: Optional[str] = None  # Set for higher rate limits
    nvd_rate_limit_sec: float = 6.0  # Without API key
    enable_cve_enrichment: bool = True
    enable_mitre_mapping: bool = True
    cache_enabled: bool = True


@dataclass
class ReportSettings:
    """Report generation settings."""
    output_dir: str = "data/reports"
    default_format: str = "markdown"
    include_ai_analysis: bool = True
    max_vulns_in_executive: int = 10
    classification: str = "Confidential"


@dataclass
class PipelineSettings:
    """Main pipeline settings."""
    llm: LLMSettings = field(default_factory=LLMSettings)
    scan: ScanSettings = field(default_factory=ScanSettings)
    enrichment: EnrichmentSettings = field(default_factory=EnrichmentSettings)
    report: ReportSettings = field(default_factory=ReportSettings)

    # Pipeline behavior
    enable_ai_analysis: bool = True
    parallel_processing: bool = False
    log_level: str = "INFO"

    @classmethod
    def from_file(cls, file_path: str) -> "PipelineSettings":
        """Load settings from JSON file."""
        with open(file_path, 'r') as f:
            data = json.load(f)

        settings = cls()

        if 'llm' in data:
            for k, v in data['llm'].items():
                if hasattr(settings.llm, k):
                    setattr(settings.llm, k, v)

        if 'enrichment' in data:
            for k, v in data['enrichment'].items():
                if hasattr(settings.enrichment, k):
                    setattr(settings.enrichment, k, v)

        if 'report' in data:
            for k, v in data['report'].items():
                if hasattr(settings.report, k):
                    setattr(settings.report, k, v)

        for k in ['enable_ai_analysis', 'parallel_processing', 'log_level']:
            if k in data:
                setattr(settings, k, data[k])

        return settings

    @classmethod
    def from_env(cls) -> "PipelineSettings":
        """Load settings from environment variables."""
        settings = cls()

        # LLM settings
        if os.getenv('LLM_MODEL'):
            settings.llm.default_model = os.getenv('LLM_MODEL')
        if os.getenv('OLLAMA_URL'):
            settings.llm.ollama_url = os.getenv('OLLAMA_URL')

        # Enrichment
        if os.getenv('NVD_API_KEY'):
            settings.enrichment.nvd_api_key = os.getenv('NVD_API_KEY')

        # Pipeline
        if os.getenv('DISABLE_AI'):
            settings.enable_ai_analysis = False

        return settings

    def to_dict(self) -> dict:
        """Convert settings to dictionary."""
        return {
            "llm": {
                "default_model": self.llm.default_model,
                "ollama_url": self.llm.ollama_url,
                "temperature": self.llm.temperature,
                "max_tokens": self.llm.max_tokens,
                "model_routing": self.llm.model_routing
            },
            "enrichment": {
                "enable_cve_enrichment": self.enrichment.enable_cve_enrichment,
                "enable_mitre_mapping": self.enrichment.enable_mitre_mapping,
                "cache_enabled": self.enrichment.cache_enabled
            },
            "report": {
                "output_dir": self.report.output_dir,
                "default_format": self.report.default_format,
                "include_ai_analysis": self.report.include_ai_analysis
            },
            "enable_ai_analysis": self.enable_ai_analysis,
            "log_level": self.log_level
        }

    def save(self, file_path: str):
        """Save settings to JSON file."""
        with open(file_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


# Default settings instance
DEFAULT_SETTINGS = PipelineSettings()


# Metrics for evaluation (from project specs)
EVALUATION_METRICS = {
    "accuracy": "Taux global de bonnes réponses (justesse)",
    "precision": "Proportion de vraies vulnérabilités parmi les alertes (évite faux positifs)",
    "recall": "Proportion de vulnérabilités réelles détectées (évite faux négatifs)"
}


# Project hyperparameters (from project specs)
HYPERPARAMETERS = {
    "temperature": 0.0,  # Déterministe pour reproductibilité
    "justification": """
    En cybersécurité, la créativité est un risque (hallucination).
    Nous cherchons la reproductibilité (10 analyses du même log doivent donner
    10 fois le même résultat) et la précision factuelle.
    Référence théorique: Dans l'échantillonnage de tokens (Temperature Sampling),
    une valeur proche de 0 (Argmax) rend le modèle déterministe.
    """
}
