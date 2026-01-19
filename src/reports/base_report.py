"""Base report generator interface."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import json

from ..models import Vulnerability, ScanResult


class ReportFormat(Enum):
    """Supported report formats."""
    MARKDOWN = "md"
    HTML = "html"
    JSON = "json"
    PDF = "pdf"


class BaseReportGenerator(ABC):
    """Abstract base class for report generators."""

    def __init__(self, output_dir: str = "data/reports"):
        """
        Initialize report generator.

        Args:
            output_dir: Directory for generated reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def generate(
            self,
            vulnerabilities: List[Vulnerability],
            scan_results: Optional[List[ScanResult]] = None,
            metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate report content.

        Args:
            vulnerabilities: List of vulnerabilities to report
            scan_results: Optional scan results for context
            metadata: Optional report metadata

        Returns:
            Generated report content as string
        """
        pass

    def save(
            self,
            content: str,
            filename: str,
            format: ReportFormat = ReportFormat.MARKDOWN
    ) -> Path:
        """
        Save report to file.

        Args:
            content: Report content
            filename: Base filename (without extension)
            format: Output format

        Returns:
            Path to saved file
        """
        ext = format.value
        file_path = self.output_dir / f"{filename}.{ext}"

        if format == ReportFormat.JSON:
            # Ensure valid JSON
            try:
                json_content = json.loads(content)
                content = json.dumps(json_content, indent=2)
            except json.JSONDecodeError:
                # Wrap in JSON structure if not valid JSON
                content = json.dumps({"content": content}, indent=2)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return file_path

    def _get_severity_stats(
            self, vulnerabilities: List[Vulnerability]
    ) -> Dict[str, int]:
        """Calculate severity statistics."""
        stats = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for vuln in vulnerabilities:
            stats[vuln.severity.value] += 1

        return stats

    def _get_top_vulnerabilities(
            self,
            vulnerabilities: List[Vulnerability],
            count: int = 5
    ) -> List[Vulnerability]:
        """Get top vulnerabilities by CVSS score."""
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: v.cvss_score,
            reverse=True
        )
        return sorted_vulns[:count]

    def _format_timestamp(self, dt: Optional[datetime] = None) -> str:
        """Format timestamp for reports."""
        if dt is None:
            dt = datetime.now()
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    def _calculate_risk_score(
            self, vulnerabilities: List[Vulnerability]
    ) -> float:
        """Calculate overall risk score (0-100)."""
        if not vulnerabilities:
            return 0.0

        # Weight by severity
        weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1,
            "info": 0
        }

        total_weight = sum(
            weights[v.severity.value] for v in vulnerabilities
        )

        # Normalize to 0-100 scale
        max_possible = len(vulnerabilities) * 10
        return min(100, (total_weight / max_possible) * 100) if max_possible > 0 else 0
