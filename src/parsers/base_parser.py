"""Base parser interface for scan results."""

from abc import ABC, abstractmethod
from typing import List, Union
from pathlib import Path

from ..models import ScanResult, Vulnerability


class BaseParser(ABC):
    """Abstract base class for scan result parsers."""

    @abstractmethod
    def parse_file(self, file_path: Union[str, Path]) -> ScanResult:
        """
        Parse a scan result file.

        Args:
            file_path: Path to the scan result file

        Returns:
            ScanResult object containing parsed data
        """
        pass

    @abstractmethod
    def parse_string(self, content: str) -> ScanResult:
        """
        Parse scan results from a string.

        Args:
            content: String containing scan results

        Returns:
            ScanResult object containing parsed data
        """
        pass

    @abstractmethod
    def extract_vulnerabilities(self, scan_result: ScanResult) -> List[Vulnerability]:
        """
        Extract vulnerabilities from scan results.

        Args:
            scan_result: Parsed scan result

        Returns:
            List of Vulnerability objects
        """
        pass

    def get_supported_formats(self) -> List[str]:
        """Return list of supported file formats."""
        return ["xml", "json"]
