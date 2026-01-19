"""Data models for vulnerability analysis."""

from .vulnerability import Vulnerability, VulnerabilitySeverity
from .scan_result import ScanResult, Host, Port, Service, PortState

__all__ = [
    "Vulnerability",
    "VulnerabilitySeverity",
    "ScanResult",
    "Host",
    "Port",
    "Service",
    "PortState"
]
