"""Scan result data models."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class PortState(Enum):
    """Port state enumeration."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


@dataclass
class Service:
    """Represents a network service."""
    name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    os_type: str = ""
    cpe: List[str] = field(default_factory=list)  # Common Platform Enumeration


@dataclass
class Port:
    """Represents a network port."""
    number: int
    protocol: str = "tcp"
    state: PortState = PortState.UNKNOWN
    service: Optional[Service] = None
    scripts: Dict[str, str] = field(default_factory=dict)  # NSE script results

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "number": self.number,
            "protocol": self.protocol,
            "state": self.state.value,
            "service": {
                "name": self.service.name if self.service else "",
                "product": self.service.product if self.service else "",
                "version": self.service.version if self.service else "",
                "extra_info": self.service.extra_info if self.service else "",
                "cpe": self.service.cpe if self.service else []
            },
            "scripts": self.scripts
        }


@dataclass
class Host:
    """Represents a scanned host."""
    ip: str
    hostname: str = ""
    mac_address: str = ""
    os_match: str = ""
    os_accuracy: int = 0
    status: str = "up"
    ports: List[Port] = field(default_factory=list)

    def get_open_ports(self) -> List[Port]:
        """Return only open ports."""
        return [p for p in self.ports if p.state == PortState.OPEN]

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "os_match": self.os_match,
            "os_accuracy": self.os_accuracy,
            "status": self.status,
            "ports": [p.to_dict() for p in self.ports]
        }


@dataclass
class ScanResult:
    """Represents complete scan results."""

    # Scan metadata
    scan_id: str
    scanner: str  # nmap, nessus, openvas
    scan_type: str = ""  # full, quick, vuln, etc.

    # Timing
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None

    # Target information
    target_spec: str = ""  # Original target specification

    # Results
    hosts: List[Host] = field(default_factory=list)

    # Raw data
    raw_output: str = ""
    command_line: str = ""

    # Statistics
    hosts_up: int = 0
    hosts_down: int = 0

    def get_all_open_ports(self) -> List[tuple]:
        """Return all open ports across all hosts as (host_ip, port) tuples."""
        result = []
        for host in self.hosts:
            for port in host.get_open_ports():
                result.append((host.ip, port))
        return result

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "scanner": self.scanner,
            "scan_type": self.scan_type,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "target_spec": self.target_spec,
            "hosts": [h.to_dict() for h in self.hosts],
            "command_line": self.command_line,
            "hosts_up": self.hosts_up,
            "hosts_down": self.hosts_down
        }

    def summary(self) -> str:
        """Generate a brief summary of the scan."""
        total_open_ports = sum(len(h.get_open_ports()) for h in self.hosts)
        return (
            f"Scan {self.scan_id} ({self.scanner}): "
            f"{len(self.hosts)} hosts scanned, "
            f"{self.hosts_up} up, "
            f"{total_open_ports} open ports detected"
        )
