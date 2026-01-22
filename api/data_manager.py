"""
Data Manager for VulnAI Platform.

Simple storage that starts EMPTY.
Vulnerabilities are only added when AI scans detect them.
NO pre-loaded data, NO demo data.
"""

import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from .risk_calculator import get_risk_calculator, RiskScore

logger = logging.getLogger(__name__)


@dataclass
class DataStore:
    """Central data store - starts EMPTY."""
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    scan_history: List[Dict[str, Any]] = field(default_factory=list)
    reports: List[Dict[str, Any]] = field(default_factory=list)


class DataManager:
    """
    Manages vulnerability data discovered by AI scans.

    IMPORTANT: Starts with ZERO vulnerabilities.
    Vulnerabilities are only added when:
    1. User uploads code/scan files
    2. AI analyzes the content
    3. AI detects actual vulnerabilities
    """

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.uploads_dir = self.data_dir / "uploads"
        self.cache_dir = self.data_dir / "cache"
        self.reports_dir = self.data_dir / "reports"

        # Create directories
        for d in [self.uploads_dir, self.cache_dir, self.reports_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # Initialize EMPTY data store
        self.store = DataStore()

        # Load any previously saved scan results (not pre-populated data)
        self._load_saved_results()

        logger.info(f"DataManager initialized with {len(self.store.vulnerabilities)} vulnerabilities from previous scans")

    def _load_saved_results(self):
        """Load previously saved scan results (user's own scans, not demo data)."""
        cache_file = self.cache_dir / "scan_results.json"

        if cache_file.exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.store.vulnerabilities = data.get('vulnerabilities', [])
                    self.store.scan_history = data.get('scan_history', [])
                    self.store.reports = data.get('reports', [])
                    logger.info(f"Loaded {len(self.store.vulnerabilities)} vulnerabilities from previous scans")
            except Exception as e:
                logger.error(f"Failed to load saved results: {e}")
                # Start fresh if load fails
                self.store = DataStore()

    def save_results(self):
        """Save current scan results to cache."""
        cache_file = self.cache_dir / "scan_results.json"

        try:
            data = {
                'vulnerabilities': self.store.vulnerabilities,
                'scan_history': self.store.scan_history,
                'reports': self.store.reports,
                'saved_at': datetime.now().isoformat()
            }
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            logger.info(f"Saved {len(self.store.vulnerabilities)} vulnerabilities")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")

    def clear_all_data(self):
        """Clear all vulnerability data (reset to empty state)."""
        self.store = DataStore()
        self.save_results()
        logger.info("All data cleared")

    def add_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a vulnerability discovered by AI scan."""
        # Generate ID if not present
        if 'id' not in vuln_data:
            vuln_data['id'] = f"VULN-{len(self.store.vulnerabilities) + 1:04d}"

        vuln_data['discovered_at'] = datetime.now().isoformat()
        self.store.vulnerabilities.append(vuln_data)
        self.save_results()

        return vuln_data

    def add_vulnerabilities(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add multiple vulnerabilities from an AI scan."""
        added = []
        for vuln in vulns:
            added.append(self.add_vulnerability(vuln))
        return added

    def add_scan_record(self, scan_info: Dict[str, Any]):
        """Record a scan that was performed."""
        scan_info['scanned_at'] = datetime.now().isoformat()
        self.store.scan_history.append(scan_info)
        self.save_results()

    def add_report(self, report_info: Dict[str, Any]):
        """Record a generated report."""
        report_info['generated_at'] = datetime.now().isoformat()
        self.store.reports.append(report_info)
        self.save_results()

    def get_vulnerabilities(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get discovered vulnerabilities, optionally filtered by project."""
        if project_id:
            return [v for v in self.store.vulnerabilities if v.get("project_id") == project_id]
        return self.store.vulnerabilities

    def get_vulnerability(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific vulnerability by ID."""
        for v in self.store.vulnerabilities:
            if v.get('id') == vuln_id:
                return v
        return None

    def update_vulnerability(self, vuln_id: str, updated_data: Dict[str, Any]) -> bool:
        """Update an existing vulnerability with new data."""
        for i, v in enumerate(self.store.vulnerabilities):
            if v.get('id') == vuln_id:
                # Preserve the original ID and discovery time
                updated_data['id'] = vuln_id
                if 'discovered_at' in v:
                    updated_data['discovered_at'] = v['discovered_at']
                updated_data['updated_at'] = datetime.now().isoformat()
                self.store.vulnerabilities[i] = updated_data
                self.save_results()
                return True
        return False

    def get_scan_history(self) -> List[Dict[str, Any]]:
        """Get scan history."""
        return self.store.scan_history

    def get_reports(self) -> List[Dict[str, Any]]:
        """Get generated reports."""
        return self.store.reports

    def get_stats(self, project_id: Optional[str] = None) -> Dict[str, Any]:
        """Get dashboard statistics with advanced risk scoring, optionally filtered by project."""
        vulns = self.get_vulnerabilities(project_id)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            sev = v.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        exploitable = sum(1 for v in vulns if v.get("exploit_available", False))
        patchable = sum(1 for v in vulns if v.get("patch_available", False))

        # Advanced risk score calculation using CVSS and business impact
        risk_calculator = get_risk_calculator()
        risk_result: RiskScore = risk_calculator.calculate_risk(vulns)

        unique_hosts = list(set(
            v.get("affected_host", "") for v in vulns if v.get("affected_host")
        ))

        return {
            "total_vulnerabilities": len(vulns),
            "severity_breakdown": severity_counts,
            "exploitable_count": exploitable,
            "patchable_count": patchable,
            "risk_score": risk_result.overall_score,
            "risk_level": risk_result.risk_level,
            "risk_breakdown": risk_result.breakdown,
            "risk_recommendations": risk_result.recommendations,
            "hosts_affected": len(unique_hosts),
            "unique_hosts": unique_hosts,
            "total_scans": len(self.store.scan_history),
            "total_reports": len(self.store.reports)
        }

    def get_mitre_summary(self) -> Dict[str, Any]:
        """Get MITRE ATT&CK tactics summary from discovered vulnerabilities."""
        tactics_data = {}

        for v in self.store.vulnerabilities:
            for tactic in v.get("mitre_tactics", []):
                if tactic not in tactics_data:
                    tactics_data[tactic] = {"count": 0, "vulnerabilities": []}
                tactics_data[tactic]["count"] += 1
                tactics_data[tactic]["vulnerabilities"].append(v.get("id"))

        return {"tactics": tactics_data}

    def get_hosts_summary(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get affected hosts summary, optionally filtered by project."""
        hosts_data = {}

        vulns = self.get_vulnerabilities(project_id)
        for v in vulns:
            host = v.get("affected_host", "")
            if host:
                if host not in hosts_data:
                    hosts_data[host] = {
                        "ip": host,
                        "project_id": v.get("project_id"),
                        "vulnerabilities": [],
                        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}
                    }
                hosts_data[host]["vulnerabilities"].append(v.get("id"))
                sev = v.get("severity", "low")
                if sev in hosts_data[host]["severity_counts"]:
                    hosts_data[host]["severity_counts"][sev] += 1

        return list(hosts_data.values())


# Global data manager instance
_data_manager: Optional[DataManager] = None


def get_data_manager() -> DataManager:
    """Get or create the global DataManager instance."""
    global _data_manager
    if _data_manager is None:
        _data_manager = DataManager(data_dir="data")
    return _data_manager
