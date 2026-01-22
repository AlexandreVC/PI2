"""Technical report generator for security administrators."""

from typing import List, Dict, Any, Optional
from datetime import datetime
import json

from .base_report import BaseReportGenerator, ReportFormat
from ..models import Vulnerability, ScanResult
from ..agent import LLMClient


class TechnicalReportGenerator(BaseReportGenerator):
    """
    Generate detailed technical security reports.

    Features:
    - Complete vulnerability details
    - Technical remediation steps
    - Configuration examples
    - MITRE ATT&CK mapping
    - CVE/CWE references
    """

    def __init__(
            self,
            output_dir: str = "data/reports",
            llm_client: Optional[LLMClient] = None
    ):
        """
        Initialize technical report generator.

        Args:
            output_dir: Output directory for reports
            llm_client: Optional LLM client for AI analysis
        """
        super().__init__(output_dir)
        self.llm = llm_client

    def generate(
            self,
            vulnerabilities: List[Vulnerability],
            scan_results: Optional[List[ScanResult]] = None,
            metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate technical report."""
        metadata = metadata or {}

        # Sort vulnerabilities by severity
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: v.cvss_score,
            reverse=True
        )

        # Build report sections
        report = self._build_header(metadata)
        report += self._build_summary(vulnerabilities, scan_results)
        report += self._build_scope(scan_results, metadata)
        report += self._build_findings_overview(vulnerabilities)
        report += self._build_detailed_findings(sorted_vulns)
        report += self._build_mitre_analysis(vulnerabilities)
        report += self._build_remediation_guide(sorted_vulns)
        report += self._build_appendices(vulnerabilities, scan_results)

        return report

    def _build_header(self, metadata: Dict[str, Any]) -> str:
        """Build report header."""
        return f"""# Technical Security Assessment Report

**Assessment Date:** {self._format_timestamp()}
**Report Version:** 1.0
**Classification:** {metadata.get("classification", "Confidential")}
**Prepared By:** {metadata.get("prepared_by", "Security Team")}

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Assessment Scope](#assessment-scope)
3. [Findings Overview](#findings-overview)
4. [Detailed Findings](#detailed-findings)
5. [MITRE ATT&CK Analysis](#mitre-attck-analysis)
6. [Remediation Guide](#remediation-guide)
7. [Appendices](#appendices)

---

"""

    def _build_summary(
            self,
            vulnerabilities: List[Vulnerability],
            scan_results: Optional[List[ScanResult]]
    ) -> str:
        """Build technical summary."""
        stats = self._get_severity_stats(vulnerabilities)
        total = len(vulnerabilities)

        hosts_scanned = 0
        ports_found = 0
        if scan_results:
            hosts_scanned = sum(len(sr.hosts) for sr in scan_results)
            ports_found = sum(
                len(h.get_open_ports())
                for sr in scan_results
                for h in sr.hosts
            )

        return f"""## 1. Executive Summary

### Assessment Results

| Metric | Value |
|--------|-------|
| Total Vulnerabilities | {total} |
| Critical | {stats['critical']} |
| High | {stats['high']} |
| Medium | {stats['medium']} |
| Low | {stats['low']} |
| Informational | {stats['info']} |
| Hosts Scanned | {hosts_scanned} |
| Open Ports Detected | {ports_found} |
| Exploitable Vulns | {sum(1 for v in vulnerabilities if v.exploit_available)} |

### Risk Assessment

- **Overall Risk Level:** {self._get_risk_level(vulnerabilities)}
- **Risk Score:** {self._calculate_risk_score(vulnerabilities):.1f}/100

### Critical Findings Summary

"""

    def _build_scope(
            self,
            scan_results: Optional[List[ScanResult]],
            metadata: Dict[str, Any]
    ) -> str:
        """Build assessment scope section."""
        section = """## 2. Assessment Scope

### Target Systems

"""
        if scan_results:
            for sr in scan_results:
                section += f"**Scan: {sr.scan_id}** ({sr.scanner})\n"
                section += f"- Type: {sr.scan_type}\n"
                section += f"- Target: {sr.target_spec}\n"
                section += f"- Hosts Up: {sr.hosts_up}\n"

                if sr.hosts:
                    section += "\n| Host | Hostname | OS | Open Ports |\n"
                    section += "|------|----------|----|-----------|\n"
                    for host in sr.hosts[:10]:  # Limit to 10
                        open_ports = ", ".join(
                            str(p.number) for p in host.get_open_ports()[:5]
                        )
                        section += f"| {host.ip} | {host.hostname or 'N/A'} | {host.os_match[:30] if host.os_match else 'Unknown'} | {open_ports} |\n"

                section += "\n"
        else:
            section += "Scan results not available.\n\n"

        section += f"""### Assessment Methodology

- Network discovery and port scanning (Nmap)
- Vulnerability scanning (Nessus)
- CVE/NVD correlation
- MITRE ATT&CK mapping
- AI-assisted analysis

### Tools Used

| Tool | Purpose |
|------|---------|
| Nmap | Network discovery, port scanning |
| Nessus | Vulnerability assessment |
| NVD API | CVE enrichment |
| Custom AI Agent | Analysis and correlation |

"""
        return section

    def _build_findings_overview(self, vulnerabilities: List[Vulnerability]) -> str:
        """Build findings overview section."""
        section = """## 3. Findings Overview

### Vulnerability Distribution by Severity

"""
        stats = self._get_severity_stats(vulnerabilities)

        # ASCII bar chart
        max_count = max(stats.values()) if stats.values() else 1
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = stats[severity]
            bar_length = int((count / max_count) * 30) if max_count > 0 else 0
            bar = "█" * bar_length
            section += f"{severity.upper():10} | {bar} {count}\n"

        section += "\n### Vulnerabilities by Host\n\n"
        section += "| Host | Critical | High | Medium | Low |\n"
        section += "|------|----------|------|--------|-----|\n"

        # Group by host
        host_vulns: Dict[str, Dict[str, int]] = {}
        for v in vulnerabilities:
            if v.affected_host not in host_vulns:
                host_vulns[v.affected_host] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            host_vulns[v.affected_host][v.severity.value] += 1

        for host, counts in host_vulns.items():
            section += f"| {host} | {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |\n"

        section += "\n### CVE Coverage\n\n"
        cve_vulns = [v for v in vulnerabilities if v.cve_id]
        section += f"- Vulnerabilities with CVE: {len(cve_vulns)}/{len(vulnerabilities)}\n"

        return section + "\n"

    def _build_detailed_findings(self, vulnerabilities: List[Vulnerability]) -> str:
        """Build detailed findings section."""
        section = """## 4. Detailed Findings

"""
        for i, vuln in enumerate(vulnerabilities, 1):
            section += self._format_vulnerability_details(i, vuln)

        return section

    def _format_vulnerability_details(self, index: int, vuln: Vulnerability) -> str:
        """Format single vulnerability details."""
        # Build location info
        location_info = ""
        if vuln.affected_file:
            location_info = f"- File: `{vuln.affected_file}`\n"
            if vuln.location:
                location_info += f"- Location: {vuln.location}\n"

        # Build vulnerable code section
        vulnerable_code_section = ""
        if vuln.vulnerable_code:
            vulnerable_code_section = f"""
**Vulnerable Code:**
```
{vuln.vulnerable_code}
```
"""

        # Build fixed code section
        fixed_code_section = ""
        if vuln.fixed_code:
            fixed_code_section = f"""
**Fixed Code:**
```
{vuln.fixed_code}
```
"""

        return f"""### 4.{index}. {vuln.title}

**Identifiers:**
- Internal ID: `{vuln.id}`
- CVE: {vuln.cve_id or "N/A"}
- CWE: {vuln.cwe_id or "N/A"}

**Severity:**
- CVSS Score: **{vuln.cvss_score}** ({vuln.severity.value.upper()})
- CVSS Vector: `{vuln.cvss_vector or "N/A"}`

**Affected System:**
- Host: `{vuln.affected_host}`
- Port: {vuln.affected_port}
- Service: {vuln.affected_service}
- Product: {vuln.affected_product or "N/A"}
- Version: {vuln.affected_version or "N/A"}
{location_info}
**Description:**
{vuln.description or "No description available."}
{vulnerable_code_section}
**Exploit Status:**
- Exploit Available: {"Yes" if vuln.exploit_available else "No"}
- Exploitability: {vuln.exploitability or "Unknown"}
- Patch Available: {"Yes" if vuln.patch_available else "No"}

**MITRE ATT&CK:**
- Tactics: {", ".join(vuln.mitre_tactics) if vuln.mitre_tactics else "N/A"}
- Techniques: {", ".join(vuln.mitre_techniques) if vuln.mitre_techniques else "N/A"}

**AI Analysis:**
{vuln.ai_analysis if vuln.ai_analysis else "Analysis pending."}

**Remediation:**
{vuln.remediation if vuln.remediation else "See remediation guide."}
{fixed_code_section}
**References:**
{self._format_references(vuln.references)}

---

"""

    def _build_mitre_analysis(self, vulnerabilities: List[Vulnerability]) -> str:
        """Build MITRE ATT&CK analysis section."""
        section = """## 5. MITRE ATT&CK Analysis

### Tactics Coverage

The following MITRE ATT&CK tactics are relevant to the identified vulnerabilities:

"""
        # Collect all tactics
        tactics: Dict[str, List[str]] = {}
        techniques: Dict[str, List[str]] = {}

        for vuln in vulnerabilities:
            for tactic in vuln.mitre_tactics:
                if tactic not in tactics:
                    tactics[tactic] = []
                tactics[tactic].append(vuln.id)

            for technique in vuln.mitre_techniques:
                if technique not in techniques:
                    techniques[technique] = []
                techniques[technique].append(vuln.id)

        section += "| Tactic | Vulnerability Count | Examples |\n"
        section += "|--------|--------------------|---------|\n"

        for tactic, vuln_ids in sorted(tactics.items()):
            examples = ", ".join(vuln_ids[:3])
            section += f"| {tactic} | {len(vuln_ids)} | {examples} |\n"

        section += "\n### Techniques Identified\n\n"
        section += "| Technique | Description | Affected Vulnerabilities |\n"
        section += "|-----------|-------------|-------------------------|\n"

        for technique, vuln_ids in sorted(techniques.items()):
            section += f"| {technique} | - | {len(vuln_ids)} |\n"

        section += """
### Attack Path Analysis

Based on the identified vulnerabilities, potential attack paths include:

1. **Initial Access** via exploitable network services
2. **Execution** through vulnerable applications
3. **Privilege Escalation** using local vulnerabilities
4. **Lateral Movement** via compromised credentials

"""
        return section

    def _build_remediation_guide(self, vulnerabilities: List[Vulnerability]) -> str:
        """Build remediation guide section."""
        section = """## 6. Remediation Guide

### Priority Matrix

| Priority | Timeframe | Criteria |
|----------|-----------|----------|
| P1 - Critical | 24-48 hours | CVSS >= 9.0 or active exploit |
| P2 - High | 1 week | CVSS >= 7.0 |
| P3 - Medium | 2-4 weeks | CVSS >= 4.0 |
| P4 - Low | Next cycle | CVSS < 4.0 |

### Remediation Steps by Priority

"""
        # Group by priority
        p1 = [v for v in vulnerabilities if v.cvss_score >= 9.0 or v.exploit_available]
        p2 = [v for v in vulnerabilities if 7.0 <= v.cvss_score < 9.0 and not v.exploit_available]
        p3 = [v for v in vulnerabilities if 4.0 <= v.cvss_score < 7.0]
        p4 = [v for v in vulnerabilities if v.cvss_score < 4.0]

        if p1:
            section += "#### P1 - Critical (Immediate)\n\n"
            for v in p1:
                section += f"- **{v.title}** ({v.affected_host})\n"
                section += f"  - {v.remediation or 'Apply vendor patch immediately'}\n\n"

        if p2:
            section += "#### P2 - High (1 Week)\n\n"
            for v in p2:
                section += f"- **{v.title}** ({v.affected_host})\n"
                section += f"  - {v.remediation or 'Schedule patching'}\n\n"

        if p3:
            section += "#### P3 - Medium (2-4 Weeks)\n\n"
            for v in p3[:10]:  # Limit display
                section += f"- **{v.title}** ({v.affected_host})\n"

        if p4:
            section += f"\n#### P4 - Low ({len(p4)} items)\n\n"
            section += "Address during regular maintenance cycles.\n\n"

        section += """### General Recommendations

1. **Patch Management**
   - Establish regular patching schedule
   - Test patches in staging environment
   - Document all changes

2. **Configuration Hardening**
   - Disable unnecessary services
   - Implement least privilege
   - Enable security logging

3. **Network Security**
   - Segment networks appropriately
   - Implement firewall rules
   - Enable IDS/IPS

4. **Monitoring**
   - Enable comprehensive logging
   - Implement SIEM integration
   - Set up alerting for critical events

"""
        return section

    def _build_appendices(
            self,
            vulnerabilities: List[Vulnerability],
            scan_results: Optional[List[ScanResult]]
    ) -> str:
        """Build appendices section."""
        section = """## 7. Appendices

### A. Vulnerability Data (JSON)

```json
"""
        # Export vulnerability data as JSON
        vuln_data = [v.to_dict() for v in vulnerabilities[:10]]  # Limit for readability
        section += json.dumps(vuln_data, indent=2, default=str)

        section += """
```

### B. CVE References

"""
        cves = set(v.cve_id for v in vulnerabilities if v.cve_id)
        for cve in sorted(cves):
            section += f"- [{cve}](https://nvd.nist.gov/vuln/detail/{cve})\n"

        section += f"""
### C. Report Metadata

- Generated: {self._format_timestamp()}
- Total Vulnerabilities: {len(vulnerabilities)}
- Scanner Sources: {", ".join(set(v.source for v in vulnerabilities))}

---

*End of Technical Report*
"""
        return section

    def _format_references(self, references: List[str]) -> str:
        """Format reference URLs."""
        if not references:
            return "None available"

        formatted = []
        for ref in references[:5]:  # Limit to 5
            formatted.append(f"- {ref}")

        return "\n".join(formatted)

    def _get_risk_level(self, vulnerabilities: List[Vulnerability]) -> str:
        """Determine overall risk level."""
        score = self._calculate_risk_score(vulnerabilities)
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        return "LOW"
