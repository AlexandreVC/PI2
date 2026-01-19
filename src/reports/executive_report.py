"""Executive report generator for management audience."""

from typing import List, Dict, Any, Optional
from datetime import datetime

from .base_report import BaseReportGenerator, ReportFormat
from ..models import Vulnerability, ScanResult
from ..agent import LLMClient


class ExecutiveReportGenerator(BaseReportGenerator):
    """
    Generate executive-level security reports.

    Features:
    - High-level risk summary
    - Business impact focus
    - Key metrics and trends
    - Strategic recommendations
    - No technical jargon
    """

    def __init__(
            self,
            output_dir: str = "data/reports",
            llm_client: Optional[LLMClient] = None
    ):
        """
        Initialize executive report generator.

        Args:
            output_dir: Output directory for reports
            llm_client: Optional LLM client for AI summaries
        """
        super().__init__(output_dir)
        self.llm = llm_client

    def generate(
            self,
            vulnerabilities: List[Vulnerability],
            scan_results: Optional[List[ScanResult]] = None,
            metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate executive report."""
        metadata = metadata or {}

        # Calculate statistics
        severity_stats = self._get_severity_stats(vulnerabilities)
        risk_score = self._calculate_risk_score(vulnerabilities)
        top_vulns = self._get_top_vulnerabilities(vulnerabilities, 5)

        # Build report
        report = self._build_header(metadata)
        report += self._build_executive_summary(
            vulnerabilities, severity_stats, risk_score
        )
        report += self._build_risk_overview(risk_score, severity_stats)
        report += self._build_key_findings(top_vulns)
        report += self._build_business_impact(vulnerabilities)
        report += self._build_recommendations(vulnerabilities)
        report += self._build_resource_requirements(vulnerabilities)
        report += self._build_footer()

        return report

    def _build_header(self, metadata: Dict[str, Any]) -> str:
        """Build report header."""
        org_name = metadata.get("organization", "Organization")
        report_date = self._format_timestamp()

        return f"""# Security Assessment - Executive Report

**Organization:** {org_name}
**Report Date:** {report_date}
**Classification:** {metadata.get("classification", "Internal")}

---

"""

    def _build_executive_summary(
            self,
            vulnerabilities: List[Vulnerability],
            stats: Dict[str, int],
            risk_score: float
    ) -> str:
        """Build executive summary section."""
        total = len(vulnerabilities)
        critical_high = stats["critical"] + stats["high"]

        # Determine risk level text
        if risk_score >= 75:
            risk_level = "CRITICAL"
            risk_color = "red"
        elif risk_score >= 50:
            risk_level = "HIGH"
            risk_color = "orange"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
            risk_color = "yellow"
        else:
            risk_level = "LOW"
            risk_color = "green"

        summary = f"""## Executive Summary

### Overall Security Posture: {risk_level}

The security assessment identified **{total} vulnerabilities** across the evaluated systems.

| Risk Category | Count | Percentage |
|--------------|-------|------------|
| Critical | {stats['critical']} | {stats['critical']/total*100 if total else 0:.1f}% |
| High | {stats['high']} | {stats['high']/total*100 if total else 0:.1f}% |
| Medium | {stats['medium']} | {stats['medium']/total*100 if total else 0:.1f}% |
| Low | {stats['low']} | {stats['low']/total*100 if total else 0:.1f}% |

**Key Metrics:**
- Overall Risk Score: **{risk_score:.0f}/100**
- Critical/High Priority Issues: **{critical_high}**
- Exploitable Vulnerabilities: **{sum(1 for v in vulnerabilities if v.exploit_available)}**

"""

        # Add AI-generated summary if available
        if self.llm:
            ai_summary = self._generate_ai_summary(vulnerabilities)
            if ai_summary:
                summary += f"""**AI Analysis Summary:**
{ai_summary}

"""

        return summary

    def _build_risk_overview(
            self, risk_score: float, stats: Dict[str, int]
    ) -> str:
        """Build risk overview section."""
        return f"""## Risk Overview

### Risk Score Breakdown

The organization's current risk score is **{risk_score:.0f}** out of 100.

**Risk Factors:**
- {stats['critical']} critical vulnerabilities that could lead to immediate compromise
- {stats['high']} high-severity issues requiring urgent attention
- {stats['medium']} medium-risk vulnerabilities for scheduled remediation

### Risk Trend

This assessment establishes a baseline for tracking security improvements. Future assessments will show trend analysis.

"""

    def _build_key_findings(self, top_vulns: List[Vulnerability]) -> str:
        """Build key findings section."""
        section = """## Key Findings

The following are the most critical security issues identified:

"""
        for i, vuln in enumerate(top_vulns, 1):
            section += f"""### {i}. {vuln.title}

- **Risk Level:** {vuln.severity.value.upper()}
- **CVSS Score:** {vuln.cvss_score}
- **Affected System:** {vuln.affected_host}
- **Exploitable:** {"Yes - Active exploits available" if vuln.exploit_available else "No known exploits"}

{vuln.ai_business_impact if vuln.ai_business_impact else "Impact assessment pending."}

"""
        return section

    def _build_business_impact(self, vulnerabilities: List[Vulnerability]) -> str:
        """Build business impact section."""
        exploitable = sum(1 for v in vulnerabilities if v.exploit_available)
        critical = sum(1 for v in vulnerabilities if v.severity.value == "critical")

        section = """## Business Impact Assessment

### Potential Consequences

| Impact Area | Risk Level | Description |
|-------------|------------|-------------|
"""
        # Determine impact levels
        if critical > 0 or exploitable > 3:
            section += "| Data Breach | HIGH | Critical vulnerabilities could lead to unauthorized data access |\n"
            section += "| Operations | HIGH | System compromise could disrupt business operations |\n"
            section += "| Compliance | HIGH | Potential regulatory violations and penalties |\n"
            section += "| Reputation | HIGH | Public disclosure could damage brand trust |\n"
        elif exploitable > 0:
            section += "| Data Breach | MEDIUM | Exploitable vulnerabilities present data risk |\n"
            section += "| Operations | MEDIUM | Potential for service disruption |\n"
            section += "| Compliance | MEDIUM | May require disclosure to regulators |\n"
            section += "| Reputation | MEDIUM | Limited exposure risk |\n"
        else:
            section += "| Data Breach | LOW | Limited immediate risk |\n"
            section += "| Operations | LOW | Minimal disruption expected |\n"
            section += "| Compliance | LOW | No immediate compliance concerns |\n"
            section += "| Reputation | LOW | Manageable with standard processes |\n"

        section += """
### Financial Risk Estimate

Based on industry benchmarks and the vulnerabilities identified:
- **Potential breach cost:** Varies based on data sensitivity and regulatory environment
- **Remediation investment:** Recommended budget allocation for security improvements

"""
        return section

    def _build_recommendations(self, vulnerabilities: List[Vulnerability]) -> str:
        """Build strategic recommendations."""
        critical = [v for v in vulnerabilities if v.severity.value == "critical"]
        high = [v for v in vulnerabilities if v.severity.value == "high"]

        section = """## Strategic Recommendations

### Immediate Actions (0-30 Days)

"""
        if critical:
            section += f"""1. **Address Critical Vulnerabilities**
   - {len(critical)} critical issues require immediate attention
   - Allocate emergency resources for patching
   - Implement temporary mitigations where patching is not immediately possible

"""

        if high:
            section += f"""2. **Remediate High-Priority Issues**
   - {len(high)} high-severity vulnerabilities identified
   - Schedule remediation within the next 30 days
   - Prioritize internet-facing systems

"""

        section += """3. **Enhance Monitoring**
   - Implement additional logging for affected systems
   - Enable alerting for suspicious activity
   - Review access controls

### Medium-Term Actions (30-90 Days)

1. **Security Architecture Review**
   - Evaluate network segmentation
   - Assess access control policies
   - Review security tool effectiveness

2. **Process Improvements**
   - Establish regular vulnerability scanning schedule
   - Implement patch management procedures
   - Develop incident response playbooks

### Long-Term Strategy

1. **Security Program Maturity**
   - Invest in security awareness training
   - Consider security certifications (ISO 27001, SOC 2)
   - Evaluate managed security services

"""
        return section

    def _build_resource_requirements(
            self, vulnerabilities: List[Vulnerability]
    ) -> str:
        """Build resource requirements section."""
        critical_high = sum(
            1 for v in vulnerabilities
            if v.severity.value in ["critical", "high"]
        )

        section = """## Resource Requirements

### Estimated Effort

| Priority | Vulnerabilities | Estimated Effort |
|----------|-----------------|------------------|
"""
        stats = self._get_severity_stats(vulnerabilities)
        section += f"| Critical | {stats['critical']} | Immediate - dedicated resources |\n"
        section += f"| High | {stats['high']} | 1-2 weeks |\n"
        section += f"| Medium | {stats['medium']} | 2-4 weeks |\n"
        section += f"| Low | {stats['low']} | Scheduled maintenance |\n"

        section += """
### Recommended Team

- Security Engineer(s) for vulnerability remediation
- System Administrators for patching
- Project Manager for coordination
- Management oversight for critical decisions

"""
        return section

    def _build_footer(self) -> str:
        """Build report footer."""
        return f"""---

## Appendix

### Report Methodology

This report was generated using automated vulnerability analysis enhanced with AI-powered risk assessment. The findings are based on:
- Network and vulnerability scan results
- CVE/NVD vulnerability database correlation
- MITRE ATT&CK framework mapping
- Industry best practices

### Disclaimer

This report represents a point-in-time assessment. Security posture can change as new vulnerabilities are discovered or systems are modified. Regular assessments are recommended.

### Contact

For questions about this report or to discuss remediation strategies, please contact your security team.

---
*Report generated on {self._format_timestamp()}*
"""

    def _generate_ai_summary(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate AI-powered executive summary."""
        if not self.llm:
            return ""

        stats = self._get_severity_stats(vulnerabilities)

        prompt = f"""Generate a brief executive summary (3-4 sentences) for a security assessment that found:
- {stats['critical']} critical vulnerabilities
- {stats['high']} high vulnerabilities
- {stats['medium']} medium vulnerabilities
- {stats['low']} low vulnerabilities
- {sum(1 for v in vulnerabilities if v.exploit_available)} with known exploits

Focus on business risk and recommended actions. Write for non-technical executives."""

        try:
            response = self.llm.generate(
                prompt,
                "You are a cybersecurity expert writing for business executives.",
                temperature=0.3
            )
            return response.content
        except Exception:
            return ""
