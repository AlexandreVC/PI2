"""
AI-Powered Report Generator using Ollama.

Generates professional security reports based on scan findings:
- Executive Summary Reports (for management)
- Technical Reports (for security teams)
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .risk_calculator import get_risk_calculator

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    ollama_url: str = "http://localhost:11434"
    model: str = "mistral"
    temperature: float = 0.3
    timeout: int = 180  # Longer timeout for report generation
    organization: str = "Organization"


class AIReporter:
    """
    AI-powered security report generator.

    Generates:
    - Executive Summary: High-level overview for management
    - Technical Report: Detailed findings for security teams
    """

    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()
        self.reports_dir = Path("data/reports")
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def _call_ollama(self, prompt: str) -> Optional[str]:
        """Call Ollama API."""
        if not HAS_REQUESTS:
            return None

        try:
            response = requests.post(
                f"{self.config.ollama_url}/api/generate",
                json={
                    "model": self.config.model,
                    "prompt": prompt,
                    "temperature": self.config.temperature,
                    "stream": False
                },
                timeout=self.config.timeout
            )

            if response.status_code == 200:
                return response.json().get('response', '')
            else:
                logger.error(f"Ollama error: {response.status_code}")
        except Exception as e:
            logger.error(f"Ollama request failed: {e}")
        return None

    def generate_executive_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        organization: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate an executive summary report.

        Args:
            vulnerabilities: List of discovered vulnerabilities
            organization: Organization name

        Returns:
            Report information including content and file path
        """
        org = organization or self.config.organization
        timestamp = datetime.now()

        # Calculate statistics
        stats = self._calculate_stats(vulnerabilities)

        # Build prompt for executive report
        prompt = self._build_executive_prompt(vulnerabilities, stats, org)

        logger.info(f"Generating executive report with AI ({self.config.model})...")
        content = self._call_ollama(prompt)

        if not content:
            # Fallback to template-based report
            content = self._generate_executive_fallback(vulnerabilities, stats, org, timestamp)

        # Save report
        filename = f"executive_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.md"
        filepath = self.reports_dir / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

        return {
            'type': 'executive',
            'filename': filename,
            'filepath': str(filepath),
            'organization': org,
            'generated_at': timestamp.isoformat(),
            'vulnerability_count': len(vulnerabilities),
            'risk_score': stats['risk_score'],
            'model': self.config.model
        }

    def generate_technical_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        organization: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a detailed technical report.

        Args:
            vulnerabilities: List of discovered vulnerabilities
            organization: Organization name

        Returns:
            Report information including content and file path
        """
        org = organization or self.config.organization
        timestamp = datetime.now()

        stats = self._calculate_stats(vulnerabilities)

        # Build prompt for technical report
        prompt = self._build_technical_prompt(vulnerabilities, stats, org)

        logger.info(f"Generating technical report with AI ({self.config.model})...")
        content = self._call_ollama(prompt)

        if not content:
            # Fallback to template-based report
            content = self._generate_technical_fallback(vulnerabilities, stats, org, timestamp)

        # Save report
        filename = f"technical_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.md"
        filepath = self.reports_dir / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

        return {
            'type': 'technical',
            'filename': filename,
            'filepath': str(filepath),
            'organization': org,
            'generated_at': timestamp.isoformat(),
            'vulnerability_count': len(vulnerabilities),
            'model': self.config.model
        }

    def generate_both_reports(
        self,
        vulnerabilities: List[Dict[str, Any]],
        organization: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Generate both executive and technical reports."""
        reports = []
        reports.append(self.generate_executive_report(vulnerabilities, organization))
        reports.append(self.generate_technical_report(vulnerabilities, organization))
        return reports

    def _calculate_stats(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate statistics from vulnerabilities using advanced risk scoring."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for v in vulnerabilities:
            sev = v.get("severity", "medium").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        exploitable = sum(1 for v in vulnerabilities if v.get("exploit_available", False))

        # Use advanced risk calculator
        risk_calculator = get_risk_calculator()
        risk_result = risk_calculator.calculate_risk(vulnerabilities)

        # Group by type
        by_type = {}
        for v in vulnerabilities:
            vtype = v.get("type", "Unknown")
            by_type[vtype] = by_type.get(vtype, 0) + 1

        # Files affected
        files = set(v.get("affected_file", "") for v in vulnerabilities if v.get("affected_file"))

        return {
            "total": len(vulnerabilities),
            "severity": severity_counts,
            "by_type": by_type,
            "exploitable": exploitable,
            "risk_score": risk_result.overall_score,
            "risk_level": risk_result.risk_level,
            "risk_breakdown": risk_result.breakdown,
            "risk_recommendations": risk_result.recommendations,
            "files_affected": len(files),
            "files": list(files)
        }

    def _build_executive_prompt(
        self,
        vulnerabilities: List[Dict[str, Any]],
        stats: Dict[str, Any],
        organization: str
    ) -> str:
        """Build prompt for executive report."""
        vuln_summary = json.dumps([{
            'title': v.get('title', ''),
            'severity': v.get('severity', ''),
            'type': v.get('type', ''),
            'file': v.get('affected_file', '')
        } for v in vulnerabilities[:20]], indent=2)  # Limit for prompt size

        return f"""You are a cybersecurity expert writing an executive summary report.

ORGANIZATION: {organization}
DATE: {datetime.now().strftime('%Y-%m-%d')}

SCAN STATISTICS:
- Total Vulnerabilities: {stats['total']}
- Critical: {stats['severity']['critical']}
- High: {stats['severity']['high']}
- Medium: {stats['severity']['medium']}
- Low: {stats['severity']['low']}
- Risk Score: {stats['risk_score']}/100 ({stats.get('risk_level', 'N/A')})
- Files Affected: {stats['files_affected']}

RISK SCORE BREAKDOWN:
{json.dumps(stats.get('risk_breakdown', {}), indent=2)}

AI RECOMMENDATIONS:
{chr(10).join(f"- {r}" for r in stats.get('risk_recommendations', []))}

VULNERABILITY TYPES FOUND:
{json.dumps(stats['by_type'], indent=2)}

SAMPLE VULNERABILITIES:
{vuln_summary}

Write a professional EXECUTIVE SUMMARY REPORT in Markdown format that includes:

1. **Executive Summary** (2-3 paragraphs for C-level executives)
   - Overall security posture assessment
   - Key risks and business impact
   - Immediate action recommendations

2. **Risk Assessment**
   - Risk score explanation
   - Critical findings overview
   - Potential business impact

3. **Key Findings** (bullet points)
   - Top 5 most critical issues
   - Common vulnerability patterns

4. **Recommendations** (prioritized)
   - Immediate actions (24-48 hours)
   - Short-term actions (1-2 weeks)
   - Long-term improvements

5. **Conclusion**
   - Overall assessment
   - Next steps

Keep the language professional but accessible to non-technical executives.
Focus on business impact and risk, not technical details."""

    def _build_technical_prompt(
        self,
        vulnerabilities: List[Dict[str, Any]],
        stats: Dict[str, Any],
        organization: str
    ) -> str:
        """Build prompt for technical report."""
        vuln_details = json.dumps([{
            'title': v.get('title', ''),
            'severity': v.get('severity', ''),
            'type': v.get('type', ''),
            'file': v.get('affected_file', ''),
            'location': v.get('location', ''),
            'description': v.get('description', '')[:200],
            'cwe': v.get('cwe_id', ''),
            'remediation': v.get('remediation', '')[:200],
            'fixed_code': v.get('fixed_code', '')[:200]
        } for v in vulnerabilities[:30]], indent=2)

        return f"""You are a senior security engineer writing a detailed technical report.

ORGANIZATION: {organization}
DATE: {datetime.now().strftime('%Y-%m-%d')}

SCAN STATISTICS:
- Total Vulnerabilities: {stats['total']}
- Critical: {stats['severity']['critical']}
- High: {stats['severity']['high']}
- Medium: {stats['severity']['medium']}
- Low: {stats['severity']['low']}
- Files Affected: {stats['files_affected']}

VULNERABILITY TYPES:
{json.dumps(stats['by_type'], indent=2)}

DETAILED FINDINGS:
{vuln_details}

Write a comprehensive TECHNICAL SECURITY REPORT in Markdown format:

1. **Introduction**
   - Scope of assessment
   - Methodology used
   - Tools and techniques

2. **Technical Summary**
   - Vulnerability distribution
   - Attack surface analysis
   - Risk matrix

3. **Detailed Findings**
   For each vulnerability type found, provide:
   - Technical description
   - Affected files/components
   - CVSS/Severity justification
   - CWE references
   - Proof of concept (where applicable)
   - Detailed remediation steps with code examples

4. **Remediation Guide**
   - Step-by-step fix instructions
   - Code examples for each fix
   - Testing procedures
   - Verification methods

5. **Security Recommendations**
   - Secure coding practices
   - Architecture improvements
   - Security controls to implement
   - Monitoring suggestions

6. **Appendix**
   - Full vulnerability list
   - File inventory
   - Reference links

Include code examples for both vulnerable code and fixed versions."""

    def _generate_executive_fallback(
        self,
        vulnerabilities: List[Dict[str, Any]],
        stats: Dict[str, Any],
        organization: str,
        timestamp: datetime
    ) -> str:
        """Generate executive report without AI."""
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']

        risk_breakdown = stats.get('risk_breakdown', {})
        risk_recommendations = stats.get('risk_recommendations', [])
        risk_level = stats.get('risk_level', 'MEDIUM')

        return f"""# Executive Security Report
## {organization}
**Date:** {timestamp.strftime('%Y-%m-%d %H:%M')}

---

## Executive Summary

A comprehensive security assessment has identified **{stats['total']} vulnerabilities** in the analyzed codebase. The overall risk score is **{stats['risk_score']}/100** ({risk_level}), indicating {'critical' if risk_level == 'CRITICAL' else 'elevated' if risk_level == 'HIGH' else 'moderate'} risk levels that require {'immediate' if risk_level == 'CRITICAL' else 'prompt'} attention.

### Risk Score Breakdown

| Component | Contribution |
|-----------|--------------|
| CVSS Score Impact | {risk_breakdown.get('cvss_contribution', 0):.1f} pts |
| Business Impact | {risk_breakdown.get('business_impact_contribution', 0):.1f} pts |
| Exploitability | {risk_breakdown.get('exploitability_contribution', 0):.1f} pts |
| Asset Criticality | {risk_breakdown.get('asset_criticality_contribution', 0):.1f} pts |

**Max CVSS:** {risk_breakdown.get('cvss_max', 0):.1f}/10 | **Avg CVSS:** {risk_breakdown.get('cvss_average', 0):.1f}/10

### Severity Overview

| Severity | Count | Business Impact |
|----------|-------|-----------------|
| Critical | {stats['severity']['critical']} | Immediate exploitation possible |
| High | {stats['severity']['high']} | Significant security risk |
| Medium | {stats['severity']['medium']} | Moderate risk requiring attention |
| Low | {stats['severity']['low']} | Minor issues |

### Key Findings

{chr(10).join(f"- **{v.get('title')}** ({v.get('severity').upper()}): {v.get('type')}" for v in critical_vulns[:5])}
{chr(10).join(f"- **{v.get('title')}** ({v.get('severity').upper()}): {v.get('type')}" for v in high_vulns[:5])}

### AI-Generated Recommendations

{chr(10).join(f"{i+1}. {rec}" for i, rec in enumerate(risk_recommendations[:5])) if risk_recommendations else "No specific recommendations available."}

### Action Plan

1. **Immediate (24-48 hours):** Address all {stats['severity']['critical']} critical vulnerabilities
2. **Short-term (1-2 weeks):** Remediate high-severity findings
3. **Long-term:** Implement secure coding practices and regular security assessments

---

*Report generated by VulnAI Security Platform*
"""

    def _generate_technical_fallback(
        self,
        vulnerabilities: List[Dict[str, Any]],
        stats: Dict[str, Any],
        organization: str,
        timestamp: datetime
    ) -> str:
        """Generate technical report without AI."""
        vuln_sections = []

        for i, v in enumerate(vulnerabilities, 1):
            section = f"""
### {i}. {v.get('title', 'Unknown Vulnerability')}

**Severity:** {v.get('severity', 'Unknown').upper()}
**Type:** {v.get('type', 'Unknown')}
**File:** `{v.get('affected_file', 'Unknown')}`
**Location:** {v.get('location', 'Unknown')}
**CWE:** {v.get('cwe_id', 'N/A')}

**Description:**
{v.get('description', 'No description available.')}

**Vulnerable Code:**
```
{v.get('vulnerable_code', 'Not available')}
```

**Remediation:**
{v.get('remediation', 'Review and fix the vulnerability following secure coding practices.')}

**Fixed Code:**
```
{v.get('fixed_code', 'Not available')}
```

---
"""
            vuln_sections.append(section)

        return f"""# Technical Security Report
## {organization}
**Date:** {timestamp.strftime('%Y-%m-%d %H:%M')}

---

## 1. Introduction

This technical security report details vulnerabilities discovered during automated code analysis.

### Scope
- Files Analyzed: {stats['files_affected']}
- Vulnerability Types: {len(stats['by_type'])}

### Methodology
AI-powered static code analysis was performed to identify security vulnerabilities.

---

## 2. Summary Statistics

| Metric | Value |
|--------|-------|
| Total Vulnerabilities | {stats['total']} |
| Critical | {stats['severity']['critical']} |
| High | {stats['severity']['high']} |
| Medium | {stats['severity']['medium']} |
| Low | {stats['severity']['low']} |
| Exploitable | {stats['exploitable']} |

### Vulnerability Distribution by Type

| Type | Count |
|------|-------|
{chr(10).join(f"| {t} | {c} |" for t, c in stats['by_type'].items())}

---

## 3. Detailed Findings

{''.join(vuln_sections)}

---

## 4. Remediation Priority

1. Fix all **CRITICAL** vulnerabilities immediately
2. Address **HIGH** severity issues within 1 week
3. Plan remediation for **MEDIUM** issues
4. Review and address **LOW** severity items

---

*Report generated by VulnAI Security Platform*
"""


def create_reporter(
    model: str = "mistral",
    organization: str = "Organization",
    ollama_url: str = "http://localhost:11434"
) -> AIReporter:
    """Create an AI reporter with specified configuration."""
    config = ReportConfig(
        ollama_url=ollama_url,
        model=model,
        organization=organization
    )
    return AIReporter(config)
