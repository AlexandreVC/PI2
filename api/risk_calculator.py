"""
Advanced Risk Score Calculator for VulnAI Platform.

Calculates risk scores based on:
- CVSS scores (individual and aggregate)
- Business impact factors
- Exploitability
- Asset criticality
- Temporal factors

Based on industry standards: CVSS, FAIR, OWASP Risk Rating
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class BusinessImpactLevel(Enum):
    """Business impact levels based on potential damage."""
    CRITICAL = 4  # Business-ending, major data breach, complete system compromise
    HIGH = 3      # Significant financial loss, sensitive data exposure
    MEDIUM = 2    # Moderate impact, limited data exposure
    LOW = 1       # Minor impact, no sensitive data
    MINIMAL = 0   # Negligible business impact


class AssetCriticality(Enum):
    """Asset criticality levels."""
    MISSION_CRITICAL = 4  # Core business systems, cannot operate without
    BUSINESS_CRITICAL = 3  # Important but has workarounds
    BUSINESS_OPERATIONAL = 2  # Supports daily operations
    ADMINISTRATIVE = 1  # Administrative systems
    NON_CRITICAL = 0  # Non-essential systems


@dataclass
class RiskFactors:
    """All factors contributing to risk calculation."""
    cvss_base: float = 0.0
    cvss_max: float = 0.0
    cvss_average: float = 0.0
    business_impact: float = 0.0
    exploitability: float = 0.0
    asset_criticality: float = 0.0
    temporal_factor: float = 1.0
    vulnerability_count_factor: float = 0.0


@dataclass
class RiskScore:
    """Complete risk score with breakdown."""
    overall_score: float  # 0-100
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    factors: RiskFactors
    recommendations: List[str] = field(default_factory=list)
    breakdown: Dict[str, float] = field(default_factory=dict)


class RiskCalculator:
    """
    Advanced risk calculator using CVSS scores and business impact.

    Formula:
    Risk = (CVSS_Component * 0.4) + (Business_Impact * 0.3) +
           (Exploitability * 0.15) + (Asset_Criticality * 0.15)

    With temporal adjustments and vulnerability density factors.
    """

    # Vulnerability type to business impact mapping
    BUSINESS_IMPACT_MAP: Dict[str, BusinessImpactLevel] = {
        # Critical business impact - data breaches, complete compromise
        "sql_injection": BusinessImpactLevel.CRITICAL,
        "sql injection": BusinessImpactLevel.CRITICAL,
        "remote_code_execution": BusinessImpactLevel.CRITICAL,
        "remote code execution": BusinessImpactLevel.CRITICAL,
        "rce": BusinessImpactLevel.CRITICAL,
        "command_injection": BusinessImpactLevel.CRITICAL,
        "command injection": BusinessImpactLevel.CRITICAL,
        "authentication_bypass": BusinessImpactLevel.CRITICAL,
        "authentication bypass": BusinessImpactLevel.CRITICAL,
        "auth_bypass": BusinessImpactLevel.CRITICAL,
        "privilege_escalation": BusinessImpactLevel.CRITICAL,
        "privilege escalation": BusinessImpactLevel.CRITICAL,
        "deserialization": BusinessImpactLevel.CRITICAL,
        "insecure_deserialization": BusinessImpactLevel.CRITICAL,
        "insecure deserialization": BusinessImpactLevel.CRITICAL,
        "arbitrary_file_upload": BusinessImpactLevel.CRITICAL,
        "file upload": BusinessImpactLevel.CRITICAL,
        "ssrf": BusinessImpactLevel.CRITICAL,
        "server_side_request_forgery": BusinessImpactLevel.CRITICAL,

        # High business impact - significant exposure
        "xss": BusinessImpactLevel.HIGH,
        "cross_site_scripting": BusinessImpactLevel.HIGH,
        "cross-site scripting": BusinessImpactLevel.HIGH,
        "stored_xss": BusinessImpactLevel.CRITICAL,  # Stored XSS is more severe
        "path_traversal": BusinessImpactLevel.HIGH,
        "path traversal": BusinessImpactLevel.HIGH,
        "directory_traversal": BusinessImpactLevel.HIGH,
        "lfi": BusinessImpactLevel.HIGH,
        "local_file_inclusion": BusinessImpactLevel.HIGH,
        "rfi": BusinessImpactLevel.CRITICAL,
        "remote_file_inclusion": BusinessImpactLevel.CRITICAL,
        "xxe": BusinessImpactLevel.HIGH,
        "xml_external_entity": BusinessImpactLevel.HIGH,
        "idor": BusinessImpactLevel.HIGH,
        "insecure_direct_object_reference": BusinessImpactLevel.HIGH,
        "broken_access_control": BusinessImpactLevel.HIGH,
        "broken access control": BusinessImpactLevel.HIGH,
        "hardcoded_credentials": BusinessImpactLevel.HIGH,
        "hardcoded credentials": BusinessImpactLevel.HIGH,
        "hardcoded_password": BusinessImpactLevel.HIGH,
        "hardcoded_secret": BusinessImpactLevel.HIGH,
        "exposed_credentials": BusinessImpactLevel.HIGH,
        "credential_exposure": BusinessImpactLevel.HIGH,
        "session_fixation": BusinessImpactLevel.HIGH,
        "session fixation": BusinessImpactLevel.HIGH,
        "jwt_vulnerability": BusinessImpactLevel.HIGH,
        "weak_jwt": BusinessImpactLevel.HIGH,

        # Medium business impact
        "csrf": BusinessImpactLevel.MEDIUM,
        "cross_site_request_forgery": BusinessImpactLevel.MEDIUM,
        "cross-site request forgery": BusinessImpactLevel.MEDIUM,
        "open_redirect": BusinessImpactLevel.MEDIUM,
        "open redirect": BusinessImpactLevel.MEDIUM,
        "weak_cryptography": BusinessImpactLevel.MEDIUM,
        "weak cryptography": BusinessImpactLevel.MEDIUM,
        "weak_encryption": BusinessImpactLevel.MEDIUM,
        "insecure_crypto": BusinessImpactLevel.MEDIUM,
        "sensitive_data_exposure": BusinessImpactLevel.HIGH,
        "sensitive data exposure": BusinessImpactLevel.HIGH,
        "information_disclosure": BusinessImpactLevel.MEDIUM,
        "information disclosure": BusinessImpactLevel.MEDIUM,
        "info_disclosure": BusinessImpactLevel.MEDIUM,
        "error_disclosure": BusinessImpactLevel.LOW,
        "race_condition": BusinessImpactLevel.MEDIUM,
        "race condition": BusinessImpactLevel.MEDIUM,
        "toctou": BusinessImpactLevel.MEDIUM,
        "buffer_overflow": BusinessImpactLevel.HIGH,
        "buffer overflow": BusinessImpactLevel.HIGH,
        "memory_corruption": BusinessImpactLevel.HIGH,
        "use_after_free": BusinessImpactLevel.HIGH,
        "integer_overflow": BusinessImpactLevel.MEDIUM,
        "format_string": BusinessImpactLevel.HIGH,
        "ldap_injection": BusinessImpactLevel.HIGH,
        "ldap injection": BusinessImpactLevel.HIGH,
        "xpath_injection": BusinessImpactLevel.MEDIUM,
        "nosql_injection": BusinessImpactLevel.HIGH,
        "nosql injection": BusinessImpactLevel.HIGH,
        "header_injection": BusinessImpactLevel.MEDIUM,
        "http_response_splitting": BusinessImpactLevel.MEDIUM,
        "crlf_injection": BusinessImpactLevel.MEDIUM,

        # Low business impact
        "clickjacking": BusinessImpactLevel.LOW,
        "missing_security_headers": BusinessImpactLevel.LOW,
        "missing security headers": BusinessImpactLevel.LOW,
        "insecure_cookie": BusinessImpactLevel.LOW,
        "insecure cookie": BusinessImpactLevel.LOW,
        "verbose_error": BusinessImpactLevel.LOW,
        "verbose error": BusinessImpactLevel.LOW,
        "debug_enabled": BusinessImpactLevel.MEDIUM,
        "debug enabled": BusinessImpactLevel.MEDIUM,
        "outdated_dependency": BusinessImpactLevel.MEDIUM,
        "outdated dependency": BusinessImpactLevel.MEDIUM,
        "vulnerable_dependency": BusinessImpactLevel.MEDIUM,
        "deprecated_function": BusinessImpactLevel.LOW,
        "insecure_configuration": BusinessImpactLevel.MEDIUM,
        "insecure configuration": BusinessImpactLevel.MEDIUM,
        "misconfiguration": BusinessImpactLevel.MEDIUM,
        "weak_password_policy": BusinessImpactLevel.MEDIUM,
        "missing_rate_limiting": BusinessImpactLevel.LOW,
        "dos": BusinessImpactLevel.MEDIUM,
        "denial_of_service": BusinessImpactLevel.MEDIUM,
        "denial of service": BusinessImpactLevel.MEDIUM,
        "regex_dos": BusinessImpactLevel.LOW,
        "redos": BusinessImpactLevel.LOW,

        # Minimal impact
        "code_quality": BusinessImpactLevel.MINIMAL,
        "code quality": BusinessImpactLevel.MINIMAL,
        "best_practice": BusinessImpactLevel.MINIMAL,
        "best practice": BusinessImpactLevel.MINIMAL,
        "style_issue": BusinessImpactLevel.MINIMAL,
        "documentation": BusinessImpactLevel.MINIMAL,
    }

    # Component type to asset criticality mapping
    ASSET_CRITICALITY_MAP: Dict[str, AssetCriticality] = {
        # Mission critical
        "authentication": AssetCriticality.MISSION_CRITICAL,
        "auth": AssetCriticality.MISSION_CRITICAL,
        "login": AssetCriticality.MISSION_CRITICAL,
        "payment": AssetCriticality.MISSION_CRITICAL,
        "billing": AssetCriticality.MISSION_CRITICAL,
        "database": AssetCriticality.MISSION_CRITICAL,
        "db": AssetCriticality.MISSION_CRITICAL,
        "api_gateway": AssetCriticality.MISSION_CRITICAL,
        "core": AssetCriticality.MISSION_CRITICAL,
        "security": AssetCriticality.MISSION_CRITICAL,
        "encryption": AssetCriticality.MISSION_CRITICAL,
        "crypto": AssetCriticality.MISSION_CRITICAL,

        # Business critical
        "user": AssetCriticality.BUSINESS_CRITICAL,
        "account": AssetCriticality.BUSINESS_CRITICAL,
        "session": AssetCriticality.BUSINESS_CRITICAL,
        "api": AssetCriticality.BUSINESS_CRITICAL,
        "backend": AssetCriticality.BUSINESS_CRITICAL,
        "server": AssetCriticality.BUSINESS_CRITICAL,
        "admin": AssetCriticality.BUSINESS_CRITICAL,
        "config": AssetCriticality.BUSINESS_CRITICAL,
        "settings": AssetCriticality.BUSINESS_CRITICAL,

        # Business operational
        "frontend": AssetCriticality.BUSINESS_OPERATIONAL,
        "ui": AssetCriticality.BUSINESS_OPERATIONAL,
        "web": AssetCriticality.BUSINESS_OPERATIONAL,
        "client": AssetCriticality.BUSINESS_OPERATIONAL,
        "service": AssetCriticality.BUSINESS_OPERATIONAL,
        "controller": AssetCriticality.BUSINESS_OPERATIONAL,
        "handler": AssetCriticality.BUSINESS_OPERATIONAL,

        # Administrative
        "logging": AssetCriticality.ADMINISTRATIVE,
        "log": AssetCriticality.ADMINISTRATIVE,
        "monitoring": AssetCriticality.ADMINISTRATIVE,
        "metrics": AssetCriticality.ADMINISTRATIVE,
        "test": AssetCriticality.NON_CRITICAL,
        "mock": AssetCriticality.NON_CRITICAL,
        "example": AssetCriticality.NON_CRITICAL,
        "demo": AssetCriticality.NON_CRITICAL,
    }

    # Weight configuration for final score
    WEIGHTS = {
        "cvss": 0.40,           # 40% from CVSS scores
        "business_impact": 0.30, # 30% from business impact
        "exploitability": 0.15,  # 15% from exploitability
        "asset_criticality": 0.15 # 15% from asset criticality
    }

    def __init__(self):
        """Initialize the risk calculator."""
        pass

    def calculate_risk(
        self,
        vulnerabilities: List[Dict[str, Any]],
        asset_context: Optional[Dict[str, Any]] = None
    ) -> RiskScore:
        """
        Calculate comprehensive risk score for a set of vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability dictionaries
            asset_context: Optional context about the assets (criticality, etc.)

        Returns:
            RiskScore with overall score, breakdown, and recommendations
        """
        if not vulnerabilities:
            return RiskScore(
                overall_score=0,
                risk_level="NONE",
                factors=RiskFactors(),
                recommendations=["No vulnerabilities detected."],
                breakdown={}
            )

        factors = RiskFactors()

        # 1. Calculate CVSS component (0-100)
        cvss_scores = self._extract_cvss_scores(vulnerabilities)
        factors.cvss_base = self._calculate_cvss_component(cvss_scores)
        factors.cvss_max = max(cvss_scores) if cvss_scores else 0
        factors.cvss_average = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0

        # 2. Calculate business impact component (0-100)
        factors.business_impact = self._calculate_business_impact(vulnerabilities)

        # 3. Calculate exploitability component (0-100)
        factors.exploitability = self._calculate_exploitability(vulnerabilities)

        # 4. Calculate asset criticality component (0-100)
        factors.asset_criticality = self._calculate_asset_criticality(
            vulnerabilities, asset_context
        )

        # 5. Calculate temporal factor (multiplier 0.5-1.5)
        factors.temporal_factor = self._calculate_temporal_factor(vulnerabilities)

        # 6. Calculate vulnerability density factor
        factors.vulnerability_count_factor = self._calculate_density_factor(
            len(vulnerabilities)
        )

        # Calculate weighted score
        base_score = (
            factors.cvss_base * self.WEIGHTS["cvss"] +
            factors.business_impact * self.WEIGHTS["business_impact"] +
            factors.exploitability * self.WEIGHTS["exploitability"] +
            factors.asset_criticality * self.WEIGHTS["asset_criticality"]
        )

        # Apply temporal and density adjustments
        adjusted_score = base_score * factors.temporal_factor
        adjusted_score = min(100, adjusted_score + factors.vulnerability_count_factor)

        # Round to 1 decimal
        overall_score = round(adjusted_score, 1)

        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            vulnerabilities, factors, risk_level
        )

        # Build breakdown
        breakdown = {
            "cvss_contribution": round(factors.cvss_base * self.WEIGHTS["cvss"], 1),
            "business_impact_contribution": round(
                factors.business_impact * self.WEIGHTS["business_impact"], 1
            ),
            "exploitability_contribution": round(
                factors.exploitability * self.WEIGHTS["exploitability"], 1
            ),
            "asset_criticality_contribution": round(
                factors.asset_criticality * self.WEIGHTS["asset_criticality"], 1
            ),
            "temporal_adjustment": round((factors.temporal_factor - 1) * 100, 1),
            "density_bonus": round(factors.vulnerability_count_factor, 1),
            "cvss_max": round(factors.cvss_max, 1),
            "cvss_average": round(factors.cvss_average, 1),
            "vulnerability_count": len(vulnerabilities)
        }

        return RiskScore(
            overall_score=overall_score,
            risk_level=risk_level,
            factors=factors,
            recommendations=recommendations,
            breakdown=breakdown
        )

    def _extract_cvss_scores(self, vulnerabilities: List[Dict[str, Any]]) -> List[float]:
        """Extract CVSS scores from vulnerabilities."""
        scores = []
        for vuln in vulnerabilities:
            # Try different CVSS score fields
            cvss = vuln.get("cvss_score") or vuln.get("cvss") or 0

            # If no CVSS, estimate from severity
            if not cvss:
                cvss = self._severity_to_cvss(vuln.get("severity", "medium"))

            if cvss and cvss > 0:
                scores.append(float(cvss))

        return scores if scores else [0.0]

    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity string to estimated CVSS score."""
        severity_map = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.5,
            "low": 3.0,
            "info": 1.0,
            "informational": 1.0
        }
        return severity_map.get(severity.lower(), 5.0)

    def _calculate_cvss_component(self, cvss_scores: List[float]) -> float:
        """
        Calculate CVSS component score.
        Uses weighted combination of max and average.
        """
        if not cvss_scores:
            return 0

        max_cvss = max(cvss_scores)
        avg_cvss = sum(cvss_scores) / len(cvss_scores)

        # Weight: 60% max score, 40% average (max is more important)
        combined = (max_cvss * 0.6) + (avg_cvss * 0.4)

        # Normalize to 0-100 (CVSS is 0-10)
        return min(100, combined * 10)

    def _calculate_business_impact(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate business impact score based on vulnerability types."""
        if not vulnerabilities:
            return 0

        impact_scores = []

        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "").lower().replace(" ", "_")
            vuln_name = vuln.get("name", "").lower()

            # Try to find matching impact level
            impact = None

            # Check exact type match
            if vuln_type in self.BUSINESS_IMPACT_MAP:
                impact = self.BUSINESS_IMPACT_MAP[vuln_type]
            else:
                # Check partial matches in type or name
                for key, level in self.BUSINESS_IMPACT_MAP.items():
                    if key in vuln_type or key in vuln_name:
                        impact = level
                        break

            # Default based on severity if no match
            if impact is None:
                severity = vuln.get("severity", "medium").lower()
                impact_from_severity = {
                    "critical": BusinessImpactLevel.CRITICAL,
                    "high": BusinessImpactLevel.HIGH,
                    "medium": BusinessImpactLevel.MEDIUM,
                    "low": BusinessImpactLevel.LOW,
                    "info": BusinessImpactLevel.MINIMAL
                }
                impact = impact_from_severity.get(severity, BusinessImpactLevel.MEDIUM)

            # Convert to score (0-25 per level)
            impact_scores.append(impact.value * 25)

        # Use combination of max and average impact
        max_impact = max(impact_scores)
        avg_impact = sum(impact_scores) / len(impact_scores)

        return min(100, (max_impact * 0.7) + (avg_impact * 0.3))

    def _calculate_exploitability(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate exploitability score."""
        if not vulnerabilities:
            return 0

        exploitable_count = 0
        public_exploit_count = 0
        easy_exploit_count = 0

        for vuln in vulnerabilities:
            # Check various exploitability indicators
            if vuln.get("exploit_available", False):
                exploitable_count += 1

            if vuln.get("public_exploit", False):
                public_exploit_count += 1

            # Check enrichment data for exploit info
            enrichment = vuln.get("enrichment", {})
            if enrichment:
                cves = enrichment.get("related_cves", [])
                for cve in cves:
                    if cve.get("exploit_available"):
                        public_exploit_count += 1
                        break

            # Check if it's an easy-to-exploit type
            vuln_type = vuln.get("type", "").lower()
            easy_types = ["sql_injection", "xss", "command_injection", "rce", "path_traversal"]
            if any(t in vuln_type for t in easy_types):
                easy_exploit_count += 1

        total = len(vulnerabilities)

        # Calculate score components
        exploitable_ratio = exploitable_count / total
        public_exploit_ratio = public_exploit_count / total
        easy_exploit_ratio = easy_exploit_count / total

        # Weighted combination
        score = (
            exploitable_ratio * 40 +      # 40% for exploitable
            public_exploit_ratio * 40 +   # 40% for public exploits
            easy_exploit_ratio * 20       # 20% for easy-to-exploit types
        )

        return min(100, score * 2.5)  # Scale up

    def _calculate_asset_criticality(
        self,
        vulnerabilities: List[Dict[str, Any]],
        asset_context: Optional[Dict[str, Any]] = None
    ) -> float:
        """Calculate asset criticality score."""
        if not vulnerabilities:
            return 0

        criticality_scores = []

        for vuln in vulnerabilities:
            # Check file path for component type
            file_path = vuln.get("file", "") or vuln.get("affected_file", "")
            vuln_type = vuln.get("type", "").lower()

            criticality = AssetCriticality.BUSINESS_OPERATIONAL  # Default

            # Check file path against criticality map
            file_lower = file_path.lower()
            for key, level in self.ASSET_CRITICALITY_MAP.items():
                if key in file_lower or key in vuln_type:
                    if level.value > criticality.value:
                        criticality = level

            # Check if it's a security-related vulnerability
            security_types = ["auth", "crypt", "session", "credential", "password", "token"]
            if any(t in vuln_type for t in security_types):
                criticality = AssetCriticality.MISSION_CRITICAL

            criticality_scores.append(criticality.value * 25)

        # Apply asset context if provided
        context_multiplier = 1.0
        if asset_context:
            if asset_context.get("is_production", False):
                context_multiplier = 1.3
            if asset_context.get("contains_pii", False):
                context_multiplier *= 1.2
            if asset_context.get("internet_facing", False):
                context_multiplier *= 1.1

        avg_criticality = sum(criticality_scores) / len(criticality_scores)
        return min(100, avg_criticality * context_multiplier)

    def _calculate_temporal_factor(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """
        Calculate temporal adjustment factor.
        Recent vulnerabilities and those with active exploits get higher weight.
        """
        if not vulnerabilities:
            return 1.0

        factor = 1.0

        # Check for recently discovered vulnerabilities
        recent_count = 0
        for vuln in vulnerabilities:
            discovered_at = vuln.get("discovered_at")
            if discovered_at:
                try:
                    if isinstance(discovered_at, str):
                        disc_date = datetime.fromisoformat(discovered_at.replace("Z", "+00:00"))
                    else:
                        disc_date = discovered_at

                    days_old = (datetime.now() - disc_date.replace(tzinfo=None)).days
                    if days_old <= 30:
                        recent_count += 1
                except:
                    pass

        # Increase factor for recent discoveries
        if recent_count > 0:
            factor += (recent_count / len(vulnerabilities)) * 0.2

        # Check for actively exploited vulnerabilities
        active_exploits = sum(
            1 for v in vulnerabilities
            if v.get("actively_exploited", False) or v.get("exploit_available", False)
        )
        if active_exploits > 0:
            factor += (active_exploits / len(vulnerabilities)) * 0.3

        return min(1.5, factor)

    def _calculate_density_factor(self, vuln_count: int) -> float:
        """
        Calculate vulnerability density bonus.
        More vulnerabilities indicate systemic issues.
        """
        if vuln_count <= 5:
            return 0
        elif vuln_count <= 10:
            return 5
        elif vuln_count <= 20:
            return 10
        elif vuln_count <= 50:
            return 15
        else:
            return 20

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "MINIMAL"

    def _generate_recommendations(
        self,
        vulnerabilities: List[Dict[str, Any]],
        factors: RiskFactors,
        risk_level: str
    ) -> List[str]:
        """Generate actionable recommendations based on risk factors."""
        recommendations = []

        # Critical risk recommendations
        if risk_level == "CRITICAL":
            recommendations.append(
                "IMMEDIATE ACTION REQUIRED: Critical risk level detected. "
                "Prioritize remediation of all critical and high severity vulnerabilities."
            )

        # High CVSS scores
        if factors.cvss_max >= 9.0:
            recommendations.append(
                f"Address CVSS 9.0+ vulnerabilities immediately - "
                f"maximum CVSS score detected: {factors.cvss_max:.1f}"
            )

        # High business impact
        if factors.business_impact >= 70:
            recommendations.append(
                "High business impact vulnerabilities detected. "
                "Review data exposure and access control issues as priority."
            )

        # Exploitability concerns
        if factors.exploitability >= 50:
            recommendations.append(
                "Multiple easily exploitable vulnerabilities found. "
                "Implement input validation and security controls urgently."
            )

        # Asset criticality
        if factors.asset_criticality >= 70:
            recommendations.append(
                "Critical assets affected. Consider implementing additional "
                "security layers and monitoring for these components."
            )

        # Specific vulnerability type recommendations
        vuln_types = [v.get("type", "").lower() for v in vulnerabilities]

        if any("sql" in t for t in vuln_types):
            recommendations.append(
                "SQL Injection detected: Use parameterized queries and "
                "prepared statements for all database operations."
            )

        if any("xss" in t or "cross_site_scripting" in t for t in vuln_types):
            recommendations.append(
                "XSS vulnerabilities found: Implement output encoding and "
                "Content Security Policy headers."
            )

        if any("injection" in t for t in vuln_types):
            recommendations.append(
                "Injection vulnerabilities present: Review all user input handling "
                "and implement strict input validation."
            )

        if any("credential" in t or "password" in t or "hardcoded" in t for t in vuln_types):
            recommendations.append(
                "Credential exposure detected: Remove hardcoded secrets and "
                "implement secure credential management."
            )

        # General recommendations based on count
        if len(vulnerabilities) > 20:
            recommendations.append(
                "High vulnerability count indicates systemic security issues. "
                "Consider a comprehensive security review and developer training."
            )

        return recommendations[:5]  # Limit to top 5 recommendations


# Singleton instance
_risk_calculator: Optional[RiskCalculator] = None


def get_risk_calculator() -> RiskCalculator:
    """Get or create the global RiskCalculator instance."""
    global _risk_calculator
    if _risk_calculator is None:
        _risk_calculator = RiskCalculator()
    return _risk_calculator
