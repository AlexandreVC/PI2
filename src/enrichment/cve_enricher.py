"""CVE/NVD enrichment module."""

import json
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
import time

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from ..models import Vulnerability, VulnerabilitySeverity

logger = logging.getLogger(__name__)


class CVEEnricher:
    """
    Enriches vulnerabilities with data from CVE/NVD databases.

    Uses the NVD API 2.0 for fetching vulnerability details.
    """

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT_DELAY = 6  # NVD requires 6 seconds between requests without API key

    def __init__(self, api_key: Optional[str] = None, cache_enabled: bool = True):
        """
        Initialize the CVE enricher.

        Args:
            api_key: NVD API key (optional, increases rate limits)
            cache_enabled: Whether to cache API responses
        """
        self.api_key = api_key
        self.cache_enabled = cache_enabled
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._last_request_time = 0

        if not HAS_REQUESTS:
            logger.warning("requests library not available, API enrichment disabled")

    def enrich_vulnerability(self, vulnerability: Vulnerability) -> Vulnerability:
        """
        Enrich a single vulnerability with NVD data.

        Args:
            vulnerability: Vulnerability to enrich

        Returns:
            Enriched vulnerability
        """
        if not vulnerability.cve_id:
            return vulnerability

        cve_data = self._fetch_cve_data(vulnerability.cve_id)
        if cve_data:
            vulnerability = self._apply_enrichment(vulnerability, cve_data)

        return vulnerability

    def enrich_vulnerabilities(
            self, vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Enrich multiple vulnerabilities.

        Args:
            vulnerabilities: List of vulnerabilities to enrich

        Returns:
            List of enriched vulnerabilities
        """
        enriched = []
        for vuln in vulnerabilities:
            enriched.append(self.enrich_vulnerability(vuln))
        return enriched

    def _fetch_cve_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch CVE data from NVD API."""
        if not HAS_REQUESTS:
            return self._get_fallback_data(cve_id)

        # Check cache first
        if self.cache_enabled and cve_id in self._cache:
            logger.debug(f"Cache hit for {cve_id}")
            return self._cache[cve_id]

        # Rate limiting
        self._respect_rate_limit()

        try:
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key

            response = requests.get(
                f"{self.NVD_API_BASE}?cveId={cve_id}",
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('vulnerabilities'):
                    cve_data = data['vulnerabilities'][0]['cve']

                    if self.cache_enabled:
                        self._cache[cve_id] = cve_data

                    return cve_data

            elif response.status_code == 403:
                logger.warning("NVD API rate limit exceeded")
            else:
                logger.warning(f"NVD API returned {response.status_code} for {cve_id}")

        except requests.RequestException as e:
            logger.error(f"Failed to fetch CVE data for {cve_id}: {e}")

        # Return fallback data if API fails
        return self._get_fallback_data(cve_id)

    def _respect_rate_limit(self):
        """Ensure we don't exceed NVD rate limits."""
        if self.api_key:
            delay = 0.6  # With API key: 10 requests per minute
        else:
            delay = self.RATE_LIMIT_DELAY

        elapsed = time.time() - self._last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)

        self._last_request_time = time.time()

    def _apply_enrichment(
            self, vulnerability: Vulnerability, cve_data: Dict[str, Any]
    ) -> Vulnerability:
        """Apply NVD data to vulnerability."""

        # Update description if empty
        if not vulnerability.description:
            descriptions = cve_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    vulnerability.description = desc.get('value', '')
                    break

        # Extract CVSS data
        metrics = cve_data.get('metrics', {})

        # Try CVSS 3.1 first, then 3.0, then 2.0
        cvss_data = None
        if 'cvssMetricV31' in metrics:
            cvss_data = metrics['cvssMetricV31'][0]
        elif 'cvssMetricV30' in metrics:
            cvss_data = metrics['cvssMetricV30'][0]
        elif 'cvssMetricV2' in metrics:
            cvss_data = metrics['cvssMetricV2'][0]

        if cvss_data:
            cvss_info = cvss_data.get('cvssData', {})
            if 'baseScore' in cvss_info:
                vulnerability.cvss_score = cvss_info['baseScore']
                vulnerability.severity = VulnerabilitySeverity.from_cvss(
                    vulnerability.cvss_score
                )
            if 'vectorString' in cvss_info:
                vulnerability.cvss_vector = cvss_info['vectorString']

            # Exploitability
            if 'exploitabilityScore' in cvss_data:
                score = cvss_data['exploitabilityScore']
                if score >= 3.0:
                    vulnerability.exploitability = "High"
                elif score >= 1.5:
                    vulnerability.exploitability = "Medium"
                else:
                    vulnerability.exploitability = "Low"

        # Extract CWE
        weaknesses = cve_data.get('weaknesses', [])
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    cwe_value = desc.get('value', '')
                    if cwe_value.startswith('CWE-'):
                        vulnerability.cwe_id = cwe_value
                        break

        # Extract references
        refs = cve_data.get('references', [])
        for ref in refs:
            url = ref.get('url', '')
            if url and url not in vulnerability.references:
                vulnerability.references.append(url)

            # Check for exploit references
            tags = ref.get('tags', [])
            if 'Exploit' in tags:
                vulnerability.exploit_available = True

        return vulnerability

    def _get_fallback_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get fallback data for common CVEs when API is unavailable.

        This provides basic information for well-known vulnerabilities.
        """
        fallback_db = {
            "CVE-2021-44228": {
                "descriptions": [{"lang": "en", "value": "Apache Log4j2 <=2.14.1 JNDI features allow remote code execution via ldap or rmi lookups (Log4Shell)"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 10.0, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
                        "exploitabilityScore": 3.9
                    }]
                },
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-917"}]}]
            },
            "CVE-2017-0144": {
                "descriptions": [{"lang": "en", "value": "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code (EternalBlue/MS17-010)"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                        "exploitabilityScore": 3.9
                    }]
                }
            },
            "CVE-2014-0160": {
                "descriptions": [{"lang": "en", "value": "The TLS heartbeat extension in OpenSSL allows remote attackers to obtain sensitive information (Heartbleed)"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
                        "exploitabilityScore": 3.9
                    }]
                },
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-125"}]}]
            },
            "CVE-2011-2523": {
                "descriptions": [{"lang": "en", "value": "vsftpd 2.3.4 contains a backdoor that allows remote attackers to execute arbitrary commands"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 10.0, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
                        "exploitabilityScore": 3.9
                    }]
                }
            },
            "CVE-2007-2447": {
                "descriptions": [{"lang": "en", "value": "Samba 3.0.0-3.0.25rc3 allows remote execution via shell metacharacters in username map script"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 9.3, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                        "exploitabilityScore": 3.9
                    }]
                }
            }
        }

        return fallback_db.get(cve_id)

    def get_cvss_severity_label(self, score: float) -> str:
        """Get human-readable severity label from CVSS score."""
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0:
            return "Low"
        return "Informational"

    def clear_cache(self):
        """Clear the CVE data cache."""
        self._cache.clear()
        logger.info("CVE cache cleared")
