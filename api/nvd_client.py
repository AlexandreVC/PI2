"""
NVD (National Vulnerability Database) API Client.

Fetches real CVE data from the NIST NVD API 2.0.
https://nvd.nist.gov/developers/vulnerabilities
"""

import time
import logging
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Generator
from dataclasses import dataclass, field

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)


@dataclass
class NVDConfig:
    """NVD API configuration."""
    api_key: Optional[str] = None  # Get from https://nvd.nist.gov/developers/request-an-api-key
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page: int = 200  # Max 2000
    rate_limit_delay: float = 6.0  # Seconds between requests (without API key)
    rate_limit_delay_with_key: float = 0.6  # With API key
    request_timeout: int = 30
    max_retries: int = 3
    retry_delay: int = 10


class NVDClient:
    """
    Client for the NIST National Vulnerability Database API 2.0.

    Fetches real CVE data with proper rate limiting and pagination.
    """

    def __init__(self, config: Optional[NVDConfig] = None):
        self.config = config or NVDConfig()
        self._last_request_time = 0
        self._cache_dir = Path("data/cache/nvd")
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        if not HAS_REQUESTS:
            logger.error("requests library not installed. NVD API unavailable.")

    def _get_rate_limit_delay(self) -> float:
        """Get appropriate delay based on API key presence."""
        if self.config.api_key:
            return self.config.rate_limit_delay_with_key
        return self.config.rate_limit_delay

    def _respect_rate_limit(self):
        """Ensure we don't exceed NVD rate limits."""
        delay = self._get_rate_limit_delay()
        elapsed = time.time() - self._last_request_time
        if elapsed < delay:
            sleep_time = delay - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        self._last_request_time = time.time()

    def _make_request(self, params: Dict[str, Any]) -> Optional[Dict]:
        """Make a request to NVD API with retries."""
        if not HAS_REQUESTS:
            return None

        headers = {}
        if self.config.api_key:
            headers['apiKey'] = self.config.api_key

        for attempt in range(self.config.max_retries):
            self._respect_rate_limit()

            try:
                response = requests.get(
                    self.config.base_url,
                    params=params,
                    headers=headers,
                    timeout=self.config.request_timeout
                )

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 403:
                    logger.warning("NVD API rate limit exceeded. Waiting...")
                    time.sleep(30)
                elif response.status_code == 404:
                    logger.debug(f"No results for params: {params}")
                    return None
                else:
                    logger.warning(f"NVD API error {response.status_code}: {response.text[:200]}")

            except requests.Timeout:
                logger.warning(f"Request timeout (attempt {attempt + 1}/{self.config.max_retries})")
            except requests.RequestException as e:
                logger.error(f"Request failed: {e}")

            if attempt < self.config.max_retries - 1:
                time.sleep(self.config.retry_delay)

        return None

    def fetch_cves_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime,
        severity: Optional[str] = None
    ) -> Generator[Dict, None, None]:
        """
        Fetch CVEs modified within a date range.

        Args:
            start_date: Start of date range
            end_date: End of date range
            severity: Optional severity filter (LOW, MEDIUM, HIGH, CRITICAL)

        Yields:
            CVE records
        """
        params = {
            "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": self.config.results_per_page,
            "startIndex": 0
        }

        if severity:
            params["cvssV3Severity"] = severity.upper()

        total_results = None
        fetched = 0

        while True:
            logger.info(f"Fetching CVEs: startIndex={params['startIndex']}, total={total_results or 'unknown'}")

            data = self._make_request(params)
            if not data:
                break

            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info(f"Total CVEs to fetch: {total_results}")

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for vuln in vulnerabilities:
                yield vuln.get("cve", {})
                fetched += 1

            # Check if we've fetched all results
            if fetched >= total_results:
                break

            params["startIndex"] += self.config.results_per_page

        logger.info(f"Fetched {fetched} CVEs total")

    def fetch_recent_critical_cves(self, days: int = 30) -> List[Dict]:
        """
        Fetch recent critical and high severity CVEs.

        Args:
            days: Number of days to look back

        Returns:
            List of CVE records
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        cves = []

        # Fetch CRITICAL CVEs
        logger.info(f"Fetching CRITICAL CVEs from last {days} days...")
        for cve in self.fetch_cves_by_date_range(start_date, end_date, "CRITICAL"):
            cves.append(cve)

        # Fetch HIGH CVEs
        logger.info(f"Fetching HIGH CVEs from last {days} days...")
        for cve in self.fetch_cves_by_date_range(start_date, end_date, "HIGH"):
            cves.append(cve)

        return cves

    def fetch_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            CVE record or None
        """
        params = {"cveId": cve_id}
        data = self._make_request(params)

        if data and data.get("vulnerabilities"):
            return data["vulnerabilities"][0].get("cve", {})
        return None

    def fetch_cves_by_keyword(self, keyword: str, exact_match: bool = False) -> List[Dict]:
        """
        Search CVEs by keyword.

        Args:
            keyword: Search keyword
            exact_match: Whether to require exact match

        Returns:
            List of CVE records
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": self.config.results_per_page,
            "startIndex": 0
        }

        if exact_match:
            params["keywordExactMatch"] = ""

        cves = []
        data = self._make_request(params)

        if data:
            for vuln in data.get("vulnerabilities", []):
                cves.append(vuln.get("cve", {}))

        return cves

    def parse_cve_to_vulnerability(self, cve_data: Dict) -> Dict[str, Any]:
        """
        Parse NVD CVE data to vulnerability format.

        Args:
            cve_data: Raw CVE data from NVD API

        Returns:
            Vulnerability dict
        """
        cve_id = cve_data.get("id", "")

        # Get description
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Get CVSS data
        cvss_score = 0.0
        cvss_vector = ""
        severity = "info"
        exploitability = ""

        metrics = cve_data.get("metrics", {})

        # Try CVSS 3.1, then 3.0, then 2.0
        cvss_data = None
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]

        if cvss_data:
            cvss_info = cvss_data.get("cvssData", {})
            cvss_score = cvss_info.get("baseScore", 0.0)
            cvss_vector = cvss_info.get("vectorString", "")

            # Determine severity
            if cvss_score >= 9.0:
                severity = "critical"
            elif cvss_score >= 7.0:
                severity = "high"
            elif cvss_score >= 4.0:
                severity = "medium"
            elif cvss_score > 0:
                severity = "low"

            # Exploitability
            exploit_score = cvss_data.get("exploitabilityScore", 0)
            if exploit_score >= 3.0:
                exploitability = "High"
            elif exploit_score >= 1.5:
                exploitability = "Medium"
            else:
                exploitability = "Low"

        # Get CWE
        cwe_id = None
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    value = desc.get("value", "")
                    if value.startswith("CWE-"):
                        cwe_id = value
                        break

        # Get references and check for exploits
        references = []
        exploit_available = False
        patch_available = False

        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)

            tags = ref.get("tags", [])
            if "Exploit" in tags:
                exploit_available = True
            if "Patch" in tags or "Vendor Advisory" in tags:
                patch_available = True

        # Get affected products (CPE)
        affected_products = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        cpe = cpe_match.get("criteria", "")
                        # Parse CPE: cpe:2.3:a:vendor:product:version:...
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            affected_products.append({
                                "vendor": parts[3] if len(parts) > 3 else "",
                                "product": parts[4] if len(parts) > 4 else "",
                                "version": parts[5] if len(parts) > 5 else "*"
                            })

        # Build title
        title = f"{cve_id}"
        if affected_products:
            product = affected_products[0]
            title = f"{cve_id} - {product.get('vendor', '').title()} {product.get('product', '').title()}"

        # Published and modified dates
        published = cve_data.get("published", "")
        modified = cve_data.get("lastModified", "")

        return {
            "id": cve_id,
            "cve_id": cve_id,
            "title": title,
            "description": description[:500] + "..." if len(description) > 500 else description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "cwe_id": cwe_id,
            "exploitability": exploitability,
            "exploit_available": exploit_available,
            "patch_available": patch_available,
            "references": references[:10],  # Limit references
            "affected_products": affected_products[:5],  # Limit products
            "affected_host": "",  # To be filled by scan
            "affected_port": 0,
            "affected_service": "",
            "affected_product": affected_products[0].get("product", "") if affected_products else "",
            "affected_version": affected_products[0].get("version", "") if affected_products else "",
            "source": "nvd",
            "published_at": published,
            "last_modified": modified,
            "discovered_at": datetime.now().isoformat(),
            "mitre_tactics": [],
            "mitre_techniques": [],
            "remediation": f"Check vendor advisories for {cve_id}. Apply available patches.",
            "remediation_priority": 1 if severity == "critical" else 2 if severity == "high" else 5
        }

    def save_cache(self, cves: List[Dict], filename: str = "nvd_cves.json"):
        """Save CVEs to cache file."""
        cache_file = self._cache_dir / filename
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump({
                "fetched_at": datetime.now().isoformat(),
                "count": len(cves),
                "cves": cves
            }, f, indent=2, default=str)
        logger.info(f"Cached {len(cves)} CVEs to {cache_file}")

    def load_cache(self, filename: str = "nvd_cves.json") -> Optional[List[Dict]]:
        """Load CVEs from cache file."""
        cache_file = self._cache_dir / filename
        if cache_file.exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    logger.info(f"Loaded {data.get('count', 0)} CVEs from cache")
                    return data.get("cves", [])
            except Exception as e:
                logger.error(f"Failed to load cache: {e}")
        return None


def fetch_and_process_cves(
    days: int = 30,
    include_medium: bool = False,
    api_key: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Fetch and process CVEs from NVD.

    Args:
        days: Number of days to look back
        include_medium: Include MEDIUM severity CVEs
        api_key: NVD API key (optional, increases rate limits)

    Returns:
        List of processed vulnerability dicts
    """
    config = NVDConfig(api_key=api_key)
    client = NVDClient(config)

    vulnerabilities = []
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)

    # Fetch CRITICAL
    logger.info("Fetching CRITICAL CVEs...")
    for cve in client.fetch_cves_by_date_range(start_date, end_date, "CRITICAL"):
        vuln = client.parse_cve_to_vulnerability(cve)
        vulnerabilities.append(vuln)

    # Fetch HIGH
    logger.info("Fetching HIGH CVEs...")
    for cve in client.fetch_cves_by_date_range(start_date, end_date, "HIGH"):
        vuln = client.parse_cve_to_vulnerability(cve)
        vulnerabilities.append(vuln)

    # Optionally fetch MEDIUM
    if include_medium:
        logger.info("Fetching MEDIUM CVEs...")
        for cve in client.fetch_cves_by_date_range(start_date, end_date, "MEDIUM"):
            vuln = client.parse_cve_to_vulnerability(cve)
            vulnerabilities.append(vuln)

    # Save to cache
    client.save_cache(vulnerabilities)

    logger.info(f"Total vulnerabilities fetched: {len(vulnerabilities)}")
    return vulnerabilities
