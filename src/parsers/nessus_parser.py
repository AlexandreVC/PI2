"""Nessus scan result parser."""

import xml.etree.ElementTree as ET
import json
import uuid
from typing import List, Union, Optional
from pathlib import Path
from datetime import datetime

from .base_parser import BaseParser
from ..models import (
    ScanResult, Host, Port, Service, PortState,
    Vulnerability, VulnerabilitySeverity
)


class NessusParser(BaseParser):
    """Parser for Nessus .nessus (XML) and JSON export files."""

    # Nessus severity to CVSS mapping
    SEVERITY_MAP = {
        0: ("info", 0.0),
        1: ("low", 2.0),
        2: ("medium", 5.0),
        3: ("high", 7.5),
        4: ("critical", 9.5),
        5: ("critical", 10.0)  # Some exports use 5 for critical
    }

    def parse_file(self, file_path: Union[str, Path]) -> ScanResult:
        """Parse Nessus output file (.nessus XML or JSON)."""
        file_path = Path(file_path)

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if file_path.suffix.lower() == '.json':
            return self._parse_json(content)
        else:
            return self._parse_nessus_xml(content)

    def parse_string(self, content: str) -> ScanResult:
        """Parse Nessus output from string."""
        content = content.strip()
        if content.startswith('{') or content.startswith('['):
            return self._parse_json(content)
        else:
            return self._parse_nessus_xml(content)

    def _parse_nessus_xml(self, content: str) -> ScanResult:
        """Parse Nessus XML (.nessus) format."""
        root = ET.fromstring(content)

        scan_id = str(uuid.uuid4())[:8]

        # Get policy/scan info
        policy = root.find('.//Policy')
        scan_name = ""
        if policy is not None:
            name_elem = policy.find('.//policyName')
            scan_name = name_elem.text if name_elem is not None else ""

        # Parse report hosts
        hosts = []
        vulnerabilities_by_host = {}

        for report_host in root.findall('.//ReportHost'):
            host, vulns = self._parse_report_host(report_host)
            if host:
                hosts.append(host)
                vulnerabilities_by_host[host.ip] = vulns

        # Store vulnerabilities for later extraction
        self._last_vulnerabilities = vulnerabilities_by_host

        return ScanResult(
            scan_id=scan_id,
            scanner="nessus",
            scan_type=scan_name or "vulnerability",
            hosts=hosts,
            hosts_up=len(hosts),
            raw_output=content
        )

    def _parse_report_host(self, report_host: ET.Element) -> tuple:
        """Parse a single ReportHost element."""
        host_name = report_host.get('name', '')

        # Get host properties
        ip = host_name
        hostname = ""
        os_match = ""
        mac_address = ""

        for tag in report_host.findall('.//tag'):
            tag_name = tag.get('name', '')
            tag_value = tag.text or ''

            if tag_name == 'host-ip':
                ip = tag_value
            elif tag_name == 'hostname':
                hostname = tag_value
            elif tag_name == 'operating-system':
                os_match = tag_value
            elif tag_name == 'mac-address':
                mac_address = tag_value

        # Parse report items (findings)
        ports_dict = {}
        vulnerabilities = []

        for item in report_host.findall('.//ReportItem'):
            port_num = int(item.get('port', 0))
            protocol = item.get('protocol', 'tcp')
            service = item.get('svc_name', '')
            plugin_id = item.get('pluginID', item.get('pluginId', ''))
            # Try attribute first, then child element
            plugin_name = item.get('pluginName', '')
            if not plugin_name:
                plugin_name_elem = item.find('plugin_name')
                if plugin_name_elem is not None and plugin_name_elem.text:
                    plugin_name = plugin_name_elem.text
            severity = int(item.get('severity', 0))

            # Create/update port entry
            port_key = (port_num, protocol)
            if port_key not in ports_dict and port_num > 0:
                ports_dict[port_key] = Port(
                    number=port_num,
                    protocol=protocol,
                    state=PortState.OPEN,
                    service=Service(name=service)
                )

            # Extract vulnerability info
            if severity > 0 or plugin_name:  # Skip pure info unless significant
                vuln = self._parse_report_item(item, ip, port_num, service)
                if vuln:
                    vulnerabilities.append(vuln)

        host = Host(
            ip=ip,
            hostname=hostname,
            mac_address=mac_address,
            os_match=os_match,
            status='up',
            ports=list(ports_dict.values())
        )

        return host, vulnerabilities

    def _parse_report_item(
            self, item: ET.Element, host_ip: str, port: int, service: str
    ) -> Optional[Vulnerability]:
        """Parse a single ReportItem into a Vulnerability."""
        plugin_id = item.get('pluginID', item.get('pluginId', ''))
        # Try attribute first, then child element
        plugin_name = item.get('pluginName', '')
        if not plugin_name:
            plugin_name_elem = item.find('plugin_name')
            if plugin_name_elem is not None and plugin_name_elem.text:
                plugin_name = plugin_name_elem.text
        severity = int(item.get('severity', 0))

        # Get severity info (treat severity >= 4 as critical if not in map)
        if severity >= 4 and severity not in self.SEVERITY_MAP:
            _, default_cvss = ("critical", 9.5)
        else:
            _, default_cvss = self.SEVERITY_MAP.get(severity, ("info", 0.0))

        # Extract additional fields
        description = ""
        solution = ""
        cvss_score = default_cvss
        cvss_vector = ""
        cve_ids = []
        cwe_id = None
        references = []
        exploit_available = False

        # Parse child elements
        desc_elem = item.find('description')
        if desc_elem is not None and desc_elem.text:
            description = desc_elem.text

        solution_elem = item.find('solution')
        if solution_elem is not None and solution_elem.text:
            solution = solution_elem.text

        # CVSS v3
        cvss3_elem = item.find('cvss3_base_score')
        if cvss3_elem is not None and cvss3_elem.text:
            try:
                cvss_score = float(cvss3_elem.text)
            except ValueError:
                pass

        cvss3_vector_elem = item.find('cvss3_vector')
        if cvss3_vector_elem is not None and cvss3_vector_elem.text:
            cvss_vector = cvss3_vector_elem.text

        # Fallback to CVSS v2
        if cvss_score == default_cvss:
            cvss2_elem = item.find('cvss_base_score')
            if cvss2_elem is not None and cvss2_elem.text:
                try:
                    cvss_score = float(cvss2_elem.text)
                except ValueError:
                    pass

        # CVE references
        for cve_elem in item.findall('cve'):
            if cve_elem.text:
                cve_ids.append(cve_elem.text)

        # CWE
        cwe_elem = item.find('cwe')
        if cwe_elem is not None and cwe_elem.text:
            cwe_id = f"CWE-{cwe_elem.text}"

        # References
        for ref_elem in item.findall('see_also'):
            if ref_elem.text:
                references.extend(ref_elem.text.split('\n'))

        # Exploit info
        exploit_elem = item.find('exploit_available')
        if exploit_elem is not None and exploit_elem.text:
            exploit_available = exploit_elem.text.lower() == 'true'

        exploitability_elem = item.find('exploitability_ease')
        exploitability = ""
        if exploitability_elem is not None and exploitability_elem.text:
            exploitability = exploitability_elem.text

        # Product/version info
        plugin_output = ""
        output_elem = item.find('plugin_output')
        if output_elem is not None and output_elem.text:
            plugin_output = output_elem.text

        return Vulnerability(
            id=f"NESSUS-{plugin_id}",
            cve_id=cve_ids[0] if cve_ids else None,
            title=plugin_name,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=VulnerabilitySeverity.from_cvss(cvss_score),
            affected_host=host_ip,
            affected_port=port,
            affected_service=service,
            cwe_id=cwe_id,
            exploitability=exploitability,
            exploit_available=exploit_available,
            remediation=solution,
            source="nessus",
            references=references
        )

    def _parse_json(self, content: str) -> ScanResult:
        """Parse Nessus JSON export format."""
        data = json.loads(content)

        scan_id = str(uuid.uuid4())[:8]
        hosts = []
        vulnerabilities_by_host = {}

        # Handle different JSON structures
        if isinstance(data, list):
            # List of vulnerabilities
            for vuln_data in data:
                host_ip = vuln_data.get('host', vuln_data.get('ip', ''))
                if host_ip not in vulnerabilities_by_host:
                    vulnerabilities_by_host[host_ip] = []
                    hosts.append(Host(ip=host_ip, status='up'))

                vuln = self._parse_json_vulnerability(vuln_data, host_ip)
                if vuln:
                    vulnerabilities_by_host[host_ip].append(vuln)

        elif 'vulnerabilities' in data:
            # Structured export
            for vuln_data in data['vulnerabilities']:
                host_ip = vuln_data.get('host', '')
                if host_ip not in vulnerabilities_by_host:
                    vulnerabilities_by_host[host_ip] = []
                    hosts.append(Host(ip=host_ip, status='up'))

                vuln = self._parse_json_vulnerability(vuln_data, host_ip)
                if vuln:
                    vulnerabilities_by_host[host_ip].append(vuln)

        self._last_vulnerabilities = vulnerabilities_by_host

        return ScanResult(
            scan_id=scan_id,
            scanner="nessus",
            scan_type="vulnerability",
            hosts=hosts,
            hosts_up=len(hosts),
            raw_output=content
        )

    def _parse_json_vulnerability(
            self, data: dict, host_ip: str
    ) -> Optional[Vulnerability]:
        """Parse a vulnerability from JSON format."""
        return Vulnerability(
            id=f"NESSUS-{data.get('plugin_id', '')}",
            cve_id=data.get('cve'),
            title=data.get('plugin_name', data.get('name', '')),
            description=data.get('description', ''),
            cvss_score=float(data.get('cvss_score', data.get('cvss', 0))),
            severity=VulnerabilitySeverity.from_cvss(
                float(data.get('cvss_score', data.get('cvss', 0)))
            ),
            affected_host=host_ip,
            affected_port=int(data.get('port', 0)),
            affected_service=data.get('service', ''),
            remediation=data.get('solution', ''),
            source="nessus",
            exploit_available=data.get('exploit_available', False)
        )

    def extract_vulnerabilities(self, scan_result: ScanResult) -> List[Vulnerability]:
        """Extract all vulnerabilities from the last parsed scan."""
        all_vulns = []

        if hasattr(self, '_last_vulnerabilities'):
            for host_vulns in self._last_vulnerabilities.values():
                all_vulns.extend(host_vulns)

            # Assign unique IDs
            for i, vuln in enumerate(all_vulns, 1):
                if vuln.id.startswith("NESSUS-"):
                    vuln.id = f"NESSUS-{scan_result.scan_id}-{i:04d}"

        return all_vulns

    def get_supported_formats(self) -> List[str]:
        """Return supported file formats."""
        return ["nessus", "xml", "json"]
