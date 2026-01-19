"""Nmap scan result parser."""

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


class NmapParser(BaseParser):
    """Parser for Nmap XML and JSON output."""

    # Known vulnerable services/versions mapping
    KNOWN_VULNERABILITIES = {
        "vsftpd": {
            "2.3.4": {
                "cve": "CVE-2011-2523",
                "title": "vsftpd 2.3.4 Backdoor Command Execution",
                "cvss": 10.0,
                "description": "vsftpd 2.3.4 contains a backdoor that opens a shell on port 6200"
            }
        },
        "openssh": {
            "4.7p1": {
                "cve": "CVE-2008-0166",
                "title": "OpenSSH Weak Key Generation (Debian)",
                "cvss": 7.8,
                "description": "Predictable random number generator in OpenSSH keys"
            }
        },
        "apache": {
            "2.2.8": {
                "cve": "CVE-2011-3192",
                "title": "Apache HTTP Server Range Header DoS",
                "cvss": 7.8,
                "description": "Apache Range header denial of service vulnerability"
            }
        },
        "proftpd": {
            "1.3.1": {
                "cve": "CVE-2010-4221",
                "title": "ProFTPD 1.3.1 Remote Code Execution",
                "cvss": 10.0,
                "description": "Buffer overflow in ProFTPD allows remote code execution"
            }
        },
        "mysql": {
            "5.0.51a": {
                "cve": "CVE-2012-2122",
                "title": "MySQL Authentication Bypass",
                "cvss": 5.1,
                "description": "MySQL authentication bypass via memcmp timing attack"
            }
        },
        "samba": {
            "3.0.20": {
                "cve": "CVE-2007-2447",
                "title": "Samba username map script Command Execution",
                "cvss": 9.3,
                "description": "Remote command execution via shell metacharacters"
            }
        }
    }

    # Insecure protocols
    INSECURE_PROTOCOLS = {
        "telnet": {
            "title": "Telnet Service Detected",
            "cvss": 5.0,
            "description": "Telnet transmits data in cleartext including credentials",
            "remediation": "Disable Telnet and use SSH for remote administration"
        },
        "ftp": {
            "title": "FTP Service Detected (Potential Cleartext)",
            "cvss": 4.0,
            "description": "FTP may transmit credentials in cleartext",
            "remediation": "Use SFTP or FTPS instead of plain FTP"
        },
        "rlogin": {
            "title": "rlogin Service Detected",
            "cvss": 7.5,
            "description": "rlogin is an insecure remote login protocol",
            "remediation": "Disable rlogin and use SSH"
        },
        "rsh": {
            "title": "rsh Service Detected",
            "cvss": 7.5,
            "description": "Remote shell service is insecure",
            "remediation": "Disable rsh and use SSH"
        }
    }

    def parse_file(self, file_path: Union[str, Path]) -> ScanResult:
        """Parse Nmap output file (XML or JSON)."""
        file_path = Path(file_path)

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if file_path.suffix.lower() == '.json':
            return self._parse_json(content)
        else:
            return self._parse_xml(content)

    def parse_string(self, content: str) -> ScanResult:
        """Parse Nmap output from string."""
        content = content.strip()
        if content.startswith('{'):
            return self._parse_json(content)
        else:
            return self._parse_xml(content)

    def _parse_xml(self, content: str) -> ScanResult:
        """Parse Nmap XML output."""
        root = ET.fromstring(content)

        # Extract scan metadata
        scan_id = str(uuid.uuid4())[:8]
        start_time = datetime.fromtimestamp(
            int(root.get('start', 0))
        ) if root.get('start') else datetime.now()

        # Get scan arguments
        command_line = root.get('args', '')

        # Parse hosts
        hosts = []
        for host_elem in root.findall('.//host'):
            host = self._parse_host_xml(host_elem)
            if host:
                hosts.append(host)

        # Get statistics
        runstats = root.find('.//runstats/hosts')
        hosts_up = int(runstats.get('up', 0)) if runstats is not None else len(hosts)
        hosts_down = int(runstats.get('down', 0)) if runstats is not None else 0

        # Get end time
        finished = root.find('.//runstats/finished')
        end_time = datetime.fromtimestamp(
            int(finished.get('time', 0))
        ) if finished is not None and finished.get('time') else None

        return ScanResult(
            scan_id=scan_id,
            scanner="nmap",
            scan_type=self._detect_scan_type(command_line),
            start_time=start_time,
            end_time=end_time,
            command_line=command_line,
            hosts=hosts,
            hosts_up=hosts_up,
            hosts_down=hosts_down,
            raw_output=content
        )

    def _parse_host_xml(self, host_elem: ET.Element) -> Optional[Host]:
        """Parse a single host from XML."""
        # Get status
        status_elem = host_elem.find('status')
        if status_elem is None or status_elem.get('state') != 'up':
            return None

        # Get IP address
        addr_elem = host_elem.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host_elem.find("address[@addrtype='ipv6']")
        if addr_elem is None:
            return None

        ip = addr_elem.get('addr', '')

        # Get MAC address
        mac_elem = host_elem.find("address[@addrtype='mac']")
        mac = mac_elem.get('addr', '') if mac_elem is not None else ''

        # Get hostname
        hostname_elem = host_elem.find('.//hostname')
        hostname = hostname_elem.get('name', '') if hostname_elem is not None else ''

        # Get OS match
        os_match = ""
        os_accuracy = 0
        os_elem = host_elem.find('.//osmatch')
        if os_elem is not None:
            os_match = os_elem.get('name', '')
            os_accuracy = int(os_elem.get('accuracy', 0))

        # Parse ports
        ports = []
        for port_elem in host_elem.findall('.//port'):
            port = self._parse_port_xml(port_elem)
            if port:
                ports.append(port)

        return Host(
            ip=ip,
            hostname=hostname,
            mac_address=mac,
            os_match=os_match,
            os_accuracy=os_accuracy,
            status='up',
            ports=ports
        )

    def _parse_port_xml(self, port_elem: ET.Element) -> Optional[Port]:
        """Parse a single port from XML."""
        port_id = int(port_elem.get('portid', 0))
        protocol = port_elem.get('protocol', 'tcp')

        # Get state
        state_elem = port_elem.find('state')
        state_str = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'
        try:
            state = PortState(state_str)
        except ValueError:
            state = PortState.UNKNOWN

        # Get service info
        service_elem = port_elem.find('service')
        service = None
        if service_elem is not None:
            cpe_list = [cpe.text for cpe in service_elem.findall('cpe') if cpe.text]
            service = Service(
                name=service_elem.get('name', ''),
                product=service_elem.get('product', ''),
                version=service_elem.get('version', ''),
                extra_info=service_elem.get('extrainfo', ''),
                os_type=service_elem.get('ostype', ''),
                cpe=cpe_list
            )

        # Parse NSE scripts
        scripts = {}
        for script_elem in port_elem.findall('.//script'):
            script_id = script_elem.get('id', '')
            script_output = script_elem.get('output', '')
            if script_id:
                scripts[script_id] = script_output

        return Port(
            number=port_id,
            protocol=protocol,
            state=state,
            service=service,
            scripts=scripts
        )

    def _parse_json(self, content: str) -> ScanResult:
        """Parse Nmap JSON output (from nmap-parse-output or similar)."""
        data = json.loads(content)

        scan_id = str(uuid.uuid4())[:8]
        hosts = []

        # Handle different JSON formats
        if 'nmaprun' in data:
            # Standard nmap XML converted to JSON
            return self._parse_xml(content)  # Fallback to XML parsing

        # Custom JSON format
        for host_data in data.get('hosts', []):
            host = self._parse_host_json(host_data)
            if host:
                hosts.append(host)

        return ScanResult(
            scan_id=scan_id,
            scanner="nmap",
            scan_type=data.get('scan_type', 'unknown'),
            hosts=hosts,
            hosts_up=len(hosts),
            raw_output=content
        )

    def _parse_host_json(self, host_data: dict) -> Optional[Host]:
        """Parse a single host from JSON."""
        ports = []
        for port_data in host_data.get('ports', []):
            service = None
            if 'service' in port_data:
                svc = port_data['service']
                service = Service(
                    name=svc.get('name', ''),
                    product=svc.get('product', ''),
                    version=svc.get('version', ''),
                    cpe=svc.get('cpe', [])
                )

            try:
                state = PortState(port_data.get('state', 'unknown'))
            except ValueError:
                state = PortState.UNKNOWN

            ports.append(Port(
                number=port_data.get('port', 0),
                protocol=port_data.get('protocol', 'tcp'),
                state=state,
                service=service,
                scripts=port_data.get('scripts', {})
            ))

        return Host(
            ip=host_data.get('ip', ''),
            hostname=host_data.get('hostname', ''),
            mac_address=host_data.get('mac', ''),
            os_match=host_data.get('os', ''),
            status='up',
            ports=ports
        )

    def _detect_scan_type(self, command_line: str) -> str:
        """Detect scan type from command line arguments."""
        if '-sV' in command_line:
            return 'version'
        elif '-sS' in command_line:
            return 'syn'
        elif '-sT' in command_line:
            return 'connect'
        elif '-sU' in command_line:
            return 'udp'
        elif '-A' in command_line:
            return 'aggressive'
        elif '--script' in command_line or '-sC' in command_line:
            return 'script'
        return 'unknown'

    def extract_vulnerabilities(self, scan_result: ScanResult) -> List[Vulnerability]:
        """Extract vulnerabilities from Nmap scan results."""
        vulnerabilities = []
        vuln_counter = 0

        for host in scan_result.hosts:
            for port in host.get_open_ports():
                # Check for known vulnerable services
                if port.service:
                    vulns = self._check_known_vulnerabilities(
                        host.ip, port, port.service
                    )
                    for v in vulns:
                        vuln_counter += 1
                        v.id = f"NMAP-{scan_result.scan_id}-{vuln_counter:04d}"
                        vulnerabilities.append(v)

                    # Check for insecure protocols
                    proto_vulns = self._check_insecure_protocols(
                        host.ip, port, port.service
                    )
                    for v in proto_vulns:
                        vuln_counter += 1
                        v.id = f"NMAP-{scan_result.scan_id}-{vuln_counter:04d}"
                        vulnerabilities.append(v)

                # Check NSE script results for vulnerabilities
                script_vulns = self._parse_script_vulnerabilities(
                    host.ip, port
                )
                for v in script_vulns:
                    vuln_counter += 1
                    v.id = f"NMAP-{scan_result.scan_id}-{vuln_counter:04d}"
                    vulnerabilities.append(v)

        return vulnerabilities

    def _check_known_vulnerabilities(
            self, host_ip: str, port: Port, service: Service
    ) -> List[Vulnerability]:
        """Check for known vulnerabilities in detected services."""
        vulnerabilities = []

        product_lower = service.product.lower()
        version = service.version

        for product_name, versions in self.KNOWN_VULNERABILITIES.items():
            if product_name in product_lower or product_name in service.name.lower():
                if version in versions:
                    vuln_info = versions[version]
                    vulnerabilities.append(Vulnerability(
                        id="",
                        cve_id=vuln_info['cve'],
                        title=vuln_info['title'],
                        description=vuln_info['description'],
                        cvss_score=vuln_info['cvss'],
                        severity=VulnerabilitySeverity.from_cvss(vuln_info['cvss']),
                        affected_host=host_ip,
                        affected_port=port.number,
                        affected_service=service.name,
                        affected_product=service.product,
                        affected_version=version,
                        source="nmap",
                        exploit_available=True
                    ))

        return vulnerabilities

    def _check_insecure_protocols(
            self, host_ip: str, port: Port, service: Service
    ) -> List[Vulnerability]:
        """Check for insecure protocol usage."""
        vulnerabilities = []
        service_name = service.name.lower()

        for protocol, info in self.INSECURE_PROTOCOLS.items():
            if protocol in service_name:
                vulnerabilities.append(Vulnerability(
                    id="",
                    title=info['title'],
                    description=info['description'],
                    cvss_score=info['cvss'],
                    severity=VulnerabilitySeverity.from_cvss(info['cvss']),
                    affected_host=host_ip,
                    affected_port=port.number,
                    affected_service=service.name,
                    remediation=info['remediation'],
                    source="nmap"
                ))

        return vulnerabilities

    def _parse_script_vulnerabilities(
            self, host_ip: str, port: Port
    ) -> List[Vulnerability]:
        """Parse NSE script output for vulnerabilities."""
        vulnerabilities = []

        for script_id, output in port.scripts.items():
            # Check for vulnerability scripts
            if 'vuln' in script_id.lower():
                # Parse common vulnerability script output
                if 'VULNERABLE' in output.upper():
                    vuln = self._parse_vuln_script_output(
                        host_ip, port, script_id, output
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

            # Check for specific scripts
            elif script_id == 'ssl-heartbleed':
                if 'VULNERABLE' in output.upper():
                    vulnerabilities.append(Vulnerability(
                        id="",
                        cve_id="CVE-2014-0160",
                        title="OpenSSL Heartbleed Vulnerability",
                        description="The TLS heartbeat extension is vulnerable to buffer over-read",
                        cvss_score=7.5,
                        affected_host=host_ip,
                        affected_port=port.number,
                        source="nmap-script"
                    ))

            elif script_id == 'smb-vuln-ms17-010':
                if 'VULNERABLE' in output.upper():
                    vulnerabilities.append(Vulnerability(
                        id="",
                        cve_id="CVE-2017-0144",
                        title="MS17-010 EternalBlue SMB Remote Code Execution",
                        description="Remote code execution vulnerability in Microsoft SMBv1",
                        cvss_score=9.8,
                        affected_host=host_ip,
                        affected_port=port.number,
                        source="nmap-script",
                        exploit_available=True
                    ))

        return vulnerabilities

    def _parse_vuln_script_output(
            self, host_ip: str, port: Port, script_id: str, output: str
    ) -> Optional[Vulnerability]:
        """Parse generic vulnerability script output."""
        # Try to extract CVE
        import re
        cve_match = re.search(r'CVE-\d{4}-\d+', output)
        cve_id = cve_match.group(0) if cve_match else None

        # Try to extract CVSS
        cvss_match = re.search(r'CVSS[:\s]+(\d+\.?\d*)', output, re.IGNORECASE)
        cvss_score = float(cvss_match.group(1)) if cvss_match else 5.0

        return Vulnerability(
            id="",
            cve_id=cve_id,
            title=f"Vulnerability detected by {script_id}",
            description=output[:500],  # Truncate long output
            cvss_score=cvss_score,
            affected_host=host_ip,
            affected_port=port.number,
            affected_service=port.service.name if port.service else "",
            source="nmap-script"
        )
