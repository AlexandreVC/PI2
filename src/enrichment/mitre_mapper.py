"""MITRE ATT&CK mapping module."""

import logging
from typing import List, Dict, Optional, Tuple

from ..models import Vulnerability

logger = logging.getLogger(__name__)


class MITREMapper:
    """
    Maps vulnerabilities to MITRE ATT&CK framework.

    Provides tactical and technique context for vulnerability analysis.
    """

    # MITRE ATT&CK Tactics
    TACTICS = {
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0010": "Exfiltration",
        "TA0011": "Command and Control",
        "TA0040": "Impact"
    }

    # Mapping of CWE to MITRE techniques
    CWE_TO_MITRE = {
        # Injection vulnerabilities
        "CWE-78": [("T1059", "Command and Scripting Interpreter", "TA0002")],
        "CWE-79": [("T1189", "Drive-by Compromise", "TA0001")],
        "CWE-89": [("T1190", "Exploit Public-Facing Application", "TA0001")],
        "CWE-94": [("T1059", "Command and Scripting Interpreter", "TA0002")],
        "CWE-917": [("T1190", "Exploit Public-Facing Application", "TA0001"),
                    ("T1059", "Command and Scripting Interpreter", "TA0002")],

        # Authentication/Authorization
        "CWE-287": [("T1078", "Valid Accounts", "TA0001")],
        "CWE-306": [("T1078", "Valid Accounts", "TA0001")],
        "CWE-522": [("T1552", "Unsecured Credentials", "TA0006")],
        "CWE-798": [("T1552.001", "Credentials In Files", "TA0006")],

        # Cryptographic issues
        "CWE-295": [("T1557", "Adversary-in-the-Middle", "TA0006")],
        "CWE-327": [("T1040", "Network Sniffing", "TA0006")],
        "CWE-328": [("T1110", "Brute Force", "TA0006")],

        # Buffer/Memory issues
        "CWE-119": [("T1203", "Exploitation for Client Execution", "TA0002")],
        "CWE-120": [("T1203", "Exploitation for Client Execution", "TA0002")],
        "CWE-125": [("T1005", "Data from Local System", "TA0009")],
        "CWE-787": [("T1203", "Exploitation for Client Execution", "TA0002")],

        # Path traversal / File inclusion
        "CWE-22": [("T1083", "File and Directory Discovery", "TA0007")],
        "CWE-98": [("T1190", "Exploit Public-Facing Application", "TA0001")],

        # Privilege escalation
        "CWE-269": [("T1068", "Exploitation for Privilege Escalation", "TA0004")],
        "CWE-732": [("T1068", "Exploitation for Privilege Escalation", "TA0004")],

        # Information disclosure
        "CWE-200": [("T1005", "Data from Local System", "TA0009")],
        "CWE-209": [("T1082", "System Information Discovery", "TA0007")],

        # Deserialization
        "CWE-502": [("T1059", "Command and Scripting Interpreter", "TA0002")],
    }

    # Service-based mapping
    SERVICE_TO_MITRE = {
        "ssh": [("T1021.004", "SSH", "TA0008")],
        "rdp": [("T1021.001", "Remote Desktop Protocol", "TA0008")],
        "smb": [("T1021.002", "SMB/Windows Admin Shares", "TA0008")],
        "ftp": [("T1071.002", "File Transfer Protocols", "TA0011")],
        "telnet": [("T1021.001", "Remote Services", "TA0008")],
        "http": [("T1071.001", "Web Protocols", "TA0011")],
        "https": [("T1071.001", "Web Protocols", "TA0011")],
        "dns": [("T1071.004", "DNS", "TA0011")],
        "ldap": [("T1087.002", "Domain Account", "TA0007")],
        "mysql": [("T1213", "Data from Information Repositories", "TA0009")],
        "postgresql": [("T1213", "Data from Information Repositories", "TA0009")],
        "mssql": [("T1213", "Data from Information Repositories", "TA0009")],
        "vnc": [("T1021.005", "VNC", "TA0008")],
        "winrm": [("T1021.006", "Windows Remote Management", "TA0008")],
    }

    # CVE-specific mappings for well-known vulnerabilities
    CVE_TO_MITRE = {
        "CVE-2021-44228": [
            ("T1190", "Exploit Public-Facing Application", "TA0001"),
            ("T1059", "Command and Scripting Interpreter", "TA0002"),
            ("T1105", "Ingress Tool Transfer", "TA0011")
        ],
        "CVE-2017-0144": [
            ("T1210", "Exploitation of Remote Services", "TA0008"),
            ("T1570", "Lateral Tool Transfer", "TA0008")
        ],
        "CVE-2014-0160": [
            ("T1040", "Network Sniffing", "TA0006"),
            ("T1552", "Unsecured Credentials", "TA0006")
        ],
        "CVE-2011-2523": [
            ("T1190", "Exploit Public-Facing Application", "TA0001"),
            ("T1059.004", "Unix Shell", "TA0002")
        ],
        "CVE-2007-2447": [
            ("T1190", "Exploit Public-Facing Application", "TA0001"),
            ("T1059.004", "Unix Shell", "TA0002")
        ],
        "CVE-2019-0708": [
            ("T1210", "Exploitation of Remote Services", "TA0008"),
            ("T1021.001", "Remote Desktop Protocol", "TA0008")
        ]
    }

    def map_vulnerability(self, vulnerability: Vulnerability) -> Vulnerability:
        """
        Map a vulnerability to MITRE ATT&CK framework.

        Args:
            vulnerability: Vulnerability to map

        Returns:
            Vulnerability with MITRE mappings added
        """
        tactics = set()
        techniques = []

        # 1. Check CVE-specific mappings
        if vulnerability.cve_id and vulnerability.cve_id in self.CVE_TO_MITRE:
            for technique_id, technique_name, tactic_id in self.CVE_TO_MITRE[vulnerability.cve_id]:
                techniques.append(f"{technique_id}: {technique_name}")
                tactics.add(self.TACTICS.get(tactic_id, tactic_id))

        # 2. Check CWE mappings
        if vulnerability.cwe_id:
            cwe_num = vulnerability.cwe_id.replace("CWE-", "")
            cwe_key = f"CWE-{cwe_num}"
            if cwe_key in self.CWE_TO_MITRE:
                for technique_id, technique_name, tactic_id in self.CWE_TO_MITRE[cwe_key]:
                    tech_str = f"{technique_id}: {technique_name}"
                    if tech_str not in techniques:
                        techniques.append(tech_str)
                    tactics.add(self.TACTICS.get(tactic_id, tactic_id))

        # 3. Check service-based mappings
        service = vulnerability.affected_service.lower()
        for svc_key, mappings in self.SERVICE_TO_MITRE.items():
            if svc_key in service:
                for technique_id, technique_name, tactic_id in mappings:
                    tech_str = f"{technique_id}: {technique_name}"
                    if tech_str not in techniques:
                        techniques.append(tech_str)
                    tactics.add(self.TACTICS.get(tactic_id, tactic_id))

        # 4. Infer from vulnerability characteristics
        inferred = self._infer_from_characteristics(vulnerability)
        for technique_id, technique_name, tactic_id in inferred:
            tech_str = f"{technique_id}: {technique_name}"
            if tech_str not in techniques:
                techniques.append(tech_str)
            tactics.add(self.TACTICS.get(tactic_id, tactic_id))

        vulnerability.mitre_tactics = list(tactics)
        vulnerability.mitre_techniques = techniques

        return vulnerability

    def map_vulnerabilities(
            self, vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """Map multiple vulnerabilities to MITRE ATT&CK."""
        return [self.map_vulnerability(v) for v in vulnerabilities]

    def _infer_from_characteristics(
            self, vulnerability: Vulnerability
    ) -> List[Tuple[str, str, str]]:
        """Infer MITRE mappings from vulnerability characteristics."""
        mappings = []
        desc_lower = vulnerability.description.lower()
        title_lower = vulnerability.title.lower()
        combined = f"{desc_lower} {title_lower}"

        # Remote code execution
        if any(term in combined for term in ['remote code execution', 'rce', 'arbitrary code']):
            mappings.append(("T1203", "Exploitation for Client Execution", "TA0002"))

        # Command injection
        if any(term in combined for term in ['command injection', 'shell injection', 'os command']):
            mappings.append(("T1059", "Command and Scripting Interpreter", "TA0002"))

        # SQL injection
        if 'sql injection' in combined:
            mappings.append(("T1190", "Exploit Public-Facing Application", "TA0001"))

        # Authentication bypass
        if any(term in combined for term in ['authentication bypass', 'auth bypass', 'access control']):
            mappings.append(("T1078", "Valid Accounts", "TA0001"))

        # Information disclosure
        if any(term in combined for term in ['information disclosure', 'sensitive data', 'memory leak']):
            mappings.append(("T1005", "Data from Local System", "TA0009"))

        # Privilege escalation
        if any(term in combined for term in ['privilege escalation', 'elevated privileges', 'root access']):
            mappings.append(("T1068", "Exploitation for Privilege Escalation", "TA0004"))

        # Denial of service
        if any(term in combined for term in ['denial of service', 'dos', 'crash', 'resource exhaustion']):
            mappings.append(("T1499", "Endpoint Denial of Service", "TA0040"))

        # Backdoor
        if 'backdoor' in combined:
            mappings.append(("T1543", "Create or Modify System Process", "TA0003"))

        return mappings

    def get_tactic_description(self, tactic_id: str) -> str:
        """Get description for a MITRE tactic."""
        descriptions = {
            "TA0001": "The adversary is trying to get into your network.",
            "TA0002": "The adversary is trying to run malicious code.",
            "TA0003": "The adversary is trying to maintain their foothold.",
            "TA0004": "The adversary is trying to gain higher-level permissions.",
            "TA0005": "The adversary is trying to avoid being detected.",
            "TA0006": "The adversary is trying to steal credentials.",
            "TA0007": "The adversary is trying to figure out your environment.",
            "TA0008": "The adversary is trying to move through your environment.",
            "TA0009": "The adversary is trying to gather data of interest.",
            "TA0010": "The adversary is trying to steal data.",
            "TA0011": "The adversary is trying to communicate with compromised systems.",
            "TA0040": "The adversary is trying to manipulate, disrupt, or destroy systems."
        }
        return descriptions.get(tactic_id, "Unknown tactic")

    def generate_attack_path(
            self, vulnerabilities: List[Vulnerability]
    ) -> List[Dict[str, any]]:
        """
        Generate potential attack path based on vulnerabilities.

        Args:
            vulnerabilities: List of mapped vulnerabilities

        Returns:
            List of attack path stages
        """
        # Group by tactic
        tactic_order = [
            "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection",
            "Exfiltration", "Command and Control", "Impact"
        ]

        attack_path = []
        for tactic in tactic_order:
            vulns_in_tactic = [
                v for v in vulnerabilities
                if tactic in v.mitre_tactics
            ]

            if vulns_in_tactic:
                attack_path.append({
                    "stage": tactic,
                    "vulnerabilities": [
                        {
                            "id": v.id,
                            "cve": v.cve_id,
                            "title": v.title,
                            "host": v.affected_host,
                            "techniques": v.mitre_techniques
                        }
                        for v in vulns_in_tactic
                    ]
                })

        return attack_path
