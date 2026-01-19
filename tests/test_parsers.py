"""Tests for scan parsers."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parsers import NmapParser, NessusParser
from src.models import PortState


def test_nmap_parser():
    """Test Nmap XML parsing."""
    parser = NmapParser()

    # Test with sample file if available
    sample_file = Path("data/scans/sample_nmap.xml")
    if sample_file.exists():
        result = parser.parse_file(str(sample_file))

        assert result.scanner == "nmap"
        assert len(result.hosts) > 0

        # Check first host
        host = result.hosts[0]
        assert host.ip is not None
        assert len(host.ports) > 0

        # Extract vulnerabilities
        vulns = parser.extract_vulnerabilities(result)
        assert len(vulns) > 0

        print(f"[PASS] Nmap parser: {len(result.hosts)} hosts, {len(vulns)} vulnerabilities")
    else:
        print("[SKIP] Sample Nmap file not found")


def test_nessus_parser():
    """Test Nessus JSON parsing."""
    parser = NessusParser()

    # Test with sample file if available
    sample_file = Path("data/scans/sample_nessus.json")
    if sample_file.exists():
        result = parser.parse_file(str(sample_file))

        assert result.scanner == "nessus"

        # Extract vulnerabilities
        vulns = parser.extract_vulnerabilities(result)
        assert len(vulns) > 0

        # Check vulnerability properties
        for vuln in vulns:
            assert vuln.title is not None
            assert vuln.affected_host is not None

        print(f"[PASS] Nessus parser: {len(vulns)} vulnerabilities")
    else:
        print("[SKIP] Sample Nessus file not found")


def test_vulnerability_extraction():
    """Test vulnerability extraction from Nmap."""
    parser = NmapParser()

    # Test known vulnerable service detection
    xml_content = """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="192.168.1.100" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="21">
                    <state state="open"/>
                    <service name="ftp" product="vsftpd" version="2.3.4"/>
                </port>
            </ports>
        </host>
        <runstats>
            <hosts up="1" down="0" total="1"/>
        </runstats>
    </nmaprun>
    """

    result = parser.parse_string(xml_content)
    vulns = parser.extract_vulnerabilities(result)

    # Should detect vsftpd 2.3.4 backdoor
    vsftpd_vuln = next((v for v in vulns if "vsftpd" in v.title.lower()), None)
    assert vsftpd_vuln is not None, "Should detect vsftpd vulnerability"
    assert vsftpd_vuln.cve_id == "CVE-2011-2523"
    assert vsftpd_vuln.cvss_score == 10.0

    print("[PASS] Vulnerability extraction")


if __name__ == "__main__":
    print("Running parser tests...\n")
    test_nmap_parser()
    test_nessus_parser()
    test_vulnerability_extraction()
    print("\nAll tests passed!")
