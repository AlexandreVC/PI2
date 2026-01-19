"""
Main Pipeline for Vulnerability Analysis.

This module orchestrates the complete vulnerability analysis workflow:
1. Parse scan results (Nmap, Nessus)
2. Enrich with CVE/NVD data
3. Map to MITRE ATT&CK
4. AI-powered analysis
5. Prioritization
6. Report generation

Based on ESILV PI2 Project specifications.
"""

import logging
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from .parsers import NmapParser, NessusParser
from .enrichment import CVEEnricher, MITREMapper
from .dispatcher import Dispatcher
from .agent import VulnerabilityAgent, LLMClient
from .reports import ExecutiveReportGenerator, TechnicalReportGenerator
from .models import Vulnerability, ScanResult

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VulnerabilityAnalysisPipeline:
    """
    Complete pipeline for vulnerability analysis and reporting.

    Integrates all components:
    - Scan parsers (Nmap, Nessus)
    - CVE/NVD enrichment
    - MITRE ATT&CK mapping
    - AI-powered analysis
    - Report generation
    """

    def __init__(
            self,
            llm_model: str = "gpt-oss-20b",
            ollama_url: str = "http://localhost:11434",
            output_dir: str = "data/reports",
            enable_ai: bool = True
    ):
        """
        Initialize the pipeline.

        Args:
            llm_model: Default LLM model to use
            ollama_url: Ollama API URL
            output_dir: Directory for generated reports
            enable_ai: Whether to enable AI analysis
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.nmap_parser = NmapParser()
        self.nessus_parser = NessusParser()
        self.cve_enricher = CVEEnricher()
        self.mitre_mapper = MITREMapper()
        self.dispatcher = Dispatcher()

        # Initialize LLM client
        self.llm_client = LLMClient(
            api_type="ollama",
            model=llm_model,
            base_url=ollama_url
        )

        self.enable_ai = enable_ai

        # Initialize AI agent
        self.agent = VulnerabilityAgent(
            llm_client=self.llm_client,
            dispatcher=self.dispatcher,
            cve_enricher=self.cve_enricher,
            mitre_mapper=self.mitre_mapper
        )

        # Initialize report generators
        self.exec_report_gen = ExecutiveReportGenerator(
            output_dir=str(self.output_dir),
            llm_client=self.llm_client if enable_ai else None
        )
        self.tech_report_gen = TechnicalReportGenerator(
            output_dir=str(self.output_dir),
            llm_client=self.llm_client if enable_ai else None
        )

        # Store results
        self.scan_results: List[ScanResult] = []
        self.vulnerabilities: List[Vulnerability] = []

        logger.info("Pipeline initialized successfully")

    def load_nmap_scan(self, file_path: str) -> ScanResult:
        """
        Load and parse Nmap scan results.

        Args:
            file_path: Path to Nmap XML file

        Returns:
            Parsed ScanResult
        """
        logger.info(f"Loading Nmap scan: {file_path}")

        scan_result = self.nmap_parser.parse_file(file_path)
        self.scan_results.append(scan_result)

        # Extract vulnerabilities
        vulns = self.nmap_parser.extract_vulnerabilities(scan_result)
        self.vulnerabilities.extend(vulns)

        logger.info(f"Extracted {len(vulns)} vulnerabilities from Nmap scan")
        return scan_result

    def load_nessus_scan(self, file_path: str) -> ScanResult:
        """
        Load and parse Nessus scan results.

        Args:
            file_path: Path to Nessus file (.nessus or .json)

        Returns:
            Parsed ScanResult
        """
        logger.info(f"Loading Nessus scan: {file_path}")

        scan_result = self.nessus_parser.parse_file(file_path)
        self.scan_results.append(scan_result)

        # Extract vulnerabilities
        vulns = self.nessus_parser.extract_vulnerabilities(scan_result)
        self.vulnerabilities.extend(vulns)

        logger.info(f"Extracted {len(vulns)} vulnerabilities from Nessus scan")
        return scan_result

    def enrich_vulnerabilities(self) -> List[Vulnerability]:
        """
        Enrich all vulnerabilities with CVE data and MITRE mapping.

        Returns:
            List of enriched vulnerabilities
        """
        logger.info("Enriching vulnerabilities...")

        # Enrich with CVE data
        self.vulnerabilities = self.cve_enricher.enrich_vulnerabilities(
            self.vulnerabilities
        )

        # Map to MITRE ATT&CK
        self.vulnerabilities = self.mitre_mapper.map_vulnerabilities(
            self.vulnerabilities
        )

        logger.info(f"Enriched {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities

    def analyze_with_ai(self) -> List[Vulnerability]:
        """
        Perform AI-powered analysis on vulnerabilities.

        Returns:
            List of analyzed vulnerabilities
        """
        if not self.enable_ai:
            logger.warning("AI analysis disabled")
            return self.vulnerabilities

        logger.info("Performing AI analysis...")

        # Analyze each vulnerability
        for i, vuln in enumerate(self.vulnerabilities):
            logger.info(f"Analyzing vulnerability {i + 1}/{len(self.vulnerabilities)}: {vuln.title}")

            try:
                self.vulnerabilities[i] = self.agent.analyze_vulnerability(vuln)
            except Exception as e:
                logger.error(f"Failed to analyze {vuln.id}: {e}")

        return self.vulnerabilities

    def prioritize(self, context: Optional[Dict[str, Any]] = None) -> List[Vulnerability]:
        """
        Prioritize vulnerabilities based on risk and context.

        Args:
            context: Optional business context

        Returns:
            Prioritized list of vulnerabilities
        """
        logger.info("Prioritizing vulnerabilities...")

        if self.enable_ai:
            self.vulnerabilities = self.agent.prioritize_vulnerabilities(
                self.vulnerabilities,
                context
            )
        else:
            # Simple prioritization based on CVSS
            self.vulnerabilities = sorted(
                self.vulnerabilities,
                key=lambda v: (v.exploit_available, v.cvss_score),
                reverse=True
            )
            for i, vuln in enumerate(self.vulnerabilities):
                vuln.remediation_priority = i + 1

        return self.vulnerabilities

    def generate_reports(
            self,
            organization: str = "Organization",
            include_executive: bool = True,
            include_technical: bool = True
    ) -> Dict[str, Path]:
        """
        Generate security assessment reports.

        Args:
            organization: Organization name for reports
            include_executive: Generate executive report
            include_technical: Generate technical report

        Returns:
            Dictionary with report file paths
        """
        logger.info("Generating reports...")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports = {}

        metadata = {
            "organization": organization,
            "classification": "Confidential",
            "prepared_by": "AI Security Agent"
        }

        if include_executive:
            exec_content = self.exec_report_gen.generate(
                self.vulnerabilities,
                self.scan_results,
                metadata
            )
            exec_path = self.exec_report_gen.save(
                exec_content,
                f"executive_report_{timestamp}"
            )
            reports["executive"] = exec_path
            logger.info(f"Executive report saved: {exec_path}")

        if include_technical:
            tech_content = self.tech_report_gen.generate(
                self.vulnerabilities,
                self.scan_results,
                metadata
            )
            tech_path = self.tech_report_gen.save(
                tech_content,
                f"technical_report_{timestamp}"
            )
            reports["technical"] = tech_path
            logger.info(f"Technical report saved: {tech_path}")

        return reports

    def run_full_analysis(
            self,
            nmap_files: Optional[List[str]] = None,
            nessus_files: Optional[List[str]] = None,
            organization: str = "Organization",
            context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run complete analysis pipeline.

        Args:
            nmap_files: List of Nmap scan files
            nessus_files: List of Nessus scan files
            organization: Organization name
            context: Business context for prioritization

        Returns:
            Analysis results summary
        """
        logger.info("=" * 60)
        logger.info("Starting Full Vulnerability Analysis Pipeline")
        logger.info("=" * 60)

        # Step 1: Load scans
        logger.info("\n[Step 1/5] Loading scan results...")
        if nmap_files:
            for f in nmap_files:
                self.load_nmap_scan(f)

        if nessus_files:
            for f in nessus_files:
                self.load_nessus_scan(f)

        if not self.vulnerabilities:
            logger.warning("No vulnerabilities found!")
            return {"status": "no_vulnerabilities"}

        # Step 2: Enrich
        logger.info("\n[Step 2/5] Enriching vulnerabilities...")
        self.enrich_vulnerabilities()

        # Step 3: AI Analysis
        logger.info("\n[Step 3/5] AI-powered analysis...")
        self.analyze_with_ai()

        # Step 4: Prioritize
        logger.info("\n[Step 4/5] Prioritizing vulnerabilities...")
        self.prioritize(context)

        # Step 5: Generate reports
        logger.info("\n[Step 5/5] Generating reports...")
        reports = self.generate_reports(organization)

        # Build summary
        severity_stats = self._get_severity_stats()

        summary = {
            "status": "completed",
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_breakdown": severity_stats,
            "hosts_scanned": sum(len(sr.hosts) for sr in self.scan_results),
            "exploitable_count": sum(1 for v in self.vulnerabilities if v.exploit_available),
            "reports_generated": {k: str(v) for k, v in reports.items()},
            "top_priorities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "cvss": v.cvss_score,
                    "host": v.affected_host
                }
                for v in self.vulnerabilities[:5]
            ]
        }

        logger.info("\n" + "=" * 60)
        logger.info("Analysis Complete!")
        logger.info(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        logger.info(f"Critical: {severity_stats['critical']}, High: {severity_stats['high']}")
        logger.info("=" * 60)

        return summary

    def _get_severity_stats(self) -> Dict[str, int]:
        """Get severity statistics."""
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in self.vulnerabilities:
            stats[vuln.severity.value] += 1
        return stats

    def get_risk_assessment(self) -> Dict[str, Any]:
        """Get overall risk assessment."""
        if not self.enable_ai:
            return {"risk_level": "unknown", "message": "AI disabled"}

        return self.agent.assess_risk(self.vulnerabilities)

    def get_remediation_plan(self) -> Dict[str, Any]:
        """Get remediation plan."""
        if not self.enable_ai:
            return {"message": "AI disabled"}

        return self.agent.generate_remediation_plan(self.vulnerabilities)

    def export_vulnerabilities(self, file_path: str, format: str = "json"):
        """
        Export vulnerabilities to file.

        Args:
            file_path: Output file path
            format: Export format (json, csv)
        """
        if format == "json":
            data = [v.to_dict() for v in self.vulnerabilities]
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)

        logger.info(f"Exported vulnerabilities to {file_path}")


def main():
    """Main entry point for command-line usage."""
    import argparse

    parser = argparse.ArgumentParser(
        description="AI-Powered Vulnerability Analysis Pipeline"
    )
    parser.add_argument(
        "--nmap", "-n",
        nargs="+",
        help="Nmap XML scan files"
    )
    parser.add_argument(
        "--nessus", "-s",
        nargs="+",
        help="Nessus scan files"
    )
    parser.add_argument(
        "--output", "-o",
        default="data/reports",
        help="Output directory for reports"
    )
    parser.add_argument(
        "--org",
        default="Organization",
        help="Organization name for reports"
    )
    parser.add_argument(
        "--model",
        default="gpt-oss-20b",
        help="LLM model to use"
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI analysis"
    )

    args = parser.parse_args()

    # Initialize pipeline
    pipeline = VulnerabilityAnalysisPipeline(
        llm_model=args.model,
        output_dir=args.output,
        enable_ai=not args.no_ai
    )

    # Run analysis
    results = pipeline.run_full_analysis(
        nmap_files=args.nmap,
        nessus_files=args.nessus,
        organization=args.org
    )

    # Print results
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
