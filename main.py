#!/usr/bin/env python3
"""
Agent IA Génératif pour l'Analyse de Vulnérabilités et la Gestion des Risques

ESILV PI2 Project
Encadrant: Mohamed BELAOUED

This is the main entry point for the vulnerability analysis pipeline.
"""

import sys
import json
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.pipeline import VulnerabilityAnalysisPipeline
from config import DEFAULT_SETTINGS


def run_demo():
    """Run a demonstration analysis with sample data."""
    print("=" * 70)
    print("AGENT IA GÉNÉRATIF - ANALYSE DE VULNÉRABILITÉS")
    print("ESILV PI2 Project")
    print("=" * 70)

    # Sample scan files
    sample_nmap = "data/scans/sample_nmap.xml"
    sample_nessus = "data/scans/sample_nessus.json"

    # Check if sample files exist
    if not Path(sample_nmap).exists():
        print(f"\n[!] Sample Nmap file not found: {sample_nmap}")
        print("    Please add scan files to data/scans/")
        return

    # Initialize pipeline (AI disabled for demo without Ollama)
    print("\n[*] Initializing pipeline...")
    pipeline = VulnerabilityAnalysisPipeline(
        llm_model=DEFAULT_SETTINGS.llm.default_model,
        output_dir=DEFAULT_SETTINGS.report.output_dir,
        enable_ai=False  # Set to True if Ollama is running
    )

    # Load and process scans
    print("\n[*] Loading scan results...")

    if Path(sample_nmap).exists():
        pipeline.load_nmap_scan(sample_nmap)
        print(f"    Loaded: {sample_nmap}")

    if Path(sample_nessus).exists():
        pipeline.load_nessus_scan(sample_nessus)
        print(f"    Loaded: {sample_nessus}")

    # Enrich vulnerabilities
    print("\n[*] Enriching vulnerabilities with CVE/NVD data...")
    pipeline.enrich_vulnerabilities()

    # Display summary
    print("\n" + "=" * 70)
    print("VULNERABILITY SUMMARY")
    print("=" * 70)

    stats = pipeline._get_severity_stats()
    print(f"\nTotal Vulnerabilities: {len(pipeline.vulnerabilities)}")
    print(f"  - Critical: {stats['critical']}")
    print(f"  - High:     {stats['high']}")
    print(f"  - Medium:   {stats['medium']}")
    print(f"  - Low:      {stats['low']}")
    print(f"  - Info:     {stats['info']}")

    exploitable = sum(1 for v in pipeline.vulnerabilities if v.exploit_available)
    print(f"\nExploitable: {exploitable}")

    # Show top vulnerabilities
    print("\n" + "-" * 70)
    print("TOP 5 CRITICAL VULNERABILITIES")
    print("-" * 70)

    sorted_vulns = sorted(
        pipeline.vulnerabilities,
        key=lambda v: v.cvss_score,
        reverse=True
    )

    for i, vuln in enumerate(sorted_vulns[:5], 1):
        print(f"\n{i}. {vuln.title}")
        print(f"   CVE: {vuln.cve_id or 'N/A'}")
        print(f"   CVSS: {vuln.cvss_score} ({vuln.severity.value.upper()})")
        print(f"   Host: {vuln.affected_host}:{vuln.affected_port}")
        print(f"   Exploit: {'Available' if vuln.exploit_available else 'Not known'}")
        if vuln.mitre_tactics:
            print(f"   MITRE Tactics: {', '.join(vuln.mitre_tactics)}")

    # Generate reports
    print("\n" + "=" * 70)
    print("GENERATING REPORTS")
    print("=" * 70)

    reports = pipeline.generate_reports(organization="ESILV Demo")

    print("\nReports generated:")
    for report_type, path in reports.items():
        print(f"  - {report_type.capitalize()}: {path}")

    # Export vulnerabilities
    export_path = "data/reports/vulnerabilities.json"
    pipeline.export_vulnerabilities(export_path)
    print(f"  - Data Export: {export_path}")

    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)
    print("\nTo run with AI analysis, ensure Ollama is running with the model:")
    print(f"  ollama run {DEFAULT_SETTINGS.llm.default_model}")
    print("\nThen set enable_ai=True in the pipeline initialization.")


def run_with_args():
    """Run pipeline with command-line arguments."""
    import argparse

    parser = argparse.ArgumentParser(
        description="AI-Powered Vulnerability Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo
  python main.py --nmap scan.xml --nessus scan.nessus --org "Company Name"
  python main.py --nmap scan.xml --ai --model mistral-small
        """
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run demonstration with sample data"
    )
    parser.add_argument(
        "--nmap", "-n",
        nargs="+",
        help="Nmap XML scan file(s)"
    )
    parser.add_argument(
        "--nessus", "-s",
        nargs="+",
        help="Nessus scan file(s)"
    )
    parser.add_argument(
        "--org",
        default="Organization",
        help="Organization name for reports"
    )
    parser.add_argument(
        "--output", "-o",
        default="data/reports",
        help="Output directory for reports"
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_SETTINGS.llm.default_model,
        help="LLM model to use (default: gpt-oss:20b)"
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable AI-powered analysis (requires Ollama)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    # Configure logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Run demo or full analysis
    if args.demo:
        run_demo()
    elif args.nmap or args.nessus:
        # Initialize pipeline
        pipeline = VulnerabilityAnalysisPipeline(
            llm_model=args.model,
            output_dir=args.output,
            enable_ai=args.ai
        )

        # Run full analysis
        results = pipeline.run_full_analysis(
            nmap_files=args.nmap,
            nessus_files=args.nessus,
            organization=args.org
        )

        print("\n" + json.dumps(results, indent=2))
    else:
        parser.print_help()
        print("\nRun with --demo for a demonstration or provide scan files.")


if __name__ == "__main__":
    run_with_args()
