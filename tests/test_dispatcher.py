"""Tests for the intelligent dispatcher."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.dispatcher import Dispatcher, TaskComplexity, TaskType


def test_task_type_detection():
    """Test task type detection from description."""
    dispatcher = Dispatcher()

    # Test various task descriptions
    test_cases = [
        ("Parse the Nmap XML output", TaskType.NMAP_ANALYSIS),
        ("Analyze Nessus vulnerability scan results", TaskType.NESSUS_ANALYSIS),
        ("Correlate with MITRE ATT&CK framework", TaskType.MITRE_CORRELATION),
        ("Generate remediation plan for vulnerabilities", TaskType.REMEDIATION_PLANNING),
        ("Assess the risk level of findings", TaskType.RISK_ASSESSMENT),
        ("Create executive report", TaskType.REPORT_GENERATION),
        ("Generate exploit script for testing", TaskType.SCRIPT_GENERATION),
    ]

    for description, expected_type in test_cases:
        result = dispatcher.dispatch(description)
        assert result.task_type == expected_type, \
            f"Expected {expected_type} for '{description}', got {result.task_type}"

    print("[PASS] Task type detection")


def test_complexity_estimation():
    """Test complexity estimation."""
    dispatcher = Dispatcher()

    # Simple task
    result = dispatcher.dispatch("Parse log file")
    assert result.complexity in [TaskComplexity.SIMPLE, TaskComplexity.MEDIUM]

    # Complex task
    result = dispatcher.dispatch(
        "Generate comprehensive exploit analysis with MITRE correlation",
        input_data="x" * 30000  # Large input
    )
    assert result.complexity in [TaskComplexity.COMPLEX, TaskComplexity.VERY_COMPLEX]

    print("[PASS] Complexity estimation")


def test_model_selection():
    """Test model selection based on task."""
    dispatcher = Dispatcher()

    # Simple task should use fast model
    result = dispatcher.dispatch("Parse Nmap logs", prefer_speed=True)
    assert result.model is not None
    print(f"  Simple task -> {result.model.name}")

    # Complex task should use capable model
    result = dispatcher.dispatch("Correlate vulnerabilities with MITRE ATT&CK tactics")
    assert result.model is not None
    print(f"  Complex task -> {result.model.name}")

    # Very complex task
    result = dispatcher.dispatch("Generate exploit script for CVE-2021-44228")
    assert result.model is not None
    print(f"  Very complex task -> {result.model.name}")

    print("[PASS] Model selection")


def test_dispatch_statistics():
    """Test dispatch statistics tracking."""
    dispatcher = Dispatcher()

    # Make several dispatches
    dispatcher.dispatch("Parse logs")
    dispatcher.dispatch("Analyze vulnerabilities")
    dispatcher.dispatch("Generate report")

    stats = dispatcher.get_dispatch_stats()

    assert stats["total_dispatches"] == 3
    assert "by_model" in stats
    assert "by_task_type" in stats

    print(f"[PASS] Dispatch statistics: {stats['total_dispatches']} dispatches")


if __name__ == "__main__":
    print("Running dispatcher tests...\n")
    test_task_type_detection()
    test_complexity_estimation()
    test_model_selection()
    test_dispatch_statistics()
    print("\nAll tests passed!")
