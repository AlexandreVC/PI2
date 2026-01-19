#!/usr/bin/env python3
"""
Launch script for VulnAI Web Interface.

This script starts the FastAPI web server for the vulnerability analysis platform.
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    """Start the web server."""
    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn not installed.")
        print("Please run: pip install uvicorn[standard] fastapi python-multipart")
        sys.exit(1)

    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ █████╗ ██╗            ║
    ║   ██║   ██║██║   ██║██║     ████╗  ██║██╔══██╗██║            ║
    ║   ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██║            ║
    ║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██║            ║
    ║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║            ║
    ║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝            ║
    ║                                                               ║
    ║   AI-Powered Vulnerability Analysis Platform                  ║
    ║   ESILV PI2 Project                                           ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    print("Starting VulnAI Web Interface...")
    print("=" * 60)
    print()
    print("  Web Interface:  http://localhost:8000")
    print("  API Docs:       http://localhost:8000/docs")
    print("  API Schema:     http://localhost:8000/redoc")
    print()
    print("=" * 60)
    print()
    print("Press CTRL+C to stop the server")
    print()

    # Change to project directory
    os.chdir(project_root)

    # Run the server
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=[str(project_root / "api"), str(project_root / "frontend")]
    )


if __name__ == "__main__":
    main()
