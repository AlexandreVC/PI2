"""
FastAPI Backend for VulnAI - AI-Powered Vulnerability Analysis Platform.

Provides REST API endpoints for:
- Uploading code files for analysis
- Running AI-powered vulnerability scans
- Viewing discovered vulnerabilities
- Generating security reports (Executive & Technical)

IMPORTANT: Starts with ZERO vulnerabilities.
Vulnerabilities are only added when AI scans detect them.
"""

import os
import sys
import json
import uuid
import asyncio
import shutil
import logging
from pathlib import Path

# Configure logging to show in console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
from datetime import datetime
from typing import List, Dict, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# Import our modules
from api.data_manager import get_data_manager, DataManager
from api.ai_scanner import AIScanner, ScanConfig, create_scanner
from api.ai_reporter import AIReporter, ReportConfig, create_reporter
from api.nvd_client import NVDClient, NVDConfig
from api.mitre_client import MITREClient, get_mitre_client
from api.vulnerability_enricher import VulnerabilityEnricher, get_enricher
from api.project_manager import get_project_manager, ProjectManager

# Import scan parsers
from src.parsers import NmapParser, NessusParser

app = FastAPI(
    title="VulnAI - AI-Powered Vulnerability Analysis",
    description="Scan code for vulnerabilities using AI. No pre-loaded data - only findings from your scans.",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directories
UPLOAD_DIR = Path("data/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Global instances
data_manager: Optional[DataManager] = None
ai_scanner: Optional[AIScanner] = None
ai_reporter: Optional[AIReporter] = None
nvd_client: Optional[NVDClient] = None
mitre_client: Optional[MITREClient] = None
vulnerability_enricher: Optional[VulnerabilityEnricher] = None
project_manager: Optional[ProjectManager] = None

# Scan parsers
nmap_parser: Optional[NmapParser] = None
nessus_parser: Optional[NessusParser] = None

# Scan jobs tracking
scan_jobs: Dict[str, Dict[str, Any]] = {}

# Background fetch jobs
fetch_jobs: Dict[str, Dict[str, Any]] = {}


def _detect_scan_type(filename: str, content: bytes) -> str:
    """Auto-detect scan type from filename and content."""
    filename_lower = filename.lower()

    # Check by extension
    if filename_lower.endswith('.nessus'):
        return 'nessus'
    if filename_lower.endswith('.nmap'):
        return 'nmap'

    # Check content for XML signatures
    try:
        content_str = content.decode('utf-8', errors='ignore')[:2000]

        if '<!DOCTYPE nmaprun' in content_str or '<nmaprun' in content_str:
            return 'nmap'
        if '<NessusClientData' in content_str or '<Report name=' in content_str:
            return 'nessus'

        # Check for JSON formats
        if content_str.strip().startswith('{') or content_str.strip().startswith('['):
            if '"nmaprun"' in content_str or '"scaninfo"' in content_str:
                return 'nmap'
            if '"plugin' in content_str.lower() or '"severity"' in content_str:
                return 'nessus'
    except:
        pass

    # Default based on extension
    if filename_lower.endswith('.xml'):
        return 'nmap'  # Default XML to nmap
    if filename_lower.endswith('.json'):
        return 'nessus'  # Default JSON to nessus

    return 'unknown'


# Pydantic models
class ScanRequest(BaseModel):
    """Request to scan uploaded files."""
    file_ids: List[str] = []
    model: str = "mistral"
    scan_type: str = "code"  # code, directory
    project_id: Optional[str] = None  # If set, scan from project instead of uploads


class ProjectCreate(BaseModel):
    """Request to create a project."""
    name: str
    description: str = ""


class ProjectUpdate(BaseModel):
    """Request to update a project."""
    name: Optional[str] = None
    description: Optional[str] = None


class ReportRequest(BaseModel):
    """Request to generate reports."""
    organization: str = "Organization"
    report_type: str = "both"  # executive, technical, both
    project_id: Optional[str] = None  # Filter vulnerabilities by project


class AnalysisConfig(BaseModel):
    """Configuration for analysis."""
    model: str = "mistral"
    ollama_url: str = "http://localhost:11434"


# Pydantic models for NVD/MITRE
class NVDFetchRequest(BaseModel):
    """Request to fetch CVEs from NVD."""
    days: int = 30
    severity: Optional[str] = None  # CRITICAL, HIGH, MEDIUM, LOW
    keyword: Optional[str] = None
    api_key: Optional[str] = None


class MITREFetchRequest(BaseModel):
    """Request to fetch MITRE ATT&CK data."""
    force_refresh: bool = False


class ScanImportRequest(BaseModel):
    """Request to import external scan results."""
    scan_type: Optional[str] = None  # nmap, nessus, or auto-detect
    enrich: bool = True  # Enrich with CVE/MITRE data


# Startup/Shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    global data_manager, ai_scanner, ai_reporter, nvd_client, mitre_client, vulnerability_enricher, project_manager

    data_manager = get_data_manager()
    ai_scanner = create_scanner()
    ai_reporter = create_reporter()
    nvd_client = NVDClient()
    mitre_client = get_mitre_client()
    vulnerability_enricher = get_enricher(nvd_client, mitre_client)
    project_manager = get_project_manager()


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    pass


# ============================================
# Health & Status Endpoints
# ============================================

@app.get("/")
async def root():
    """Serve frontend."""
    return FileResponse("frontend/index.html")


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities_count": len(data_manager.get_vulnerabilities()) if data_manager else 0,
        "message": "AI Scanner ready. Upload code to scan for vulnerabilities."
    }


@app.get("/api/status")
async def get_status():
    """Get system status."""
    ollama_available = False
    try:
        import requests
        resp = requests.get("http://localhost:11434/api/tags", timeout=2)
        ollama_available = resp.status_code == 200
    except:
        pass

    return {
        "ollama_available": ollama_available,
        "vulnerabilities": len(data_manager.get_vulnerabilities()) if data_manager else 0,
        "scans_completed": len(data_manager.get_scan_history()) if data_manager else 0,
        "reports_generated": len(data_manager.get_reports()) if data_manager else 0
    }


# ============================================
# Dashboard Endpoints
# ============================================

@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics."""
    stats = data_manager.get_stats()

    # Add trend placeholder
    stats["trend"] = {
        "direction": "stable",
        "change": 0,
        "period": "since last scan"
    }

    return stats


# ============================================
# Upload Endpoints
# ============================================

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload a file for vulnerability scanning.

    Accepts:
    - Source code files (.py, .js, .ts, .java, .php, etc.)
    - Configuration files (.xml, .yaml, .json, .env)
    - Scan result files (.xml from Nmap, .nessus)
    """
    # Validate file
    allowed_extensions = [
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.php', '.rb', '.go',
        '.c', '.cpp', '.cs', '.sql', '.html', '.xml', '.yaml', '.yml',
        '.json', '.env', '.conf', '.ini', '.nessus', '.nmap', '.txt', '.md'
    ]

    file_ext = Path(file.filename).suffix.lower()

    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"File type not supported. Allowed: {', '.join(allowed_extensions)}"
        )

    # Generate unique ID and save file
    file_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_filename = f"{timestamp}_{file_id}_{file.filename}"
    file_path = UPLOAD_DIR / safe_filename

    content = await file.read()

    with open(file_path, "wb") as f:
        f.write(content)

    file_info = {
        "id": file_id,
        "original_name": file.filename,
        "stored_name": safe_filename,
        "path": str(file_path),
        "size": len(content),
        "extension": file_ext,
        "uploaded_at": datetime.now().isoformat()
    }

    return {
        "status": "uploaded",
        "file": file_info,
        "message": f"File uploaded. Use /api/scan to analyze for vulnerabilities."
    }


@app.post("/api/upload/directory")
async def upload_directory(files: List[UploadFile] = File(...)):
    """Upload multiple files (simulating directory upload)."""
    uploaded = []

    for file in files:
        result = await upload_file(file)
        uploaded.append(result["file"])

    return {
        "status": "uploaded",
        "files": uploaded,
        "count": len(uploaded),
        "message": f"{len(uploaded)} files uploaded. Use /api/scan to analyze."
    }


@app.get("/api/uploads")
async def list_uploads():
    """List uploaded files."""
    files = []

    for f in UPLOAD_DIR.glob("*"):
        if f.is_file():
            files.append({
                "name": f.name,
                "size": f.stat().st_size,
                "uploaded_at": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
            })

    return {"files": sorted(files, key=lambda x: x["uploaded_at"], reverse=True)}


# ============================================
# Project Endpoints
# ============================================

@app.get("/api/projects")
async def list_projects():
    """List all projects."""
    projects = project_manager.list_projects()
    return {
        "projects": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "created_at": p.created_at,
                "updated_at": p.updated_at,
                "file_count": p.file_count,
                "total_size": p.total_size,
                "last_scan": p.last_scan,
                "scan_count": p.scan_count,
                "vulnerability_count": p.vulnerability_count
            }
            for p in projects
        ]
    }


@app.post("/api/projects")
async def create_project(request: ProjectCreate):
    """Create a new project."""
    project = project_manager.create_project(request.name, request.description)
    return {
        "status": "created",
        "project": {
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "created_at": project.created_at
        }
    }


@app.get("/api/projects/{project_id}")
async def get_project(project_id: str):
    """Get project details."""
    project = project_manager.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    files = project_manager.list_files(project_id)

    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "created_at": project.created_at,
        "updated_at": project.updated_at,
        "file_count": project.file_count,
        "total_size": project.total_size,
        "last_scan": project.last_scan,
        "scan_count": project.scan_count,
        "vulnerability_count": project.vulnerability_count,
        "files": files
    }


@app.put("/api/projects/{project_id}")
async def update_project(project_id: str, request: ProjectUpdate):
    """Update a project."""
    project = project_manager.update_project(project_id, request.name, request.description)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return {
        "status": "updated",
        "project": {
            "id": project.id,
            "name": project.name,
            "description": project.description
        }
    }


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: str):
    """Delete a project and all its files."""
    success = project_manager.delete_project(project_id)
    if not success:
        raise HTTPException(status_code=404, detail="Project not found")

    return {"status": "deleted", "project_id": project_id}


@app.post("/api/projects/{project_id}/upload")
async def upload_to_project(project_id: str, file: UploadFile = File(...)):
    """Upload a file to a project."""
    project = project_manager.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    content = await file.read()
    file_info = project_manager.add_file(project_id, file.filename, content)

    return {
        "status": "uploaded",
        "file": file_info,
        "message": f"File uploaded to project '{project.name}'"
    }


@app.post("/api/projects/{project_id}/upload/multiple")
async def upload_multiple_to_project(project_id: str, files: List[UploadFile] = File(...)):
    """Upload multiple files to a project."""
    project = project_manager.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    uploaded = []
    for file in files:
        content = await file.read()
        file_info = project_manager.add_file(project_id, file.filename, content)
        uploaded.append(file_info)

    return {
        "status": "uploaded",
        "files": uploaded,
        "count": len(uploaded),
        "message": f"{len(uploaded)} files uploaded to project '{project.name}'"
    }


@app.get("/api/projects/{project_id}/files")
async def list_project_files(project_id: str):
    """List all files in a project."""
    project = project_manager.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    files = project_manager.list_files(project_id)
    return {"files": files, "count": len(files)}


@app.delete("/api/projects/{project_id}/files/{file_path:path}")
async def delete_project_file(project_id: str, file_path: str):
    """Delete a file from a project."""
    success = project_manager.delete_file(project_id, file_path)
    if not success:
        raise HTTPException(status_code=404, detail="File not found")

    return {"status": "deleted", "file": file_path}


def _generate_python_from_scan(scan_type: str, scan_result, vulnerabilities) -> str:
    """Generate Python code representing the scan results for AI analysis."""
    lines = [
        '"""',
        f'Security Scan Results - {scan_type.upper()}',
        f'Generated for AI vulnerability analysis',
        '"""',
        '',
        '# Scan Configuration',
        f'SCAN_TYPE = "{scan_type}"',
        f'HOSTS_SCANNED = {len(scan_result.hosts) if hasattr(scan_result, "hosts") else 0}',
        '',
        '# Discovered Hosts',
        'hosts = ['
    ]

    if hasattr(scan_result, 'hosts'):
        for host in scan_result.hosts:
            lines.append(f'    "{host.ip}",  # {getattr(host, "hostname", "") or "unknown"}')
    lines.append(']')
    lines.append('')

    lines.append('# Discovered Vulnerabilities')
    lines.append('vulnerabilities = [')

    for vuln in vulnerabilities:
        lines.append('    {')
        lines.append(f'        "title": """{vuln.title}""",')
        lines.append(f'        "severity": "{vuln.severity.value}",')
        lines.append(f'        "cvss_score": {vuln.cvss_score},')
        lines.append(f'        "host": "{vuln.affected_host}",')
        lines.append(f'        "port": {vuln.affected_port},')
        lines.append(f'        "service": "{vuln.affected_service}",')
        if vuln.cve_id:
            lines.append(f'        "cve": "{vuln.cve_id}",')
        if vuln.description:
            desc = vuln.description.replace('"""', '\\"\\"\\"').replace('\n', ' ')[:500]
            lines.append(f'        "description": """{desc}""",')
        if vuln.remediation:
            rem = vuln.remediation.replace('"""', '\\"\\"\\"').replace('\n', ' ')[:300]
            lines.append(f'        "remediation": """{rem}""",')
        lines.append('    },')

    lines.append(']')
    lines.append('')
    lines.append('# Security Issues Summary')
    lines.append(f'TOTAL_VULNERABILITIES = {len(vulnerabilities)}')

    # Count by severity
    severity_counts = {}
    for v in vulnerabilities:
        sev = v.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines.append(f'CRITICAL_COUNT = {severity_counts.get("critical", 0)}')
    lines.append(f'HIGH_COUNT = {severity_counts.get("high", 0)}')
    lines.append(f'MEDIUM_COUNT = {severity_counts.get("medium", 0)}')
    lines.append(f'LOW_COUNT = {severity_counts.get("low", 0)}')

    return '\n'.join(lines)


@app.post("/api/projects/{project_id}/import-scan")
async def import_scan_to_project(
    project_id: str,
    file: UploadFile = File(...),
    enrich: bool = Form(True)
):
    """
    Import a Nmap or Nessus scan file into a project.

    1. Parses the XML scan file
    2. Generates a temporary .py file with vulnerabilities
    3. Runs AI analysis on the .py file
    4. Deletes the .py file after analysis
    """
    project = project_manager.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    global nmap_parser, nessus_parser

    # Initialize parsers if needed
    if nmap_parser is None:
        nmap_parser = NmapParser()
    if nessus_parser is None:
        nessus_parser = NessusParser()

    # Read file content
    content = await file.read()

    # Detect scan type
    scan_type = _detect_scan_type(file.filename, content)

    if scan_type == 'unknown':
        return {
            "status": "error",
            "message": "File not recognized as Nmap or Nessus scan."
        }

    # Save XML temporarily to parse
    temp_xml_path = UPLOAD_DIR / f"temp_{uuid.uuid4().hex[:8]}_{file.filename}"
    with open(temp_xml_path, 'wb') as f:
        f.write(content)

    try:
        # Parse the scan file
        if scan_type == 'nmap':
            scan_result = nmap_parser.parse_file(str(temp_xml_path))
            vulnerabilities = nmap_parser.extract_vulnerabilities(scan_result)
        else:  # nessus
            scan_result = nessus_parser.parse_file(str(temp_xml_path))
            vulnerabilities = nessus_parser.extract_vulnerabilities(scan_result)

        if not vulnerabilities:
            return {
                "status": "completed",
                "scan_type": scan_type,
                "vulnerabilities_found": 0,
                "message": "Scan parsed but no vulnerabilities found."
            }

        # Generate Python file from scan results
        py_content = _generate_python_from_scan(scan_type, scan_result, vulnerabilities)

        # Save .py file to project for AI analysis
        base_name = Path(file.filename).stem
        py_filename = f"{base_name}_scan.py"
        py_path = Path(f"data/projects/{project_id}") / py_filename
        py_path.parent.mkdir(parents=True, exist_ok=True)

        with open(py_path, 'w', encoding='utf-8') as f:
            f.write(py_content)

        logger.info(f"Generated {py_filename} for AI analysis")

        # Run AI scan on the generated .py file
        ai_vulns = []
        try:
            ai_vulns = ai_scanner.scan_file(str(py_path))
            logger.info(f"AI scan found {len(ai_vulns)} additional findings")

            for v in ai_vulns:
                v["source_file"] = py_filename
                v["project_id"] = project_id
        except Exception as e:
            logger.warning(f"AI scan failed: {e}")

        # Delete the .py file after analysis
        if py_path.exists():
            py_path.unlink()
            logger.info(f"Deleted temporary file {py_filename}")

        # Convert parsed vulnerabilities to dicts
        vuln_dicts = []
        for vuln in vulnerabilities:
            vuln_dict = vuln.to_dict()
            vuln_dict['affected_file'] = f"{vuln_dict.get('affected_host', 'unknown')}:{vuln_dict.get('affected_port', 0)}"
            vuln_dict['project_id'] = project_id
            vuln_dicts.append(vuln_dict)

        # Enrich if requested
        enriched_count = 0
        if enrich and vulnerability_enricher and vuln_dicts:
            for i, vuln_dict in enumerate(vuln_dicts):
                try:
                    result = vulnerability_enricher.enrich_vulnerability(vuln_dict)
                    vuln_dicts[i] = vulnerability_enricher.to_enriched_vulnerability(result)
                    enriched_count += 1
                except Exception as e:
                    logger.warning(f"Failed to enrich vulnerability: {e}")

        # Combine parsed vulns + AI findings
        all_vulns = vuln_dicts + ai_vulns

        # Add to data manager
        if all_vulns:
            data_manager.add_vulnerabilities(all_vulns)

        # Record scan
        scan_record = {
            "id": str(uuid.uuid4())[:8],
            "type": f"{scan_type}_import",
            "project_id": project_id,
            "filename": file.filename,
            "scanner": scan_type,
            "hosts_scanned": len(scan_result.hosts) if hasattr(scan_result, 'hosts') else 0,
            "vulnerabilities_parsed": len(vuln_dicts),
            "vulnerabilities_ai": len(ai_vulns),
            "vulnerabilities_enriched": enriched_count,
            "imported_at": datetime.now().isoformat()
        }
        data_manager.add_scan_record(scan_record)

        # Update project stats
        project_manager.record_scan(project_id, len(all_vulns))

        return {
            "status": "imported",
            "scan_type": scan_type,
            "hosts_found": len(scan_result.hosts) if hasattr(scan_result, 'hosts') else 0,
            "vulnerabilities_parsed": len(vuln_dicts),
            "vulnerabilities_ai": len(ai_vulns),
            "vulnerabilities_total": len(all_vulns),
            "vulnerabilities_enriched": enriched_count,
            "message": f"Imported {len(all_vulns)} vulnerabilities from {scan_type.upper()} scan."
        }

    except Exception as e:
        logger.error(f"Failed to parse {scan_type} scan: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse {scan_type} scan: {str(e)}"
        )
    finally:
        # Clean up temp XML file
        if temp_xml_path.exists():
            temp_xml_path.unlink()


# ============================================
# Scan Endpoints
# ============================================

@app.post("/api/scan")
async def start_scan(background_tasks: BackgroundTasks, request: ScanRequest):
    """
    Start AI-powered vulnerability scan on uploaded files.

    The AI will analyze the code and detect:
    - SQL Injection
    - XSS vulnerabilities
    - Command Injection
    - Hardcoded credentials
    - Insecure configurations
    - And more...
    """
    job_id = str(uuid.uuid4())[:8]

    scan_jobs[job_id] = {
        "id": job_id,
        "status": "running",
        "progress": 0,
        "message": "Initializing AI scanner...",
        "started_at": datetime.now().isoformat(),
        "model": request.model,
        "vulnerabilities_found": 0
    }

    # Run scan in background
    background_tasks.add_task(run_ai_scan, job_id, request)

    return {
        "job_id": job_id,
        "status": "started",
        "message": "AI scan started. Poll /api/scan/{job_id} for progress."
    }


async def run_ai_scan(job_id: str, request: ScanRequest):
    """Background task to run AI vulnerability scan."""
    job = scan_jobs[job_id]

    try:
        # Update scanner model if different
        logger.info(f"[MAIN] Starting scan job {job_id} with model: {request.model}")
        if request.model != ai_scanner.config.model:
            logger.info(f"[MAIN] Updating model from {ai_scanner.config.model} to {request.model}")
            ai_scanner.config.model = request.model

        job["message"] = "Scanning files with AI..."
        job["progress"] = 10

        all_vulnerabilities = []
        scan_files_to_process = []  # .nessus and .nmap files

        # Get files to scan
        if request.project_id:
            # Scan from project
            logger.info(f"[MAIN] Scanning project: {request.project_id}")
            files_to_scan = project_manager.get_scannable_files(
                request.project_id,
                request.file_ids if request.file_ids else None
            )
            scan_source = f"project:{request.project_id}"

            # Also look for .nessus and .nmap files in the project
            project_dir = Path(f"data/projects/{request.project_id}")
            if project_dir.exists():
                for ext in ['.nessus', '.nmap']:
                    for scan_file in project_dir.glob(f"*{ext}"):
                        scan_files_to_process.append(scan_file)
                        logger.info(f"[MAIN] Found scan file: {scan_file.name}")
        else:
            # Legacy: scan from uploads directory
            logger.info(f"[MAIN] Looking for files in: {UPLOAD_DIR}")
            if request.file_ids:
                # Scan specific files
                files_to_scan = [
                    f for f in UPLOAD_DIR.glob("*")
                    if any(fid in f.name for fid in request.file_ids)
                ]
            else:
                # Scan all uploaded files
                files_to_scan = list(UPLOAD_DIR.glob("*"))
            scan_source = "uploads"

            # Also look for .nessus and .nmap files in uploads
            for ext in ['.nessus', '.nmap']:
                for scan_file in UPLOAD_DIR.glob(f"*{ext}"):
                    scan_files_to_process.append(scan_file)

        logger.info(f"[MAIN] Found {len(files_to_scan)} code files + {len(scan_files_to_process)} scan files from {scan_source}")

        # Process .nessus and .nmap files first
        if scan_files_to_process:
            global nmap_parser, nessus_parser
            if nmap_parser is None:
                nmap_parser = NmapParser()
            if nessus_parser is None:
                nessus_parser = NessusParser()

            job["message"] = "Processing scan files (Nmap/Nessus)..."

            for scan_file in scan_files_to_process:
                try:
                    logger.info(f"[MAIN] Processing scan file: {scan_file.name}")
                    ext = scan_file.suffix.lower()

                    # Parse the scan file
                    if ext == '.nmap' or (ext == '.xml' and 'nmap' in scan_file.name.lower()):
                        scan_result = nmap_parser.parse_file(str(scan_file))
                        vulnerabilities = nmap_parser.extract_vulnerabilities(scan_result)
                        scan_type = 'nmap'
                    else:  # .nessus
                        scan_result = nessus_parser.parse_file(str(scan_file))
                        vulnerabilities = nessus_parser.extract_vulnerabilities(scan_result)
                        scan_type = 'nessus'

                    logger.info(f"[MAIN] Parsed {len(vulnerabilities)} vulnerabilities from {scan_file.name}")

                    # Convert to dicts and add to all_vulnerabilities
                    for vuln in vulnerabilities:
                        vuln_dict = vuln.to_dict()
                        vuln_dict['affected_file'] = f"{vuln_dict.get('affected_host', 'unknown')}:{vuln_dict.get('affected_port', 0)}"
                        vuln_dict['source_file'] = scan_file.name
                        vuln_dict['scan_type'] = scan_type
                        if request.project_id:
                            vuln_dict['project_id'] = request.project_id
                        all_vulnerabilities.append(vuln_dict)

                    # Generate .py file for AI analysis
                    if vulnerabilities:
                        py_content = _generate_python_from_scan(scan_type, scan_result, vulnerabilities)
                        py_filename = f"{scan_file.stem}_scan.py"
                        py_path = scan_file.parent / py_filename

                        with open(py_path, 'w', encoding='utf-8') as f:
                            f.write(py_content)

                        # Add to files_to_scan for AI analysis
                        files_to_scan.append(py_path)
                        logger.info(f"[MAIN] Generated {py_filename} for AI analysis")

                except Exception as e:
                    logger.error(f"[MAIN] Failed to process scan file {scan_file.name}: {e}")

        if not files_to_scan and not all_vulnerabilities:
            logger.warning("[MAIN] No files to scan!")
            job["status"] = "completed"
            job["progress"] = 100
            job["message"] = "No files to scan"
            return

        total_files = len(files_to_scan)

        for i, file_path in enumerate(files_to_scan):
            if file_path.is_file():
                logger.info(f"[MAIN] Processing file {i+1}/{total_files}: {file_path.name}")
                job["message"] = f"Scanning {file_path.name}..."
                job["progress"] = 10 + int((i / total_files) * 80)

                # Run AI scan
                vulns = ai_scanner.scan_file(str(file_path))
                logger.info(f"[MAIN] Scan returned {len(vulns)} vulnerabilities for {file_path.name}")

                for v in vulns:
                    v["source_file"] = file_path.name
                    if request.project_id:
                        v["project_id"] = request.project_id
                    all_vulnerabilities.append(v)

                # Small delay to not overwhelm Ollama
                await asyncio.sleep(0.5)

        job["progress"] = 90
        job["message"] = "Enriching vulnerabilities with CVE and MITRE data..."

        # Enrich vulnerabilities with CVE/MITRE data
        enriched_vulnerabilities = []
        if all_vulnerabilities and vulnerability_enricher:
            for vuln in all_vulnerabilities:
                try:
                    result = vulnerability_enricher.enrich_vulnerability(vuln)
                    enriched_vuln = vulnerability_enricher.to_enriched_vulnerability(result)
                    enriched_vulnerabilities.append(enriched_vuln)
                except Exception as e:
                    logger.warning(f"Failed to enrich vulnerability: {e}")
                    enriched_vulnerabilities.append(vuln)
        else:
            enriched_vulnerabilities = all_vulnerabilities

        job["progress"] = 95
        job["message"] = "Saving results..."

        # Add enriched vulnerabilities to data manager
        if enriched_vulnerabilities:
            data_manager.add_vulnerabilities(enriched_vulnerabilities)

        # Record scan
        scan_record = {
            "id": job_id,
            "files_scanned": total_files,
            "vulnerabilities_found": len(enriched_vulnerabilities),
            "vulnerabilities_enriched": sum(1 for v in enriched_vulnerabilities if v.get("enrichment")),
            "model": request.model,
            "source": scan_source
        }
        if request.project_id:
            scan_record["project_id"] = request.project_id
            # Update project stats
            project_manager.record_scan(request.project_id, len(enriched_vulnerabilities))

        data_manager.add_scan_record(scan_record)

        job["status"] = "completed"
        job["progress"] = 100
        job["vulnerabilities_found"] = len(all_vulnerabilities)
        job["message"] = f"Scan complete. Found {len(all_vulnerabilities)} vulnerabilities."
        job["completed_at"] = datetime.now().isoformat()

        # Clean up generated .py files from scan imports
        if scan_files_to_process:
            for scan_file in scan_files_to_process:
                py_path = scan_file.parent / f"{scan_file.stem}_scan.py"
                if py_path.exists():
                    py_path.unlink()
                    logger.info(f"[MAIN] Deleted temporary file {py_path.name}")

    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)
        job["message"] = f"Scan failed: {str(e)}"


@app.get("/api/scan/{job_id}")
async def get_scan_status(job_id: str):
    """Get scan job status."""
    if job_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return scan_jobs[job_id]


@app.get("/api/scans")
async def get_scan_history():
    """Get scan history."""
    return {"scans": data_manager.get_scan_history()}


# ============================================
# External Scan Import Endpoints (Nmap/Nessus)
# ============================================

@app.post("/api/scan/import")
async def import_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    scan_type: Optional[str] = Form(None),
    enrich: bool = Form(True)
):
    """
    Import and parse external scan results (Nmap or Nessus).

    Accepts:
    - Nmap XML files (.xml)
    - Nmap JSON files (.json)
    - Nessus files (.nessus)
    - Nessus JSON exports (.json)

    The scan type is auto-detected from the file content, or can be
    specified explicitly with scan_type parameter.
    """
    global nmap_parser, nessus_parser

    # Initialize parsers if needed
    if nmap_parser is None:
        nmap_parser = NmapParser()
    if nessus_parser is None:
        nessus_parser = NessusParser()

    # Read file content
    content = await file.read()

    # Detect or validate scan type
    detected_type = _detect_scan_type(file.filename, content)

    if scan_type:
        scan_type = scan_type.lower()
        if scan_type not in ['nmap', 'nessus']:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scan_type '{scan_type}'. Use 'nmap' or 'nessus'."
            )
    else:
        scan_type = detected_type

    if scan_type == 'unknown':
        raise HTTPException(
            status_code=400,
            detail="Could not detect scan type. Please specify scan_type='nmap' or 'nessus'."
        )

    # Save file temporarily
    temp_path = UPLOAD_DIR / f"import_{uuid.uuid4().hex[:8]}_{file.filename}"
    with open(temp_path, 'wb') as f:
        f.write(content)

    try:
        # Parse the scan file
        if scan_type == 'nmap':
            scan_result = nmap_parser.parse_file(str(temp_path))
            vulnerabilities = nmap_parser.extract_vulnerabilities(scan_result)
        else:  # nessus
            scan_result = nessus_parser.parse_file(str(temp_path))
            vulnerabilities = nessus_parser.extract_vulnerabilities(scan_result)

        # Convert Vulnerability objects to dicts for data_manager
        vuln_dicts = []
        for vuln in vulnerabilities:
            vuln_dict = vuln.to_dict()
            # Ensure we have an affected_file field for UI compatibility
            if not vuln_dict.get('affected_file'):
                vuln_dict['affected_file'] = f"{vuln_dict.get('affected_host', 'unknown')}:{vuln_dict.get('affected_port', 0)}"
            vuln_dicts.append(vuln_dict)

        # Enrich vulnerabilities if requested
        enriched_count = 0
        if enrich and vulnerability_enricher and vuln_dicts:
            for i, vuln_dict in enumerate(vuln_dicts):
                try:
                    result = vulnerability_enricher.enrich_vulnerability(vuln_dict)
                    vuln_dicts[i] = vulnerability_enricher.to_enriched_vulnerability(result)
                    enriched_count += 1
                except Exception as e:
                    logger.warning(f"Failed to enrich vulnerability: {e}")

        # Add to data manager
        if vuln_dicts:
            data_manager.add_vulnerabilities(vuln_dicts)

        # Record scan
        scan_record = {
            "id": str(uuid.uuid4())[:8],
            "type": f"{scan_type}_import",
            "filename": file.filename,
            "scanner": scan_type,
            "hosts_scanned": len(scan_result.hosts) if hasattr(scan_result, 'hosts') else 0,
            "vulnerabilities_found": len(vuln_dicts),
            "vulnerabilities_enriched": enriched_count,
            "imported_at": datetime.now().isoformat()
        }
        data_manager.add_scan_record(scan_record)

        return {
            "status": "imported",
            "scan_type": scan_type,
            "filename": file.filename,
            "hosts_found": len(scan_result.hosts) if hasattr(scan_result, 'hosts') else 0,
            "vulnerabilities_found": len(vuln_dicts),
            "vulnerabilities_enriched": enriched_count,
            "message": f"Successfully imported {len(vuln_dicts)} vulnerabilities from {scan_type.upper()} scan."
        }

    except Exception as e:
        logger.error(f"Failed to parse {scan_type} scan: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse {scan_type} scan: {str(e)}"
        )
    finally:
        # Clean up temp file
        if temp_path.exists():
            temp_path.unlink()


@app.post("/api/scan/import/multiple")
async def import_multiple_scans(
    files: List[UploadFile] = File(...),
    enrich: bool = Form(True)
):
    """
    Import multiple scan files at once.

    Auto-detects the type of each file (Nmap or Nessus).
    """
    results = []
    total_vulns = 0

    for file in files:
        try:
            # Re-read the file for each upload
            content = await file.read()
            await file.seek(0)  # Reset for potential re-read

            # Create a mock request and call import_scan logic inline
            detected_type = _detect_scan_type(file.filename, content)

            if detected_type == 'unknown':
                results.append({
                    "filename": file.filename,
                    "status": "skipped",
                    "error": "Unknown scan type"
                })
                continue

            # Process inline (simplified version)
            global nmap_parser, nessus_parser
            if nmap_parser is None:
                nmap_parser = NmapParser()
            if nessus_parser is None:
                nessus_parser = NessusParser()

            temp_path = UPLOAD_DIR / f"import_{uuid.uuid4().hex[:8]}_{file.filename}"
            with open(temp_path, 'wb') as f:
                f.write(content)

            try:
                if detected_type == 'nmap':
                    scan_result = nmap_parser.parse_file(str(temp_path))
                    vulnerabilities = nmap_parser.extract_vulnerabilities(scan_result)
                else:
                    scan_result = nessus_parser.parse_file(str(temp_path))
                    vulnerabilities = nessus_parser.extract_vulnerabilities(scan_result)

                vuln_dicts = []
                for vuln in vulnerabilities:
                    vuln_dict = vuln.to_dict()
                    if not vuln_dict.get('affected_file'):
                        vuln_dict['affected_file'] = f"{vuln_dict.get('affected_host', 'unknown')}:{vuln_dict.get('affected_port', 0)}"
                    vuln_dicts.append(vuln_dict)

                enriched_count = 0
                if enrich and vulnerability_enricher and vuln_dicts:
                    for i, vuln_dict in enumerate(vuln_dicts):
                        try:
                            result = vulnerability_enricher.enrich_vulnerability(vuln_dict)
                            vuln_dicts[i] = vulnerability_enricher.to_enriched_vulnerability(result)
                            enriched_count += 1
                        except:
                            pass

                if vuln_dicts:
                    data_manager.add_vulnerabilities(vuln_dicts)

                total_vulns += len(vuln_dicts)

                results.append({
                    "filename": file.filename,
                    "status": "imported",
                    "scan_type": detected_type,
                    "vulnerabilities": len(vuln_dicts),
                    "enriched": enriched_count
                })

            finally:
                if temp_path.exists():
                    temp_path.unlink()

        except Exception as e:
            results.append({
                "filename": file.filename,
                "status": "failed",
                "error": str(e)
            })

    return {
        "status": "completed",
        "files_processed": len(files),
        "total_vulnerabilities": total_vulns,
        "results": results
    }


# ============================================
# Vulnerability Endpoints
# ============================================

@app.get("/api/vulnerabilities")
async def get_vulnerabilities(
    severity: Optional[str] = None,
    type: Optional[str] = None,
    file: Optional[str] = None,
    search: Optional[str] = None,
    project_id: Optional[str] = None,
    sort_by: str = "severity",
    sort_order: str = "desc",
    page: int = 1,
    page_size: int = 20
):
    """Get discovered vulnerabilities with filtering."""
    vulns = data_manager.get_vulnerabilities(project_id).copy()

    # Apply filters
    if severity:
        severities = severity.lower().split(",")
        vulns = [v for v in vulns if v.get("severity", "").lower() in severities]

    if type:
        vulns = [v for v in vulns if type.lower() in v.get("type", "").lower()]

    if file:
        vulns = [v for v in vulns if file.lower() in v.get("affected_file", "").lower()]

    if search:
        search_lower = search.lower()
        vulns = [v for v in vulns if
                 search_lower in v.get("title", "").lower() or
                 search_lower in v.get("description", "").lower() or
                 search_lower in v.get("type", "").lower()]

    # Sort
    reverse = sort_order.lower() == "desc"
    if sort_by == "severity":
        severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        vulns.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 0), reverse=reverse)
    elif sort_by == "cvss_score":
        vulns.sort(key=lambda x: x.get("cvss_score", 0), reverse=reverse)
    elif sort_by == "file":
        vulns.sort(key=lambda x: x.get("affected_file", ""), reverse=reverse)

    # Paginate
    total = len(vulns)
    start = (page - 1) * page_size
    end = start + page_size
    vulns = vulns[start:end]

    return {
        "items": vulns,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if total > 0 else 0
    }


@app.get("/api/vulnerabilities/{vuln_id}")
async def get_vulnerability(vuln_id: str):
    """Get single vulnerability details."""
    vuln = data_manager.get_vulnerability(vuln_id)
    if vuln:
        return vuln
    raise HTTPException(status_code=404, detail="Vulnerability not found")


@app.delete("/api/vulnerabilities")
async def clear_vulnerabilities():
    """Clear all vulnerability data (reset to empty)."""
    data_manager.clear_all_data()
    return {"status": "cleared", "message": "All vulnerability data cleared"}


@app.post("/api/vulnerabilities/{vuln_id}/enrich")
async def enrich_vulnerability(vuln_id: str):
    """
    Manually enrich a vulnerability with CVE and MITRE ATT&CK data.

    Uses semantic similarity and CWE mapping to find related CVEs
    and MITRE techniques.
    """
    vuln = data_manager.get_vulnerability(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    if not vulnerability_enricher:
        raise HTTPException(status_code=500, detail="Enricher not initialized")

    try:
        result = vulnerability_enricher.enrich_vulnerability(vuln)
        enriched_vuln = vulnerability_enricher.to_enriched_vulnerability(result)

        # Update the vulnerability in the data manager
        data_manager.update_vulnerability(vuln_id, enriched_vuln)

        return {
            "status": "enriched",
            "vulnerability": enriched_vuln,
            "enrichment_summary": {
                "cwes_found": len(result.matched_cwes),
                "cves_found": len(result.related_cves),
                "mitre_techniques": len(result.mitre_techniques),
                "mitre_tactics": result.mitre_tactics,
                "confidence": result.confidence_score,
                "estimated_severity": result.estimated_severity,
                "estimated_cvss": result.estimated_cvss
            }
        }
    except Exception as e:
        logger.error(f"Enrichment failed: {e}")
        raise HTTPException(status_code=500, detail=f"Enrichment failed: {str(e)}")


@app.post("/api/vulnerabilities/enrich-all")
async def enrich_all_vulnerabilities():
    """
    Enrich all existing vulnerabilities with CVE and MITRE ATT&CK data.

    This is useful for enriching vulnerabilities that were scanned
    before the enricher was available.
    """
    vulns = data_manager.get_vulnerabilities()

    if not vulns:
        return {"status": "no_data", "message": "No vulnerabilities to enrich"}

    if not vulnerability_enricher:
        raise HTTPException(status_code=500, detail="Enricher not initialized")

    enriched_count = 0
    errors = []

    for vuln in vulns:
        try:
            result = vulnerability_enricher.enrich_vulnerability(vuln)
            enriched_vuln = vulnerability_enricher.to_enriched_vulnerability(result)
            data_manager.update_vulnerability(vuln.get("id"), enriched_vuln)
            enriched_count += 1
        except Exception as e:
            errors.append({"id": vuln.get("id"), "error": str(e)})

    return {
        "status": "completed",
        "total": len(vulns),
        "enriched": enriched_count,
        "errors": len(errors),
        "error_details": errors[:10] if errors else []
    }


# ============================================
# Report Endpoints
# ============================================

@app.post("/api/reports/generate")
async def generate_reports(request: ReportRequest):
    """
    Generate security reports using AI.

    Types:
    - executive: High-level summary for management
    - technical: Detailed findings for security teams
    - both: Generate both reports

    If project_id is provided, only vulnerabilities from that project are included.
    """
    vulns = data_manager.get_vulnerabilities(request.project_id)

    if not vulns:
        if request.project_id:
            raise HTTPException(
                status_code=400,
                detail=f"No vulnerabilities found for project '{request.project_id}'. Run a scan first."
            )
        raise HTTPException(
            status_code=400,
            detail="No vulnerabilities to report. Run a scan first."
        )

    ai_reporter.config.organization = request.organization
    reports = []

    # Get project name if project_id is provided
    project_name = None
    if request.project_id:
        project = project_manager.get_project(request.project_id)
        if project:
            project_name = project.name

    if request.report_type in ["executive", "both"]:
        report = ai_reporter.generate_executive_report(vulns, request.organization, request.project_id, project_name)
        data_manager.add_report(report)
        reports.append(report)

    if request.report_type in ["technical", "both"]:
        report = ai_reporter.generate_technical_report(vulns, request.organization, request.project_id, project_name)
        data_manager.add_report(report)
        reports.append(report)

    return {
        "status": "completed",
        "reports": reports,
        "project_id": request.project_id,
        "message": f"Generated {len(reports)} report(s)" + (f" for project '{project_name}'" if project_name else "")
    }


@app.get("/api/reports")
async def list_reports():
    """List generated reports."""
    reports = data_manager.get_reports()

    # Also check filesystem for reports
    reports_dir = Path("data/reports")
    if reports_dir.exists():
        for f in reports_dir.glob("*.md"):
            if not any(r.get("filename") == f.name for r in reports):
                reports.append({
                    "filename": f.name,
                    "type": "executive" if "executive" in f.name else "technical",
                    "size": f.stat().st_size,
                    "generated_at": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                })

    return {"reports": sorted(reports, key=lambda x: x.get("generated_at", ""), reverse=True)}


@app.get("/api/reports/{filename}")
async def download_report(filename: str):
    """Download a report file."""
    filepath = Path("data/reports") / filename

    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    return FileResponse(filepath, filename=filename, media_type="text/markdown")


# ============================================
# NVD API Endpoints
# ============================================

@app.post("/api/nvd/fetch")
async def fetch_nvd_cves(background_tasks: BackgroundTasks, request: NVDFetchRequest):
    """
    Fetch CVEs from the National Vulnerability Database (NVD).

    This fetches real CVE data from NIST NVD API 2.0.
    Results are added to the vulnerability database.
    """
    job_id = f"nvd-{str(uuid.uuid4())[:8]}"

    fetch_jobs[job_id] = {
        "id": job_id,
        "type": "nvd",
        "status": "running",
        "progress": 0,
        "message": "Connecting to NVD API...",
        "started_at": datetime.now().isoformat(),
        "cves_fetched": 0
    }

    background_tasks.add_task(run_nvd_fetch, job_id, request)

    return {
        "job_id": job_id,
        "status": "started",
        "message": f"Fetching CVEs from last {request.days} days. Poll /api/nvd/fetch/{job_id} for progress."
    }


async def run_nvd_fetch(job_id: str, request: NVDFetchRequest):
    """Background task to fetch CVEs from NVD."""
    job = fetch_jobs[job_id]

    try:
        # Configure NVD client
        if request.api_key:
            nvd_client.config.api_key = request.api_key

        job["message"] = "Fetching CVEs from NVD..."
        job["progress"] = 10

        cves_added = 0
        from datetime import timedelta

        end_date = datetime.now()
        start_date = end_date - timedelta(days=request.days)

        # Fetch by severity if specified
        severities = [request.severity.upper()] if request.severity else ["CRITICAL", "HIGH"]

        for i, severity in enumerate(severities):
            job["message"] = f"Fetching {severity} CVEs..."
            job["progress"] = 10 + int((i / len(severities)) * 70)

            for cve in nvd_client.fetch_cves_by_date_range(start_date, end_date, severity):
                vuln = nvd_client.parse_cve_to_vulnerability(cve)
                data_manager.add_vulnerability(vuln)
                cves_added += 1
                job["cves_fetched"] = cves_added

                # Update progress periodically
                if cves_added % 10 == 0:
                    job["message"] = f"Fetching {severity} CVEs... ({cves_added} total)"

                # Yield control
                await asyncio.sleep(0.01)

        job["progress"] = 95
        job["message"] = "Saving results..."

        # Record fetch
        data_manager.add_scan_record({
            "id": job_id,
            "type": "nvd_fetch",
            "days": request.days,
            "cves_fetched": cves_added
        })

        job["status"] = "completed"
        job["progress"] = 100
        job["message"] = f"Fetched {cves_added} CVEs from NVD"
        job["completed_at"] = datetime.now().isoformat()

    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)
        job["message"] = f"NVD fetch failed: {str(e)}"


@app.get("/api/nvd/fetch/{job_id}")
async def get_nvd_fetch_status(job_id: str):
    """Get NVD fetch job status."""
    if job_id not in fetch_jobs:
        raise HTTPException(status_code=404, detail="Fetch job not found")
    return fetch_jobs[job_id]


@app.get("/api/nvd/search")
async def search_nvd(
    keyword: Optional[str] = None,
    cve_id: Optional[str] = None
):
    """Search NVD for specific CVEs."""
    if cve_id:
        cve = nvd_client.fetch_cve_by_id(cve_id)
        if cve:
            return {"cve": nvd_client.parse_cve_to_vulnerability(cve)}
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    if keyword:
        cves = nvd_client.fetch_cves_by_keyword(keyword)
        return {
            "keyword": keyword,
            "results": [nvd_client.parse_cve_to_vulnerability(c) for c in cves[:50]]
        }

    raise HTTPException(status_code=400, detail="Provide keyword or cve_id parameter")


@app.post("/api/nvd/add/{cve_id}")
async def add_cve_to_database(cve_id: str):
    """Fetch a specific CVE and add it to the vulnerability database."""
    cve = nvd_client.fetch_cve_by_id(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in NVD")

    vuln = nvd_client.parse_cve_to_vulnerability(cve)
    data_manager.add_vulnerability(vuln)

    return {
        "status": "added",
        "vulnerability": vuln
    }


# ============================================
# MITRE ATT&CK API Endpoints
# ============================================

@app.post("/api/mitre/fetch")
async def fetch_mitre_data(request: MITREFetchRequest):
    """
    Fetch MITRE ATT&CK data from the official STIX repository.

    This fetches real tactics, techniques, groups, and software
    from the MITRE CTI GitHub repository.
    """
    data = mitre_client.fetch_attack_data(force_refresh=request.force_refresh)

    return {
        "status": "completed",
        "stats": data.get("stats", {}),
        "source": data.get("source", ""),
        "fetched_at": data.get("fetched_at", ""),
        "message": f"Fetched {data.get('stats', {}).get('tactics_count', 0)} tactics, "
                   f"{data.get('stats', {}).get('techniques_count', 0)} techniques"
    }


@app.get("/api/mitre/tactics")
async def get_mitre_tactics():
    """Get MITRE ATT&CK tactics."""
    # First get tactics from discovered vulnerabilities
    vuln_tactics = data_manager.get_mitre_summary()

    # Also get full MITRE tactics list
    all_tactics = mitre_client.get_tactics()

    return {
        "vulnerability_mapping": vuln_tactics,
        "all_tactics": all_tactics
    }


@app.get("/api/mitre/techniques")
async def get_mitre_techniques(tactic: Optional[str] = None):
    """Get MITRE ATT&CK techniques, optionally filtered by tactic."""
    techniques = mitre_client.get_techniques(tactic)
    return {
        "techniques": techniques,
        "count": len(techniques),
        "filter": {"tactic": tactic} if tactic else None
    }


@app.get("/api/mitre/techniques/{technique_id}")
async def get_mitre_technique(technique_id: str):
    """Get a specific MITRE technique by ID."""
    technique = mitre_client.get_technique_by_id(technique_id)
    if technique:
        return technique
    raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")


@app.get("/api/mitre/groups")
async def get_mitre_groups():
    """Get MITRE ATT&CK threat groups."""
    groups = mitre_client.get_groups()
    return {
        "groups": groups,
        "count": len(groups)
    }


@app.get("/api/mitre/software")
async def get_mitre_software():
    """Get MITRE ATT&CK software (malware and tools)."""
    software = mitre_client.get_software()
    return {
        "software": software,
        "count": len(software)
    }


@app.get("/api/mitre/mitigations")
async def get_mitre_mitigations():
    """Get MITRE ATT&CK mitigations."""
    mitigations = mitre_client.get_mitigations()
    return {
        "mitigations": mitigations,
        "count": len(mitigations)
    }


@app.get("/api/mitre/search")
async def search_mitre(query: str):
    """Search across all MITRE ATT&CK data."""
    if len(query) < 2:
        raise HTTPException(status_code=400, detail="Query must be at least 2 characters")

    results = mitre_client.search(query)
    total = sum(len(v) for v in results.values())

    return {
        "query": query,
        "total_results": total,
        "results": results
    }


# ============================================
# Hosts Endpoints
# ============================================

@app.get("/api/hosts")
async def get_hosts(project_id: Optional[str] = None):
    """Get affected hosts/files summary, optionally filtered by project."""
    # For code scanning, "hosts" are really files
    files_data = {}

    for v in data_manager.get_vulnerabilities(project_id):
        file = v.get("affected_file", "Unknown")
        if file not in files_data:
            files_data[file] = {
                "ip": file,  # Using 'ip' for frontend compatibility
                "name": file,
                "project_id": v.get("project_id"),
                "vulnerabilities": [],
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}
            }
        files_data[file]["vulnerabilities"].append(v.get("id"))
        sev = v.get("severity", "low").lower()  # Normalize to lowercase
        if sev in files_data[file]["severity_counts"]:
            files_data[file]["severity_counts"][sev] += 1

    return {"hosts": list(files_data.values())}


# ============================================
# Configuration Endpoints
# ============================================

@app.post("/api/config/model")
async def set_model(config: AnalysisConfig):
    """Configure the AI model to use."""
    ai_scanner.config.model = config.model
    ai_scanner.config.ollama_url = config.ollama_url
    ai_reporter.config.model = config.model
    ai_reporter.config.ollama_url = config.ollama_url

    return {
        "status": "configured",
        "model": config.model,
        "ollama_url": config.ollama_url
    }


@app.get("/api/models")
async def list_models():
    """List available Ollama models."""
    try:
        import requests
        resp = requests.get(f"{ai_scanner.config.ollama_url}/api/tags", timeout=5)
        if resp.status_code == 200:
            models = resp.json().get("models", [])
            return {
                "models": [m.get("name") for m in models],
                "current": ai_scanner.config.model
            }
    except:
        pass

    return {
        "models": ["mistral", "llama2", "codellama", "phi"],
        "current": ai_scanner.config.model,
        "note": "Could not connect to Ollama. Showing default models."
    }


# Mount frontend static files
frontend_path = Path(__file__).parent.parent / "frontend"
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
