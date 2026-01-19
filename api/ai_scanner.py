"""
AI-Powered Vulnerability Scanner using Ollama.

Scans code and configuration files to detect security vulnerabilities.
Uses LLM to analyze code patterns, identify issues, and suggest fixes.
"""

import os
import json
import logging
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Try to import Ollama
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class ScanConfig:
    """Configuration for AI scanning."""
    ollama_url: str = "http://localhost:11434"
    model: str = "mistral"  # Default model
    temperature: float = 0.1  # Low temperature for consistent analysis
    max_file_size: int = 100000  # Max file size to scan (100KB)
    timeout: int = 3600  # Request timeout in seconds (1 hour)


class AIScanner:
    """
    AI-powered vulnerability scanner using Ollama LLM.

    Analyzes code files to detect:
    - SQL Injection
    - XSS (Cross-Site Scripting)
    - Command Injection
    - Path Traversal
    - Hardcoded Credentials
    - Insecure Configurations
    - Authentication Issues
    - And more...
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self._check_ollama()

    def _check_ollama(self) -> bool:
        """Check if Ollama is available."""
        if not HAS_REQUESTS:
            logger.error("requests library not installed")
            return False

        try:
            response = requests.get(
                f"{self.config.ollama_url}/api/tags",
                timeout=5
            )
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [m.get('name', '').split(':')[0] for m in models]
                logger.info(f"Ollama available. Models: {model_names}")
                return True
        except Exception as e:
            logger.warning(f"Ollama not available: {e}")
        return False

    def _call_ollama(self, prompt: str) -> Optional[str]:
        """Call Ollama API with a prompt."""
        if not HAS_REQUESTS:
            logger.error("[OLLAMA] requests library not available")
            return None

        try:
            logger.info(f"[OLLAMA] Sending request to {self.config.ollama_url}/api/generate")
            logger.info(f"[OLLAMA] Model: {self.config.model}, Prompt length: {len(prompt)}")

            response = requests.post(
                f"{self.config.ollama_url}/api/generate",
                json={
                    "model": self.config.model,
                    "prompt": prompt,
                    "temperature": self.config.temperature,
                    "stream": False
                },
                timeout=self.config.timeout
            )

            logger.info(f"[OLLAMA] Response status: {response.status_code}")

            if response.status_code == 200:
                result = response.json().get('response', '')
                logger.info(f"[OLLAMA] Success! Response length: {len(result)}")
                return result
            else:
                logger.error(f"[OLLAMA] Error {response.status_code}: {response.text[:500]}")
        except Exception as e:
            logger.error(f"[OLLAMA] Request failed: {e}")
        return None

    def scan_code(self, code: str, filename: str, language: str = "auto") -> List[Dict[str, Any]]:
        """
        Scan code content for vulnerabilities using AI.

        Args:
            code: Source code content
            filename: Name of the file being scanned
            language: Programming language (auto-detected if not specified)

        Returns:
            List of detected vulnerabilities
        """
        logger.info(f"[SCAN] Starting scan for {filename}, code length: {len(code) if code else 0} chars")

        if not code or len(code) > self.config.max_file_size:
            logger.warning(f"Skipping {filename}: empty or too large (size: {len(code) if code else 0})")
            return []

        # Auto-detect language from extension
        if language == "auto":
            language = self._detect_language(filename)

        logger.info(f"[SCAN] Detected language: {language}")

        # Build the analysis prompt
        prompt = self._build_scan_prompt(code, filename, language)
        logger.info(f"[SCAN] Built prompt, length: {len(prompt)} chars")
        logger.debug(f"[SCAN] Code preview: {code[:500]}...")

        # Call AI for analysis
        logger.info(f"[SCAN] Calling Ollama with model: {self.config.model} at {self.config.ollama_url}")
        response = self._call_ollama(prompt)

        if not response:
            logger.warning(f"[SCAN] No response from AI for {filename}")
            return []

        logger.info(f"[SCAN] Got response from AI, length: {len(response)} chars")
        logger.debug(f"[SCAN] Response preview: {response[:500]}...")

        # Parse AI response into vulnerabilities
        vulnerabilities = self._parse_vulnerabilities(response, filename)
        logger.info(f"[SCAN] Found {len(vulnerabilities)} vulnerabilities in {filename}")

        return vulnerabilities

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a file for vulnerabilities."""
        path = Path(file_path)
        logger.info(f"[FILE] Attempting to scan file: {file_path}")

        if not path.exists():
            logger.error(f"[FILE] File not found: {file_path}")
            return []

        # Check file size
        file_size = path.stat().st_size
        logger.info(f"[FILE] File size: {file_size} bytes")

        if file_size > self.config.max_file_size:
            logger.warning(f"[FILE] File too large: {file_path} ({file_size} > {self.config.max_file_size})")
            return []

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            logger.info(f"[FILE] Read {len(code)} characters from {path.name}")
            return self.scan_code(code, path.name)
        except Exception as e:
            logger.error(f"[FILE] Failed to read {file_path}: {e}")
            return []

    def scan_directory(self, dir_path: str, extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Scan a directory for vulnerabilities.

        Args:
            dir_path: Path to directory
            extensions: File extensions to scan (e.g., ['.py', '.js'])

        Returns:
            List of all detected vulnerabilities
        """
        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.jsx', '.tsx', '.php', '.java',
                         '.rb', '.go', '.c', '.cpp', '.cs', '.sql', '.xml',
                         '.yaml', '.yml', '.json', '.env', '.conf', '.ini']

        path = Path(dir_path)
        if not path.exists():
            logger.error(f"Directory not found: {dir_path}")
            return []

        all_vulnerabilities = []

        for file_path in path.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in extensions:
                # Skip common non-essential directories
                if any(skip in str(file_path) for skip in ['node_modules', '__pycache__', '.git', 'venv', 'dist', 'build']):
                    continue

                vulns = self.scan_file(str(file_path))
                for v in vulns:
                    v['file_path'] = str(file_path.relative_to(path))
                all_vulnerabilities.extend(vulns)

        return all_vulnerabilities

    def _detect_language(self, filename: str) -> str:
        """Detect programming language from filename."""
        ext_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.jsx': 'React/JavaScript',
            '.tsx': 'React/TypeScript',
            '.php': 'PHP',
            '.java': 'Java',
            '.rb': 'Ruby',
            '.go': 'Go',
            '.c': 'C',
            '.cpp': 'C++',
            '.cs': 'C#',
            '.sql': 'SQL',
            '.xml': 'XML',
            '.html': 'HTML',
            '.yaml': 'YAML',
            '.yml': 'YAML',
            '.json': 'JSON',
            '.env': 'Environment Config',
            '.conf': 'Configuration',
            '.ini': 'INI Config'
        }
        ext = Path(filename).suffix.lower()
        return ext_map.get(ext, 'Unknown')

    def _build_scan_prompt(self, code: str, filename: str, language: str) -> str:
        """Build the prompt for vulnerability analysis."""
        return f"""You are a security expert analyzing code for vulnerabilities.
Analyze the following {language} code from file "{filename}" and identify ALL security vulnerabilities.

For EACH vulnerability found, provide:
1. Type (e.g., SQL Injection, XSS, Command Injection, Hardcoded Credentials, etc.)
2. Severity (critical, high, medium, low)
3. Line number or location
4. Description of the vulnerability
5. The vulnerable code snippet
6. Specific remediation/fix with code example

CODE TO ANALYZE:
```{language.lower()}
{code[:50000]}
```

RESPOND IN THIS EXACT JSON FORMAT:
{{
    "vulnerabilities": [
        {{
            "type": "vulnerability type",
            "severity": "critical|high|medium|low",
            "title": "short title",
            "description": "detailed description",
            "location": "line number or function name",
            "vulnerable_code": "the problematic code",
            "cwe_id": "CWE-XXX if applicable",
            "remediation": "how to fix it",
            "fixed_code": "corrected code example"
        }}
    ],
    "summary": "brief summary of findings"
}}

If no vulnerabilities are found, return: {{"vulnerabilities": [], "summary": "No vulnerabilities detected"}}

IMPORTANT: Only report REAL security issues. Do not report style issues or minor warnings.
Respond ONLY with the JSON, no other text."""

    def _parse_vulnerabilities(self, response: str, filename: str) -> List[Dict[str, Any]]:
        """Parse AI response into vulnerability dictionaries."""
        vulnerabilities = []

        # Try to extract JSON from response
        try:
            # Find JSON in response
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())
                vulns = data.get('vulnerabilities', [])

                for i, v in enumerate(vulns):
                    vuln = {
                        'id': f"VULN-{datetime.now().strftime('%Y%m%d%H%M%S')}-{i+1:03d}",
                        'title': v.get('title', v.get('type', 'Unknown Vulnerability')),
                        'description': v.get('description', ''),
                        'severity': v.get('severity', 'medium').lower(),
                        'type': v.get('type', 'Unknown'),
                        'cwe_id': v.get('cwe_id'),
                        'affected_file': filename,
                        'location': v.get('location', 'Unknown'),
                        'vulnerable_code': v.get('vulnerable_code', ''),
                        'remediation': v.get('remediation', ''),
                        'fixed_code': v.get('fixed_code', ''),
                        'source': 'ai_scan',
                        'model': self.config.model,
                        'cvss_score': self._severity_to_cvss(v.get('severity', 'medium')),
                        'exploit_available': v.get('severity', '').lower() in ['critical', 'high'],
                        'patch_available': bool(v.get('fixed_code')),
                        'mitre_tactics': self._map_to_mitre_tactics(v.get('type', '')),
                        'mitre_techniques': self._map_to_mitre_techniques(v.get('type', ''))
                    }
                    vulnerabilities.append(vuln)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            # Try to extract information from free text
            vulnerabilities = self._parse_freetext_response(response, filename)

        return vulnerabilities

    def _parse_freetext_response(self, response: str, filename: str) -> List[Dict[str, Any]]:
        """Fallback parser for non-JSON responses."""
        vulnerabilities = []

        # Simple pattern matching for common vulnerability mentions
        severity_patterns = {
            'critical': r'critical|severe|dangerous',
            'high': r'high|important|serious',
            'medium': r'medium|moderate',
            'low': r'low|minor|informational'
        }

        vuln_types = [
            'SQL Injection', 'XSS', 'Cross-Site Scripting', 'Command Injection',
            'Path Traversal', 'SSRF', 'XXE', 'Insecure Deserialization',
            'Hardcoded Credentials', 'Weak Cryptography', 'Authentication Bypass',
            'Sensitive Data Exposure', 'CSRF', 'Buffer Overflow'
        ]

        for vuln_type in vuln_types:
            if vuln_type.lower() in response.lower():
                # Determine severity
                severity = 'medium'
                for sev, pattern in severity_patterns.items():
                    if re.search(pattern, response, re.IGNORECASE):
                        severity = sev
                        break

                vuln = {
                    'id': f"VULN-{datetime.now().strftime('%Y%m%d%H%M%S')}-{len(vulnerabilities)+1:03d}",
                    'title': f"{vuln_type} Detected",
                    'description': f"Potential {vuln_type} vulnerability detected in {filename}",
                    'severity': severity,
                    'type': vuln_type,
                    'affected_file': filename,
                    'source': 'ai_scan',
                    'model': self.config.model,
                    'cvss_score': self._severity_to_cvss(severity),
                    'remediation': f"Review code for {vuln_type} patterns and apply secure coding practices."
                }
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity to approximate CVSS score."""
        scores = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 0.0
        }
        return scores.get(severity.lower(), 5.0)

    def _map_to_mitre_tactics(self, vuln_type: str) -> List[str]:
        """Map vulnerability type to MITRE ATT&CK tactics."""
        tactics_map = {
            'sql injection': ['Initial Access', 'Collection'],
            'xss': ['Initial Access', 'Execution'],
            'cross-site scripting': ['Initial Access', 'Execution'],
            'command injection': ['Execution', 'Privilege Escalation'],
            'path traversal': ['Collection', 'Exfiltration'],
            'ssrf': ['Initial Access', 'Lateral Movement'],
            'xxe': ['Collection', 'Exfiltration'],
            'hardcoded credentials': ['Credential Access', 'Initial Access'],
            'authentication bypass': ['Initial Access', 'Defense Evasion'],
            'insecure deserialization': ['Execution', 'Persistence'],
            'csrf': ['Initial Access'],
            'buffer overflow': ['Execution', 'Privilege Escalation']
        }
        return tactics_map.get(vuln_type.lower(), [])

    def _map_to_mitre_techniques(self, vuln_type: str) -> List[str]:
        """Map vulnerability type to MITRE ATT&CK techniques."""
        techniques_map = {
            'sql injection': ['T1190: Exploit Public-Facing Application'],
            'xss': ['T1189: Drive-by Compromise', 'T1059: Command and Scripting Interpreter'],
            'cross-site scripting': ['T1189: Drive-by Compromise'],
            'command injection': ['T1059: Command and Scripting Interpreter'],
            'path traversal': ['T1083: File and Directory Discovery'],
            'hardcoded credentials': ['T1552: Unsecured Credentials'],
            'authentication bypass': ['T1078: Valid Accounts'],
            'ssrf': ['T1090: Proxy']
        }
        return techniques_map.get(vuln_type.lower(), [])


def create_scanner(model: str = "mistral", ollama_url: str = "http://localhost:11434") -> AIScanner:
    """Create an AI scanner with specified configuration."""
    config = ScanConfig(
        ollama_url=ollama_url,
        model=model
    )
    return AIScanner(config)
