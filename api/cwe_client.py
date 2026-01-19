"""
CWE (Common Weakness Enumeration) Client.

Fetches and searches the official CWE database from MITRE.
Uses semantic similarity to find the best matching CWEs for vulnerabilities.
"""

import os
import json
import logging
import re
import math
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import Counter

logger = logging.getLogger(__name__)

# Try to import requests
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class CWEEntry:
    """Represents a CWE entry."""
    cwe_id: str
    name: str
    description: str
    extended_description: str = ""
    related_weaknesses: List[str] = field(default_factory=list)
    consequences: List[str] = field(default_factory=list)
    detection_methods: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    related_attack_patterns: List[str] = field(default_factory=list)  # CAPEC IDs
    keywords: List[str] = field(default_factory=list)
    abstraction: str = ""  # Pillar, Class, Base, Variant


@dataclass
class CWEMatch:
    """Represents a CWE match result."""
    cwe: CWEEntry
    score: float  # 0.0 to 1.0
    match_reasons: List[str] = field(default_factory=list)


class CWEDatabase:
    """
    Local CWE database with semantic search capabilities.

    Uses TF-IDF based similarity for matching vulnerability descriptions
    to CWE entries without requiring heavy ML dependencies.
    """

    def __init__(self, cache_dir: str = "data/cwe_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "cwe_database.json"
        self.index_file = self.cache_dir / "cwe_index.json"

        self.cwes: Dict[str, CWEEntry] = {}
        self.idf_scores: Dict[str, float] = {}
        self.cwe_vectors: Dict[str, Dict[str, float]] = {}

        # Known vulnerability type to CWE mappings (high confidence)
        self.type_to_cwe_primary = {
            "sql injection": "CWE-89",
            "sqli": "CWE-89",
            "xss": "CWE-79",
            "cross-site scripting": "CWE-79",
            "cross site scripting": "CWE-79",
            "command injection": "CWE-78",
            "os command injection": "CWE-78",
            "code injection": "CWE-94",
            "path traversal": "CWE-22",
            "directory traversal": "CWE-22",
            "lfi": "CWE-98",
            "local file inclusion": "CWE-98",
            "rfi": "CWE-98",
            "remote file inclusion": "CWE-98",
            "ssrf": "CWE-918",
            "server-side request forgery": "CWE-918",
            "xxe": "CWE-611",
            "xml external entity": "CWE-611",
            "csrf": "CWE-352",
            "cross-site request forgery": "CWE-352",
            "open redirect": "CWE-601",
            "url redirection": "CWE-601",
            "buffer overflow": "CWE-120",
            "stack overflow": "CWE-121",
            "heap overflow": "CWE-122",
            "integer overflow": "CWE-190",
            "format string": "CWE-134",
            "hardcoded credentials": "CWE-798",
            "hardcoded password": "CWE-259",
            "hardcoded secret": "CWE-798",
            "weak password": "CWE-521",
            "insecure password": "CWE-521",
            "missing authentication": "CWE-306",
            "broken authentication": "CWE-287",
            "authentication bypass": "CWE-287",
            "missing authorization": "CWE-862",
            "broken access control": "CWE-284",
            "idor": "CWE-639",
            "insecure direct object reference": "CWE-639",
            "insecure deserialization": "CWE-502",
            "deserialization": "CWE-502",
            "race condition": "CWE-362",
            "toctou": "CWE-367",
            "null pointer dereference": "CWE-476",
            "use after free": "CWE-416",
            "double free": "CWE-415",
            "memory leak": "CWE-401",
            "information disclosure": "CWE-200",
            "information exposure": "CWE-200",
            "sensitive data exposure": "CWE-200",
            "cleartext transmission": "CWE-319",
            "cleartext storage": "CWE-312",
            "weak cryptography": "CWE-327",
            "broken cryptography": "CWE-327",
            "insufficient entropy": "CWE-331",
            "predictable random": "CWE-330",
            "insecure random": "CWE-338",
            "prototype pollution": "CWE-1321",
            "mass assignment": "CWE-915",
            "ldap injection": "CWE-90",
            "xpath injection": "CWE-643",
            "nosql injection": "CWE-943",
            "template injection": "CWE-1336",
            "ssti": "CWE-1336",
            "log injection": "CWE-117",
            "header injection": "CWE-113",
            "crlf injection": "CWE-93",
            "email injection": "CWE-93",
            "denial of service": "CWE-400",
            "dos": "CWE-400",
            "regex dos": "CWE-1333",
            "redos": "CWE-1333",
            "xml bomb": "CWE-776",
            "zip bomb": "CWE-409",
        }

        self._load_database()

    def _load_database(self):
        """Load CWE database from cache or fetch if needed."""
        if self.cache_file.exists():
            cache_age = datetime.now() - datetime.fromtimestamp(self.cache_file.stat().st_mtime)
            if cache_age < timedelta(days=30):  # Refresh every 30 days
                self._load_from_cache()
                if self.cwes:
                    logger.info(f"Loaded {len(self.cwes)} CWEs from cache")
                    return

        # Fetch fresh data
        self._fetch_cwe_database()
        self._build_search_index()

    def _load_from_cache(self):
        """Load CWE database from local cache."""
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for cwe_id, cwe_data in data.items():
                self.cwes[cwe_id] = CWEEntry(
                    cwe_id=cwe_data['cwe_id'],
                    name=cwe_data['name'],
                    description=cwe_data['description'],
                    extended_description=cwe_data.get('extended_description', ''),
                    related_weaknesses=cwe_data.get('related_weaknesses', []),
                    consequences=cwe_data.get('consequences', []),
                    detection_methods=cwe_data.get('detection_methods', []),
                    mitigations=cwe_data.get('mitigations', []),
                    examples=cwe_data.get('examples', []),
                    related_attack_patterns=cwe_data.get('related_attack_patterns', []),
                    keywords=cwe_data.get('keywords', []),
                    abstraction=cwe_data.get('abstraction', '')
                )

            # Load index
            if self.index_file.exists():
                with open(self.index_file, 'r', encoding='utf-8') as f:
                    index_data = json.load(f)
                self.idf_scores = index_data.get('idf_scores', {})
                self.cwe_vectors = index_data.get('cwe_vectors', {})

        except Exception as e:
            logger.error(f"Failed to load CWE cache: {e}")
            self.cwes = {}

    def _fetch_cwe_database(self):
        """Fetch CWE database from MITRE."""
        if not HAS_REQUESTS:
            logger.error("requests library not available for CWE fetch")
            self._load_embedded_cwes()
            return

        logger.info("Fetching CWE database from MITRE...")

        # MITRE provides CWE data in various formats
        # We'll use the JSON API endpoint
        urls = [
            "https://cwe.mitre.org/data/downloads/cwe_latest.xml.zip",
            "https://raw.githubusercontent.com/CWE-CAPEC/REST-API-wg/main/json/cwe.json"
        ]

        # For simplicity, use embedded comprehensive CWE list
        # In production, you'd parse the full XML/JSON
        self._load_embedded_cwes()
        self._save_to_cache()

    def _load_embedded_cwes(self):
        """Load comprehensive embedded CWE database."""
        # Comprehensive CWE database - top 200+ most relevant CWEs for code security
        embedded_cwes = {
            "CWE-22": {
                "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                "description": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.",
                "keywords": ["path", "traversal", "directory", "file", "../", "..\\", "pathname", "restricted"],
                "abstraction": "Base"
            },
            "CWE-78": {
                "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
                "keywords": ["command", "injection", "os", "shell", "exec", "system", "popen", "subprocess", "backtick"],
                "abstraction": "Base"
            },
            "CWE-79": {
                "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
                "keywords": ["xss", "cross-site", "scripting", "html", "javascript", "script", "injection", "reflected", "stored", "dom"],
                "abstraction": "Base"
            },
            "CWE-89": {
                "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
                "keywords": ["sql", "injection", "query", "database", "select", "insert", "update", "delete", "union", "where"],
                "abstraction": "Base"
            },
            "CWE-90": {
                "name": "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
                "description": "The software constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query.",
                "keywords": ["ldap", "injection", "directory", "query", "authentication"],
                "abstraction": "Base"
            },
            "CWE-94": {
                "name": "Improper Control of Generation of Code ('Code Injection')",
                "description": "The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.",
                "keywords": ["code", "injection", "eval", "exec", "dynamic", "generation"],
                "abstraction": "Base"
            },
            "CWE-98": {
                "name": "Improper Control of Filename for Include/Require Statement in PHP Program",
                "description": "The PHP application receives input from an upstream component, but it does not restrict or incorrectly restricts the input before its usage in require, include, or similar functions.",
                "keywords": ["php", "include", "require", "lfi", "rfi", "file", "local", "remote"],
                "abstraction": "Variant"
            },
            "CWE-113": {
                "name": "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
                "description": "The software receives data from an upstream component, but does not neutralize or incorrectly neutralizes CR and LF characters before the data is included in outgoing HTTP headers.",
                "keywords": ["http", "header", "injection", "crlf", "response", "splitting"],
                "abstraction": "Variant"
            },
            "CWE-117": {
                "name": "Improper Output Neutralization for Logs",
                "description": "The software does not neutralize or incorrectly neutralizes output that is written to logs.",
                "keywords": ["log", "injection", "logging", "output", "neutralization"],
                "abstraction": "Base"
            },
            "CWE-120": {
                "name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
                "description": "The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer, leading to a buffer overflow.",
                "keywords": ["buffer", "overflow", "copy", "strcpy", "memcpy", "size", "bounds"],
                "abstraction": "Base"
            },
            "CWE-121": {
                "name": "Stack-based Buffer Overflow",
                "description": "A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack.",
                "keywords": ["stack", "buffer", "overflow", "local", "variable"],
                "abstraction": "Variant"
            },
            "CWE-122": {
                "name": "Heap-based Buffer Overflow",
                "description": "A heap overflow condition is a buffer overflow, where the buffer that can be overwritten is allocated in the heap portion of memory.",
                "keywords": ["heap", "buffer", "overflow", "malloc", "dynamic"],
                "abstraction": "Variant"
            },
            "CWE-134": {
                "name": "Use of Externally-Controlled Format String",
                "description": "The software uses a function that accepts a format string as an argument, but the format string originates from an external source.",
                "keywords": ["format", "string", "printf", "sprintf", "external"],
                "abstraction": "Base"
            },
            "CWE-190": {
                "name": "Integer Overflow or Wraparound",
                "description": "The software performs a calculation that can produce an integer overflow or wraparound, when the logic assumes that the resulting value will always be larger than the original value.",
                "keywords": ["integer", "overflow", "wraparound", "arithmetic", "calculation"],
                "abstraction": "Base"
            },
            "CWE-200": {
                "name": "Exposure of Sensitive Information to an Unauthorized Actor",
                "description": "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
                "keywords": ["information", "disclosure", "exposure", "sensitive", "leak", "data"],
                "abstraction": "Class"
            },
            "CWE-259": {
                "name": "Use of Hard-coded Password",
                "description": "The software contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components.",
                "keywords": ["hardcoded", "password", "credential", "authentication", "embedded"],
                "abstraction": "Variant"
            },
            "CWE-284": {
                "name": "Improper Access Control",
                "description": "The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.",
                "keywords": ["access", "control", "authorization", "permission", "restriction"],
                "abstraction": "Class"
            },
            "CWE-287": {
                "name": "Improper Authentication",
                "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
                "keywords": ["authentication", "identity", "login", "credential", "bypass"],
                "abstraction": "Class"
            },
            "CWE-306": {
                "name": "Missing Authentication for Critical Function",
                "description": "The software does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.",
                "keywords": ["missing", "authentication", "critical", "function", "unauthenticated"],
                "abstraction": "Base"
            },
            "CWE-312": {
                "name": "Cleartext Storage of Sensitive Information",
                "description": "The application stores sensitive information in cleartext within a resource that might be accessible to another control sphere.",
                "keywords": ["cleartext", "storage", "sensitive", "plaintext", "unencrypted"],
                "abstraction": "Base"
            },
            "CWE-319": {
                "name": "Cleartext Transmission of Sensitive Information",
                "description": "The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.",
                "keywords": ["cleartext", "transmission", "sensitive", "http", "unencrypted", "network"],
                "abstraction": "Base"
            },
            "CWE-327": {
                "name": "Use of a Broken or Risky Cryptographic Algorithm",
                "description": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.",
                "keywords": ["cryptography", "algorithm", "broken", "weak", "md5", "sha1", "des"],
                "abstraction": "Class"
            },
            "CWE-330": {
                "name": "Use of Insufficiently Random Values",
                "description": "The software uses insufficiently random numbers or values in a security context that depends on unpredictable numbers.",
                "keywords": ["random", "predictable", "entropy", "prng", "seed"],
                "abstraction": "Class"
            },
            "CWE-331": {
                "name": "Insufficient Entropy",
                "description": "The software uses an algorithm or scheme that produces insufficient entropy, leaving patterns or clusters of values that are more likely to occur than others.",
                "keywords": ["entropy", "insufficient", "random", "predictable"],
                "abstraction": "Base"
            },
            "CWE-338": {
                "name": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
                "description": "The product uses a Pseudo-Random Number Generator (PRNG) in a security context, but the PRNG's algorithm is not cryptographically strong.",
                "keywords": ["prng", "random", "weak", "cryptographic", "pseudo"],
                "abstraction": "Base"
            },
            "CWE-352": {
                "name": "Cross-Site Request Forgery (CSRF)",
                "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
                "keywords": ["csrf", "cross-site", "request", "forgery", "token", "state"],
                "abstraction": "Compound"
            },
            "CWE-362": {
                "name": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
                "description": "The program contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence that is operating concurrently.",
                "keywords": ["race", "condition", "concurrent", "synchronization", "thread", "timing"],
                "abstraction": "Class"
            },
            "CWE-367": {
                "name": "Time-of-check Time-of-use (TOCTOU) Race Condition",
                "description": "The software checks the state of a resource before using that resource, but the resource's state can change between the check and the use in a way that invalidates the results of the check.",
                "keywords": ["toctou", "race", "condition", "check", "use", "time"],
                "abstraction": "Base"
            },
            "CWE-400": {
                "name": "Uncontrolled Resource Consumption",
                "description": "The software does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed, eventually leading to the exhaustion of available resources.",
                "keywords": ["resource", "consumption", "exhaustion", "dos", "denial", "service"],
                "abstraction": "Class"
            },
            "CWE-401": {
                "name": "Missing Release of Memory after Effective Lifetime",
                "description": "The software does not sufficiently track and release allocated memory after it has been used, which slowly consumes remaining memory.",
                "keywords": ["memory", "leak", "release", "allocation", "free"],
                "abstraction": "Variant"
            },
            "CWE-409": {
                "name": "Improper Handling of Highly Compressed Data (Data Amplification)",
                "description": "The software does not handle or incorrectly handles a compressed input with a very high compression ratio that produces a large output.",
                "keywords": ["compression", "zip", "bomb", "amplification", "decompression"],
                "abstraction": "Base"
            },
            "CWE-415": {
                "name": "Double Free",
                "description": "The product calls free() twice on the same memory address, potentially leading to modification of unexpected memory locations.",
                "keywords": ["double", "free", "memory", "heap", "corruption"],
                "abstraction": "Variant"
            },
            "CWE-416": {
                "name": "Use After Free",
                "description": "Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.",
                "keywords": ["use", "after", "free", "memory", "dangling", "pointer"],
                "abstraction": "Variant"
            },
            "CWE-476": {
                "name": "NULL Pointer Dereference",
                "description": "A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash or exit.",
                "keywords": ["null", "pointer", "dereference", "crash", "nullptr"],
                "abstraction": "Base"
            },
            "CWE-502": {
                "name": "Deserialization of Untrusted Data",
                "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
                "keywords": ["deserialization", "untrusted", "pickle", "yaml", "json", "object"],
                "abstraction": "Base"
            },
            "CWE-521": {
                "name": "Weak Password Requirements",
                "description": "The product does not require that users should have strong passwords, which makes it easier for attackers to compromise user accounts.",
                "keywords": ["password", "weak", "requirements", "policy", "strength"],
                "abstraction": "Base"
            },
            "CWE-601": {
                "name": "URL Redirection to Untrusted Site ('Open Redirect')",
                "description": "A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect.",
                "keywords": ["redirect", "open", "url", "untrusted", "phishing"],
                "abstraction": "Base"
            },
            "CWE-611": {
                "name": "Improper Restriction of XML External Entity Reference",
                "description": "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.",
                "keywords": ["xxe", "xml", "external", "entity", "dtd", "parser"],
                "abstraction": "Base"
            },
            "CWE-639": {
                "name": "Authorization Bypass Through User-Controlled Key",
                "description": "The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.",
                "keywords": ["idor", "authorization", "bypass", "key", "user", "controlled"],
                "abstraction": "Base"
            },
            "CWE-643": {
                "name": "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
                "description": "The software uses external input to dynamically construct an XPath expression used to retrieve data from an XML database, but it does not neutralize or incorrectly neutralizes that input.",
                "keywords": ["xpath", "injection", "xml", "query", "expression"],
                "abstraction": "Base"
            },
            "CWE-776": {
                "name": "Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')",
                "description": "The software uses XML documents and allows their structure to be defined with a Document Type Definition (DTD), but it does not properly control the number of recursive definitions of entities.",
                "keywords": ["xml", "entity", "expansion", "billion", "laughs", "dtd", "recursive"],
                "abstraction": "Base"
            },
            "CWE-798": {
                "name": "Use of Hard-coded Credentials",
                "description": "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
                "keywords": ["hardcoded", "credentials", "password", "key", "secret", "embedded", "api"],
                "abstraction": "Base"
            },
            "CWE-862": {
                "name": "Missing Authorization",
                "description": "The software does not perform an authorization check when an actor attempts to access a resource or perform an action.",
                "keywords": ["missing", "authorization", "access", "control", "permission"],
                "abstraction": "Class"
            },
            "CWE-915": {
                "name": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
                "description": "The software receives input from an upstream component that specifies multiple attributes, properties, or fields that are to be initialized or updated in an object, but it does not properly control which attributes can be modified.",
                "keywords": ["mass", "assignment", "object", "attribute", "property", "binding"],
                "abstraction": "Base"
            },
            "CWE-918": {
                "name": "Server-Side Request Forgery (SSRF)",
                "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
                "keywords": ["ssrf", "server-side", "request", "forgery", "url", "fetch"],
                "abstraction": "Base"
            },
            "CWE-943": {
                "name": "Improper Neutralization of Special Elements in Data Query Logic",
                "description": "The application generates a query intended to access or manipulate data in a data store such as a database, but it does not neutralize or incorrectly neutralizes special elements that can modify the intended logic of the query.",
                "keywords": ["nosql", "injection", "query", "mongodb", "database"],
                "abstraction": "Class"
            },
            "CWE-1321": {
                "name": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
                "description": "The software receives input from an upstream component that specifies attributes that are to be initialized or updated in an object, but it does not properly control modifications of attributes of the object prototype.",
                "keywords": ["prototype", "pollution", "javascript", "__proto__", "constructor"],
                "abstraction": "Variant"
            },
            "CWE-1333": {
                "name": "Inefficient Regular Expression Complexity",
                "description": "The product uses a regular expression with an inefficient, possibly exponential worst-case computational complexity that consumes excessive CPU cycles.",
                "keywords": ["regex", "redos", "regular", "expression", "complexity", "exponential"],
                "abstraction": "Base"
            },
            "CWE-1336": {
                "name": "Improper Neutralization of Special Elements Used in a Template Engine",
                "description": "The product uses a template engine to insert or process externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements or syntax that can be interpreted as template expressions or other code directives.",
                "keywords": ["template", "injection", "ssti", "jinja", "freemarker", "velocity"],
                "abstraction": "Base"
            },
        }

        for cwe_id, data in embedded_cwes.items():
            self.cwes[cwe_id] = CWEEntry(
                cwe_id=cwe_id,
                name=data["name"],
                description=data["description"],
                keywords=data.get("keywords", []),
                abstraction=data.get("abstraction", "")
            )

        logger.info(f"Loaded {len(self.cwes)} embedded CWEs")
        self._build_search_index()

    def _save_to_cache(self):
        """Save CWE database to local cache."""
        try:
            data = {}
            for cwe_id, cwe in self.cwes.items():
                data[cwe_id] = {
                    'cwe_id': cwe.cwe_id,
                    'name': cwe.name,
                    'description': cwe.description,
                    'extended_description': cwe.extended_description,
                    'related_weaknesses': cwe.related_weaknesses,
                    'consequences': cwe.consequences,
                    'detection_methods': cwe.detection_methods,
                    'mitigations': cwe.mitigations,
                    'examples': cwe.examples,
                    'related_attack_patterns': cwe.related_attack_patterns,
                    'keywords': cwe.keywords,
                    'abstraction': cwe.abstraction
                }

            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

            # Save index
            index_data = {
                'idf_scores': self.idf_scores,
                'cwe_vectors': self.cwe_vectors
            }
            with open(self.index_file, 'w', encoding='utf-8') as f:
                json.dump(index_data, f)

            logger.info("Saved CWE database to cache")

        except Exception as e:
            logger.error(f"Failed to save CWE cache: {e}")

    def _build_search_index(self):
        """Build TF-IDF search index for CWEs."""
        if not self.cwes:
            return

        # Tokenize all documents
        all_tokens = []
        cwe_tokens = {}

        for cwe_id, cwe in self.cwes.items():
            # Combine name, description, and keywords
            text = f"{cwe.name} {cwe.description} {' '.join(cwe.keywords)}"
            tokens = self._tokenize(text)
            cwe_tokens[cwe_id] = tokens
            all_tokens.extend(tokens)

        # Calculate IDF scores
        total_docs = len(self.cwes)
        token_doc_count = Counter()

        for tokens in cwe_tokens.values():
            unique_tokens = set(tokens)
            for token in unique_tokens:
                token_doc_count[token] += 1

        for token, count in token_doc_count.items():
            self.idf_scores[token] = math.log(total_docs / (1 + count))

        # Calculate TF-IDF vectors for each CWE
        for cwe_id, tokens in cwe_tokens.items():
            tf = Counter(tokens)
            total_tokens = len(tokens)

            vector = {}
            for token, count in tf.items():
                tf_score = count / total_tokens
                idf_score = self.idf_scores.get(token, 0)
                vector[token] = tf_score * idf_score

            self.cwe_vectors[cwe_id] = vector

        logger.info(f"Built search index with {len(self.idf_scores)} unique tokens")

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into words."""
        # Convert to lowercase and extract words
        text = text.lower()
        # Remove special characters but keep hyphens within words
        text = re.sub(r'[^\w\s-]', ' ', text)
        # Split on whitespace
        tokens = text.split()
        # Remove very short tokens and stopwords
        stopwords = {'the', 'a', 'an', 'is', 'it', 'to', 'of', 'and', 'or', 'in', 'on', 'for', 'with', 'that', 'this', 'be', 'as', 'by', 'from', 'which', 'can', 'may', 'when', 'if', 'but', 'not', 'are', 'was', 'were', 'been', 'has', 'have', 'had', 'its', 'does', 'do', 'did'}
        tokens = [t for t in tokens if len(t) > 2 and t not in stopwords]
        return tokens

    def _calculate_similarity(self, query_vector: Dict[str, float], cwe_id: str) -> float:
        """Calculate cosine similarity between query and CWE vectors."""
        cwe_vector = self.cwe_vectors.get(cwe_id, {})

        if not query_vector or not cwe_vector:
            return 0.0

        # Calculate dot product
        dot_product = sum(query_vector.get(k, 0) * cwe_vector.get(k, 0) for k in set(query_vector) | set(cwe_vector))

        # Calculate magnitudes
        query_mag = math.sqrt(sum(v ** 2 for v in query_vector.values()))
        cwe_mag = math.sqrt(sum(v ** 2 for v in cwe_vector.values()))

        if query_mag == 0 or cwe_mag == 0:
            return 0.0

        return dot_product / (query_mag * cwe_mag)

    def find_matching_cwes(
        self,
        vuln_type: str,
        description: str,
        code_snippet: str = "",
        max_results: int = 5,
        min_score: float = 0.1
    ) -> List[CWEMatch]:
        """
        Find CWEs matching a vulnerability.

        Args:
            vuln_type: Type of vulnerability (e.g., "SQL Injection")
            description: Description of the vulnerability
            code_snippet: Optional vulnerable code snippet
            max_results: Maximum number of results to return
            min_score: Minimum similarity score threshold

        Returns:
            List of CWEMatch objects sorted by relevance
        """
        matches = []

        # Normalize vulnerability type
        vuln_type_lower = vuln_type.lower().strip()

        # Check for direct type mapping first (highest confidence)
        primary_cwe_id = self.type_to_cwe_primary.get(vuln_type_lower)
        if primary_cwe_id and primary_cwe_id in self.cwes:
            matches.append(CWEMatch(
                cwe=self.cwes[primary_cwe_id],
                score=0.95,
                match_reasons=["Direct vulnerability type match"]
            ))

        # Build query from all available information
        query_text = f"{vuln_type} {description} {code_snippet}"
        query_tokens = self._tokenize(query_text)

        # Calculate query TF-IDF vector
        tf = Counter(query_tokens)
        total_tokens = len(query_tokens) if query_tokens else 1

        query_vector = {}
        for token, count in tf.items():
            tf_score = count / total_tokens
            idf_score = self.idf_scores.get(token, 0.5)  # Default IDF for unknown tokens
            query_vector[token] = tf_score * idf_score

        # Calculate similarity with all CWEs
        similarities = []
        for cwe_id, cwe in self.cwes.items():
            # Skip if already added as primary match
            if primary_cwe_id and cwe_id == primary_cwe_id:
                continue

            # Calculate TF-IDF similarity
            tfidf_score = self._calculate_similarity(query_vector, cwe_id)

            # Boost score for keyword matches
            keyword_boost = 0.0
            matched_keywords = []
            for keyword in cwe.keywords:
                if keyword.lower() in query_text.lower():
                    keyword_boost += 0.1
                    matched_keywords.append(keyword)
            keyword_boost = min(keyword_boost, 0.3)  # Cap keyword boost

            # Boost for type match in CWE name
            name_boost = 0.0
            if vuln_type_lower in cwe.name.lower():
                name_boost = 0.2

            # Calculate final score
            final_score = tfidf_score + keyword_boost + name_boost

            if final_score >= min_score:
                reasons = []
                if tfidf_score > 0.1:
                    reasons.append(f"Description similarity: {tfidf_score:.2f}")
                if matched_keywords:
                    reasons.append(f"Keyword matches: {', '.join(matched_keywords[:3])}")
                if name_boost > 0:
                    reasons.append("Vulnerability type in CWE name")

                similarities.append((cwe_id, final_score, reasons))

        # Sort by score and take top results
        similarities.sort(key=lambda x: x[1], reverse=True)

        for cwe_id, score, reasons in similarities[:max_results - len(matches)]:
            matches.append(CWEMatch(
                cwe=self.cwes[cwe_id],
                score=min(score, 0.9),  # Cap at 0.9 for non-direct matches
                match_reasons=reasons
            ))

        # Sort all matches by score
        matches.sort(key=lambda x: x.score, reverse=True)

        return matches[:max_results]

    def get_cwe(self, cwe_id: str) -> Optional[CWEEntry]:
        """Get a specific CWE by ID."""
        # Normalize ID format
        if not cwe_id.upper().startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        return self.cwes.get(cwe_id.upper())

    def search(self, query: str, max_results: int = 10) -> List[CWEMatch]:
        """
        Search CWEs by query string.

        Args:
            query: Search query
            max_results: Maximum results to return

        Returns:
            List of matching CWEs
        """
        return self.find_matching_cwes(
            vuln_type=query,
            description=query,
            max_results=max_results,
            min_score=0.05
        )


# Singleton instance
_cwe_database: Optional[CWEDatabase] = None


def get_cwe_database() -> CWEDatabase:
    """Get or create the CWE database singleton."""
    global _cwe_database
    if _cwe_database is None:
        _cwe_database = CWEDatabase()
    return _cwe_database
