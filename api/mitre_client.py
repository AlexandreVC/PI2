"""
MITRE ATT&CK API Client.

Fetches real tactics, techniques, and threat data from MITRE ATT&CK.
Uses the official STIX/TAXII feed and CTI repository.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class MITREClient:
    """
    Client for fetching MITRE ATT&CK data.

    Data sources:
    - MITRE CTI GitHub repository (STIX format)
    - MITRE ATT&CK website
    """

    # MITRE ATT&CK Enterprise STIX data URL
    STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    # Alternative: MITRE ATT&CK API (if available)
    ATTACK_API_URL = "https://attack.mitre.org"

    def __init__(self, cache_dir: str = "data/cache/mitre"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "attack_data.json"
        self._data = None

    def fetch_attack_data(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Fetch MITRE ATT&CK data from the official STIX repository.

        Args:
            force_refresh: Force re-download even if cached

        Returns:
            Dictionary with tactics, techniques, and metadata
        """
        if not HAS_REQUESTS:
            logger.error("requests library not installed")
            return self._get_fallback_data()

        # Check cache first
        if not force_refresh and self.cache_file.exists():
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    cached = json.load(f)
                    # Check if cache is less than 24 hours old
                    cached_at = datetime.fromisoformat(cached.get('fetched_at', '2000-01-01'))
                    if (datetime.now() - cached_at).total_seconds() < 86400:
                        logger.info("Using cached MITRE ATT&CK data")
                        self._data = cached
                        return cached
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")

        # Fetch fresh data
        logger.info("Fetching MITRE ATT&CK data from GitHub...")

        try:
            response = requests.get(self.STIX_URL, timeout=60)
            response.raise_for_status()
            stix_data = response.json()

            # Parse STIX data
            parsed = self._parse_stix_data(stix_data)
            parsed['fetched_at'] = datetime.now().isoformat()
            parsed['source'] = 'mitre_cti_github'

            # Save to cache
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(parsed, f, indent=2, default=str)

            logger.info(f"Fetched {len(parsed.get('tactics', []))} tactics, "
                       f"{len(parsed.get('techniques', []))} techniques")

            self._data = parsed
            return parsed

        except Exception as e:
            logger.error(f"Failed to fetch MITRE data: {e}")
            return self._get_fallback_data()

    def _parse_stix_data(self, stix_data: Dict) -> Dict[str, Any]:
        """Parse STIX 2.0 format data into usable structure."""
        tactics = []
        techniques = []
        groups = []
        software = []
        mitigations = []

        objects = stix_data.get('objects', [])

        for obj in objects:
            obj_type = obj.get('type', '')

            # Skip revoked or deprecated items
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue

            if obj_type == 'x-mitre-tactic':
                tactic = self._parse_tactic(obj)
                if tactic:
                    tactics.append(tactic)

            elif obj_type == 'attack-pattern':
                technique = self._parse_technique(obj)
                if technique:
                    techniques.append(technique)

            elif obj_type == 'intrusion-set':
                group = self._parse_group(obj)
                if group:
                    groups.append(group)

            elif obj_type == 'malware' or obj_type == 'tool':
                sw = self._parse_software(obj)
                if sw:
                    software.append(sw)

            elif obj_type == 'course-of-action':
                mitigation = self._parse_mitigation(obj)
                if mitigation:
                    mitigations.append(mitigation)

        # Sort tactics by kill chain order
        kill_chain_order = [
            'reconnaissance', 'resource-development', 'initial-access',
            'execution', 'persistence', 'privilege-escalation', 'defense-evasion',
            'credential-access', 'discovery', 'lateral-movement', 'collection',
            'command-and-control', 'exfiltration', 'impact'
        ]

        tactics.sort(key=lambda t: (
            kill_chain_order.index(t.get('short_name', '').lower())
            if t.get('short_name', '').lower() in kill_chain_order
            else 999
        ))

        return {
            'tactics': tactics,
            'techniques': techniques,
            'groups': groups,
            'software': software,
            'mitigations': mitigations,
            'stats': {
                'tactics_count': len(tactics),
                'techniques_count': len(techniques),
                'groups_count': len(groups),
                'software_count': len(software),
                'mitigations_count': len(mitigations)
            }
        }

    def _parse_tactic(self, obj: Dict) -> Optional[Dict]:
        """Parse a tactic object."""
        external_refs = obj.get('external_references', [])
        mitre_id = None
        url = None

        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                mitre_id = ref.get('external_id')
                url = ref.get('url')
                break

        if not mitre_id:
            return None

        return {
            'id': mitre_id,
            'name': obj.get('name', ''),
            'short_name': obj.get('x_mitre_shortname', ''),
            'description': obj.get('description', ''),
            'url': url,
            'created': obj.get('created'),
            'modified': obj.get('modified')
        }

    def _parse_technique(self, obj: Dict) -> Optional[Dict]:
        """Parse a technique object."""
        external_refs = obj.get('external_references', [])
        mitre_id = None
        url = None

        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                mitre_id = ref.get('external_id')
                url = ref.get('url')
                break

        if not mitre_id:
            return None

        # Get tactics this technique belongs to
        kill_chain_phases = obj.get('kill_chain_phases', [])
        tactics = [
            phase.get('phase_name', '').replace('-', ' ').title()
            for phase in kill_chain_phases
            if phase.get('kill_chain_name') == 'mitre-attack'
        ]

        # Get platforms
        platforms = obj.get('x_mitre_platforms', [])

        # Get data sources
        data_sources = obj.get('x_mitre_data_sources', [])

        # Check if sub-technique
        is_subtechnique = obj.get('x_mitre_is_subtechnique', False)

        return {
            'id': mitre_id,
            'name': obj.get('name', ''),
            'description': obj.get('description', '')[:500] + '...' if len(obj.get('description', '')) > 500 else obj.get('description', ''),
            'tactics': tactics,
            'platforms': platforms,
            'data_sources': data_sources,
            'is_subtechnique': is_subtechnique,
            'url': url,
            'detection': obj.get('x_mitre_detection', ''),
            'created': obj.get('created'),
            'modified': obj.get('modified')
        }

    def _parse_group(self, obj: Dict) -> Optional[Dict]:
        """Parse a threat group object."""
        external_refs = obj.get('external_references', [])
        mitre_id = None
        url = None
        aliases = obj.get('aliases', [])

        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                mitre_id = ref.get('external_id')
                url = ref.get('url')
                break

        if not mitre_id:
            return None

        return {
            'id': mitre_id,
            'name': obj.get('name', ''),
            'aliases': aliases,
            'description': obj.get('description', '')[:300] + '...' if len(obj.get('description', '')) > 300 else obj.get('description', ''),
            'url': url,
            'created': obj.get('created'),
            'modified': obj.get('modified')
        }

    def _parse_software(self, obj: Dict) -> Optional[Dict]:
        """Parse malware/tool object."""
        external_refs = obj.get('external_references', [])
        mitre_id = None
        url = None

        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                mitre_id = ref.get('external_id')
                url = ref.get('url')
                break

        if not mitre_id:
            return None

        return {
            'id': mitre_id,
            'name': obj.get('name', ''),
            'type': obj.get('type', ''),
            'description': obj.get('description', '')[:300] + '...' if len(obj.get('description', '')) > 300 else obj.get('description', ''),
            'platforms': obj.get('x_mitre_platforms', []),
            'url': url,
            'created': obj.get('created'),
            'modified': obj.get('modified')
        }

    def _parse_mitigation(self, obj: Dict) -> Optional[Dict]:
        """Parse mitigation object."""
        external_refs = obj.get('external_references', [])
        mitre_id = None
        url = None

        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                mitre_id = ref.get('external_id')
                url = ref.get('url')
                break

        if not mitre_id:
            return None

        return {
            'id': mitre_id,
            'name': obj.get('name', ''),
            'description': obj.get('description', ''),
            'url': url,
            'created': obj.get('created'),
            'modified': obj.get('modified')
        }

    def _get_fallback_data(self) -> Dict[str, Any]:
        """Return minimal fallback data if fetch fails."""
        return {
            'tactics': [
                {'id': 'TA0043', 'name': 'Reconnaissance', 'short_name': 'reconnaissance'},
                {'id': 'TA0042', 'name': 'Resource Development', 'short_name': 'resource-development'},
                {'id': 'TA0001', 'name': 'Initial Access', 'short_name': 'initial-access'},
                {'id': 'TA0002', 'name': 'Execution', 'short_name': 'execution'},
                {'id': 'TA0003', 'name': 'Persistence', 'short_name': 'persistence'},
                {'id': 'TA0004', 'name': 'Privilege Escalation', 'short_name': 'privilege-escalation'},
                {'id': 'TA0005', 'name': 'Defense Evasion', 'short_name': 'defense-evasion'},
                {'id': 'TA0006', 'name': 'Credential Access', 'short_name': 'credential-access'},
                {'id': 'TA0007', 'name': 'Discovery', 'short_name': 'discovery'},
                {'id': 'TA0008', 'name': 'Lateral Movement', 'short_name': 'lateral-movement'},
                {'id': 'TA0009', 'name': 'Collection', 'short_name': 'collection'},
                {'id': 'TA0011', 'name': 'Command and Control', 'short_name': 'command-and-control'},
                {'id': 'TA0010', 'name': 'Exfiltration', 'short_name': 'exfiltration'},
                {'id': 'TA0040', 'name': 'Impact', 'short_name': 'impact'},
            ],
            'techniques': [],
            'groups': [],
            'software': [],
            'mitigations': [],
            'stats': {'tactics_count': 14, 'techniques_count': 0},
            'source': 'fallback',
            'fetched_at': datetime.now().isoformat()
        }

    def get_tactics(self) -> List[Dict]:
        """Get all tactics."""
        if not self._data:
            self.fetch_attack_data()
        return self._data.get('tactics', [])

    def get_techniques(self, tactic: Optional[str] = None) -> List[Dict]:
        """Get techniques, optionally filtered by tactic."""
        if not self._data:
            self.fetch_attack_data()

        techniques = self._data.get('techniques', [])

        if tactic:
            techniques = [t for t in techniques if tactic.lower() in [
                tc.lower() for tc in t.get('tactics', [])
            ]]

        return techniques

    def get_technique_by_id(self, technique_id: str) -> Optional[Dict]:
        """Get a specific technique by ID."""
        if not self._data:
            self.fetch_attack_data()

        for tech in self._data.get('techniques', []):
            if tech.get('id') == technique_id:
                return tech
        return None

    def get_groups(self) -> List[Dict]:
        """Get all threat groups."""
        if not self._data:
            self.fetch_attack_data()
        return self._data.get('groups', [])

    def get_software(self) -> List[Dict]:
        """Get all malware and tools."""
        if not self._data:
            self.fetch_attack_data()
        return self._data.get('software', [])

    def get_mitigations(self) -> List[Dict]:
        """Get all mitigations."""
        if not self._data:
            self.fetch_attack_data()
        return self._data.get('mitigations', [])

    def search(self, query: str) -> Dict[str, List]:
        """Search across all MITRE data."""
        if not self._data:
            self.fetch_attack_data()

        query_lower = query.lower()
        results = {
            'tactics': [],
            'techniques': [],
            'groups': [],
            'software': [],
            'mitigations': []
        }

        for tactic in self._data.get('tactics', []):
            if query_lower in tactic.get('name', '').lower() or \
               query_lower in tactic.get('description', '').lower():
                results['tactics'].append(tactic)

        for tech in self._data.get('techniques', []):
            if query_lower in tech.get('name', '').lower() or \
               query_lower in tech.get('description', '').lower() or \
               query_lower in tech.get('id', '').lower():
                results['techniques'].append(tech)

        for group in self._data.get('groups', []):
            if query_lower in group.get('name', '').lower() or \
               query_lower in group.get('description', '').lower() or \
               any(query_lower in alias.lower() for alias in group.get('aliases', [])):
                results['groups'].append(group)

        for sw in self._data.get('software', []):
            if query_lower in sw.get('name', '').lower() or \
               query_lower in sw.get('description', '').lower():
                results['software'].append(sw)

        return results


# Global instance
_mitre_client: Optional[MITREClient] = None


def get_mitre_client() -> MITREClient:
    """Get or create the global MITRE client."""
    global _mitre_client
    if _mitre_client is None:
        _mitre_client = MITREClient()
    return _mitre_client
