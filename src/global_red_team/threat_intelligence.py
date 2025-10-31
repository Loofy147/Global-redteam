import json
import os
from typing import Dict, Optional

# Build a path to the JSON file relative to this file's location
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_KEV_FILE_PATH = os.path.join(_CURRENT_DIR, "known_exploited_vulnerabilities.json")


class ThreatIntelligence:
    def __init__(self, kev_file: str = _KEV_FILE_PATH):
        self.known_exploited_vulnerabilities = self._load_kev_data(kev_file)

    def _load_kev_data(self, kev_file: str) -> Dict:
        """Loads Known Exploited Vulnerabilities data from a JSON file."""
        try:
            with open(kev_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # In a real application, you'd want to log this error.
            return {}

    def get_threat_info(self, cve_id: str) -> Optional[Dict]:
        """Retrieves threat intelligence for a given CVE ID."""
        return self.known_exploited_vulnerabilities.get(cve_id)
