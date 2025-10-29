"""
This module contains the ThreatIntelligence class, which is responsible for
loading and querying the threat intelligence data.
"""

import json
from typing import Dict, Optional


class ThreatIntelligence:
    """
    Loads and queries threat intelligence data.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.threat_data = self._load_threat_data()

    def _load_threat_data(self) -> Dict:
        """Loads the threat data from the specified JSON file."""
        try:
            with open(self.filepath, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def get_threat_info(self, cve_id: str) -> Optional[Dict]:
        """
        Retrieves threat intelligence information for a given CVE ID.

        Args:
            cve_id (str): The CVE ID to look up.

        Returns:
            Optional[Dict]: A dictionary containing the threat intelligence
                           information, or None if no information is found.
        """
        return self.threat_data.get(cve_id)
