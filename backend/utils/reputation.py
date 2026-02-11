from __future__ import annotations

import logging
import os
import time
import requests
import zipfile
import io
from typing import Set, Optional, Dict, Any
from urllib.parse import urlparse

logger = logging.getLogger("security_analyzer")

class ReputationService:
    _instance: Optional[ReputationService] = None
    _top_domains: Set[str] = set()
    _status: Dict[str, Any] = {
        "loaded": False,
        "count": 0,
        "last_sync": None,
        "source": "https://tranco-list.eu/download/current/100000"
    }

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ReputationService, cls).__new__(cls)
        return cls._instance

    def get_status(self) -> Dict[str, Any]:
        return self._status

    def load_dataset(self, file_path: str = "backend/data/top_100k.txt"):
        """Load the Tranco Top 100K domains into memory, syncing if necessary."""
        
        # Check if we need to sync
        self._check_and_sync(file_path)

        if not os.path.exists(file_path):
            # Try absolute path based on workspace root if relative fails
            file_path = os.path.join(os.getcwd(), file_path)
            if not os.path.exists(file_path):
                logger.warning(f"Reputation dataset not found at {file_path}. Reputation checks will be disabled.")
                return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                self._top_domains = {line.strip().lower() for line in f if line.strip()}
            
            self._status["loaded"] = True
            self._status["count"] = len(self._top_domains)
            self._status["last_sync"] = time.ctime(os.path.getmtime(file_path))
            
            logger.info(f"Loaded {len(self._top_domains)} domains into Reputation Service.")
        except Exception as e:
            logger.error(f"Failed to load reputation dataset: {e}")

    def _check_and_sync(self, file_path: str):
        """Check if dataset is missing or older than 7 days, and sync if needed."""
        needs_sync = False
        
        if not os.path.exists(file_path):
            needs_sync = True
            logger.info("Reputation dataset missing. Triggering sync...")
        else:
            file_age_days = (time.time() - os.path.getmtime(file_path)) / (24 * 3600)
            if file_age_days > 7:
                needs_sync = True
                logger.info(f"Reputation dataset is {int(file_age_days)} days old. Triggering sync...")

        if needs_sync:
            self._sync_from_tranco(file_path)

    def _sync_from_tranco(self, output_path: str):
        """Download and extract the latest Tranco 100K list."""
        url = self._status["source"]
        try:
            logger.info(f"Downloading latest Tranco list from {url}...")
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            # Tranco current/100000 returns a CSV inside a ZIP or a direct CSV
            # Their API has changed occasionally, so we handle both.
            content_type = response.headers.get('Content-Type', '')
            
            domains = []
            if 'zip' in content_type or response.content[:2] == b'PK':
                with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                    for filename in z.namelist():
                        if filename.endswith('.csv'):
                            with z.open(filename) as f:
                                # CSV format is "rank,domain"
                                for line in f:
                                    parts = line.decode('utf-8').strip().split(',')
                                    if len(parts) >= 2:
                                        domains.append(parts[1])
            else:
                # Assume direct CSV
                for line in response.text.splitlines():
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        domains.append(parts[1])

            if domains:
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(domains))
                logger.info(f"Successfully synced {len(domains)} domains to {output_path}")
            else:
                logger.error("Sync failed: No domains found in response.")

        except Exception as e:
            logger.error(f"Failed to sync reputation dataset from Tranco: {e}")

    def normalize_domain(self, domain: str) -> str:
        """
        Normalize domain for lookup:
        - Lowercase
        - Strip protocol
        - Strip www.
        - Extract registered domain (base domain)
        """
        d = domain.lower().strip().rstrip(".")
        
        # Strip protocol if present
        if "://" in d:
            try:
                parsed = urlparse(d)
                d = parsed.hostname or d
            except Exception:
                pass
        
        # Remove trailing slash/path if still present
        if "/" in d:
            d = d.split("/")[0]

        # Strip www.
        if d.startswith("www."):
            d = d[4:]

        # Extract base domain using tldextract if available
        try:
            import tldextract
            ext = tldextract.extract(d)
            if ext.registered_domain:
                return ext.registered_domain
        except ImportError:
            # Fallback: very basic SLD+TLD extraction for common cases
            parts = d.split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])

        return d

    def is_reputable(self, target: str) -> bool:
        normalized = self.normalize_domain(target)
        return normalized in self._top_domains

reputation_service = ReputationService()
