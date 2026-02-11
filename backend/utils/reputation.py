from __future__ import annotations

import logging
import os
from typing import Set, Optional
from urllib.parse import urlparse

logger = logging.getLogger("security_analyzer")

class ReputationService:
    _instance: Optional[ReputationService] = None
    _top_domains: Set[str] = set()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ReputationService, cls).__new__(cls)
        return cls._instance

    def load_dataset(self, file_path: str = "backend/data/top_100k.txt"):
        """Load the Tranco Top 100K domains into memory once."""
        if self._top_domains:
            return

        if not os.path.exists(file_path):
            # Try absolute path based on workspace root if relative fails
            file_path = os.path.join(os.getcwd(), file_path)
            if not os.path.exists(file_path):
                logger.warning(f"Reputation dataset not found at {file_path}. Reputation checks will be disabled.")
                return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                self._top_domains = {line.strip().lower() for line in f if line.strip()}
            logger.info(f"Loaded {len(self._top_domains)} domains into Reputation Service.")
        except Exception as e:
            logger.error(f"Failed to load reputation dataset: {e}")

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
