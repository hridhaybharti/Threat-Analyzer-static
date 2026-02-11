from __future__ import annotations

import ssl
import socket
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import urlparse

def get_certificate_info(hostname: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception:
        return None

def ssl_certificate_signal(url: str) -> Dict[str, Any]:
    """
    Check SSL certificate validity and properties.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
             return {
                "name": "SSL Certificate",
                "category": "network",
                "bucket": "network",
                "impact": 5,
                "confidence": 0.8,
                "description": "URL does not use HTTPS.",
                "evidence": {"scheme": parsed.scheme}
            }
            
        hostname = parsed.hostname
        if not hostname:
             return {
                "name": "SSL Certificate",
                "category": "network",
                "bucket": "network",
                "impact": 0,
                "confidence": 0.0,
                "description": "Could not determine hostname.",
                "evidence": {}
            }

        # In a real heuristic, we'd do a proper handshake
        # For now, we'll do a basic connection check if possible, or just return a placeholder
        # if dependencies/permissions are tricky. 
        # But let's try to implement a simple check.
        
        cert = get_certificate_info(hostname)
        if not cert:
            return {
                "name": "SSL Certificate",
                "category": "network",
                "bucket": "network",
                "impact": 15,
                "confidence": 0.6,
                "description": "HTTPS connection failed or certificate invalid.",
                "evidence": {"error": "Connection failed"}
            }

        # Check expiration
        not_after_str = cert.get('notAfter')
        if not_after_str:
            # format: 'May 26 23:59:59 2024 GMT'
            # Python's ssl module returns this format
            try:
                not_after = datetime.strptime(not_after_str, r"%b %d %H:%M:%S %Y %Z")
                remaining = (not_after - datetime.now()).days
                
                if remaining < 0:
                    return {
                        "name": "SSL Certificate",
                        "category": "network",
                        "bucket": "network",
                        "impact": 40,
                        "confidence": 0.9,
                        "description": "SSL certificate has expired.",
                        "evidence": {"expiration": not_after_str, "days_remaining": remaining}
                    }
                elif remaining < 7:
                     return {
                        "name": "SSL Certificate",
                        "category": "network",
                        "bucket": "network",
                        "impact": 10,
                        "confidence": 0.8,
                        "description": "SSL certificate expires very soon.",
                        "evidence": {"expiration": not_after_str, "days_remaining": remaining}
                     }
            except Exception as e:
                return {
                    "name": "SSL Certificate",
                    "category": "network",
                    "bucket": "network",
                    "impact": 0,
                    "confidence": 0.3,
                    "description": f"SSL date parsing error: {str(e)}",
                    "evidence": {"error": str(e)}
                }

        issuer_str = str(cert.get('issuer'))
        return {
            "name": "SSL Certificate",
            "category": "network",
            "bucket": "network",
            "impact": 0,
            "confidence": 0.7,
            "description": "Valid SSL certificate found.",
            "evidence": {"issuer": issuer_str[:50] + "..."}
        }

    except Exception as e:
        return {
            "name": "SSL Certificate",
            "category": "network",
            "bucket": "network",
            "impact": 0,
            "confidence": 0.3,
            "description": f"SSL check error: {str(e)}",
            "evidence": {"error": str(e)}
        }
