"""
ThreatKill - Online Threat Intelligence Module
By - RAVI CHAUHAN | github.com/Ravirazchauhan

Uses FREE public APIs - no API key required:
- URLhaus (abuse.ch)  - malicious URLs & domains
- ThreatFox (abuse.ch) - IOCs, malware hashes
- MalwareBazaar (abuse.ch) - malware file hashes
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import hashlib
import os
import socket
from typing import Optional, Dict, List
from dataclasses import dataclass


TIMEOUT = 8  # seconds per API call

APIS = {
    "malwarebazaar": "https://mb-api.abuse.ch/api/v1/",
    "threatfox":     "https://threatfox-api.abuse.ch/api/v1/",
    "urlhaus":       "https://urlhaus-api.abuse.ch/v1/",
}


@dataclass
class IntelResult:
    found: bool
    source: str
    threat_name: str = ""
    threat_type: str = ""
    severity: str = "high"
    tags: List[str] = None
    confidence: int = 0
    details: str = ""

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


def is_online() -> bool:
    """Check if the machine has internet connectivity."""
    try:
        socket.setdefaulttimeout(4)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
        return True
    except Exception:
        return False


def _post_json(url: str, data: dict) -> Optional[dict]:
    """Send a POST request with JSON body, return parsed response."""
    try:
        payload = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ThreatKill/1.0 (github.com/Ravirazchauhan)",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def check_hash_malwarebazaar(file_hash: str) -> Optional[IntelResult]:
    """
    Query MalwareBazaar for a file hash (MD5, SHA1, or SHA256).
    Returns IntelResult if found, None if clean or unreachable.
    """
    data = {"query": "get_info", "hash": file_hash}
    resp = _post_json(APIS["malwarebazaar"], data)

    if not resp or resp.get("query_status") != "ok":
        return None

    items = resp.get("data", [])
    if not items:
        return None

    item = items[0]
    tags = item.get("tags") or []

    return IntelResult(
        found=True,
        source="MalwareBazaar",
        threat_name=item.get("signature") or item.get("file_name", "Unknown"),
        threat_type=item.get("file_type_mime", "unknown"),
        severity="critical",
        tags=tags if isinstance(tags, list) else [],
        confidence=100,
        details=(
            f"First seen: {item.get('first_seen', 'unknown')}  |  "
            f"Family: {item.get('signature', 'unknown')}  |  "
            f"Reporter: {item.get('reporter', 'unknown')}"
        ),
    )


def check_hash_threatfox(file_hash: str) -> Optional[IntelResult]:
    """
    Query ThreatFox for IOC (indicators of compromise) by hash.
    """
    data = {"query": "search_ioc", "search_term": file_hash}
    resp = _post_json(APIS["threatfox"], data)

    if not resp or resp.get("query_status") != "ok":
        return None

    items = resp.get("data", [])
    if not items:
        return None

    item = items[0]
    confidence = item.get("confidence_level", 50)

    return IntelResult(
        found=True,
        source="ThreatFox",
        threat_name=item.get("malware_printable", "Unknown Malware"),
        threat_type=item.get("ioc_type", "unknown"),
        severity="critical" if confidence >= 75 else "high",
        tags=item.get("tags") or [],
        confidence=confidence,
        details=(
            f"Malware family: {item.get('malware_printable', 'unknown')}  |  "
            f"Confidence: {confidence}%  |  "
            f"First seen: {item.get('first_seen', 'unknown')}"
        ),
    )


def check_url_urlhaus(url_or_domain: str) -> Optional[IntelResult]:
    """
    Query URLhaus for a suspicious URL or domain.
    """
    data = {"url": url_or_domain}
    resp = _post_json(APIS["urlhaus"] + "url/", data)

    if not resp or resp.get("query_status") != "is_malware":
        return None

    tags = resp.get("tags") or []

    return IntelResult(
        found=True,
        source="URLhaus",
        threat_name=resp.get("threat", "Malicious URL"),
        threat_type="malicious_url",
        severity="high",
        tags=tags if isinstance(tags, list) else [],
        confidence=90,
        details=(
            f"URL status: {resp.get('url_status', 'unknown')}  |  "
            f"Threat: {resp.get('threat', 'unknown')}  |  "
            f"Date added: {resp.get('date_added', 'unknown')}"
        ),
    )


def check_file(filepath: str, log=None) -> List[IntelResult]:
    """
    Compute MD5 + SHA256 of a file and check all available APIs.
    Returns list of IntelResults (may be empty if clean).
    """
    results = []

    try:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha256.update(chunk)
        md5_hex    = md5.hexdigest()
        sha256_hex = sha256.hexdigest()
    except Exception:
        return results

    if log:
        log(f"  [INTEL] Checking {os.path.basename(filepath)} online...")

    for hsh in [sha256_hex, md5_hex]:
        r = check_hash_malwarebazaar(hsh)
        if r:
            results.append(r)
            break

    if not results:
        for hsh in [sha256_hex, md5_hex]:
            r = check_hash_threatfox(hsh)
            if r:
                results.append(r)
                break

    return results


def run_online_scan(file_paths: List[str], log=None) -> List[dict]:
    """
    Run online intelligence checks on a list of file paths.
    Returns list of threat dicts ready to add to ScanResult.
    """
    threats = []

    for fp in file_paths:
        if not os.path.isfile(fp):
            continue
        intel_results = check_file(fp, log)
        for ir in intel_results:
            threats.append({
                "id":          f"ONLINE-{ir.source.upper()[:3]}-{os.path.basename(fp)[:8].upper()}",
                "title":       f"[ONLINE] {ir.threat_name}",
                "severity":    ir.severity,
                "port":        None,
                "description": (
                    f"Verified by {ir.source}: {ir.details}  |  "
                    f"Tags: {', '.join(ir.tags) if ir.tags else 'none'}"
                ),
                "remediation": f"File confirmed malicious by {ir.source}. Delete immediately.",
                "references":  [APIS[k] for k in APIS],
                "location":    fp,
                "removable":   True,
                "source":      ir.source,
                "confidence":  ir.confidence,
            })
            if log:
                log(f"  [ONLINE HIT] {ir.threat_name} -- {ir.source} (confidence {ir.confidence}%)")

    return threats


def get_threat_intel_summary(log=None) -> dict:
    """
    Check connectivity and return a status summary.
    """
    online = is_online()
    reachable = {}

    if online:
        for name, url in APIS.items():
            try:
                req = urllib.request.Request(
                    url,
                    data=json.dumps({"query": "ping"}).encode(),
                    headers={"Content-Type": "application/json",
                             "User-Agent": "ThreatKill/1.0"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=4)
                reachable[name] = True
            except Exception:
                reachable[name] = False
    else:
        reachable = {k: False for k in APIS}

    if log:
        if online:
            active = [k for k, v in reachable.items() if v]
            log(f"  [INTEL] Online -- {len(active)}/{len(APIS)} threat feeds reachable")
        else:
            log("  [INTEL] Offline -- skipping online threat intelligence")

    return {"online": online, "feeds": reachable}
