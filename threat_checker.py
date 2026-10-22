"""threat_checker.py - Asks Google Safe Browsing whether a URL is a known threat.

Setup: you need a free Google Cloud API key with the "Safe Browsing API" enabled.
The key is read from an environment variable or Streamlit secrets (see README).
LoginGuard sends only the URL text to Google. It never visits the URL itself.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import requests

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Safe fake fixtures for demos and tests. ".test" is a reserved name that
# can never be a real website. Results for these are labelled SIMULATED.
DEMO_FIXTURES = {
    "phish-demo.test": "match",
    "clean-demo.test": "no_match",
}


@dataclass
class ThreatResult:
    status: str                 # "match", "no_match" or "unavailable"
    source: str
    detail: str = ""
    simulated: bool = False
    threat_types: tuple[str, ...] = ()


def check_threat(url: str, api_key: str | None, timeout: int = 8, session=None) -> ThreatResult:
    host = (urlsplit(url).hostname or "").lower()
    if host in DEMO_FIXTURES:
        return ThreatResult(
            DEMO_FIXTURES[host], "Simulated demo fixture",
            "This is a fake test result, not real threat intelligence.",
            simulated=True,
            threat_types=("SIMULATED",) if DEMO_FIXTURES[host] == "match" else ())

    source = "Google Safe Browsing"
    if not api_key:
        return ThreatResult("unavailable", source,
                            "No API key is configured, so the database check was skipped.")

    body = {
        "client": {"clientId": "loginguard", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    http = session or requests
    try:
        resp = http.post(GSB_URL, params={"key": api_key}, json=body, timeout=timeout)
    except requests.exceptions.Timeout:
        return ThreatResult("unavailable", source, "The database check timed out.")
    except requests.exceptions.RequestException:
        # Do not print the raw error: it can contain the API key.
        return ThreatResult("unavailable", source, "Could not reach the database (network problem).")

    if resp.status_code in (400, 401, 403):
        return ThreatResult("unavailable", source,
                            "The database rejected the request (check your API key and that the API is enabled).")
    if resp.status_code == 429:
        return ThreatResult("unavailable", source, "Too many requests (quota reached). Try again later.")
    if resp.status_code != 200:
        return ThreatResult("unavailable", source, f"The database returned an error (HTTP {resp.status_code}).")

    try:
        data = resp.json()
    except ValueError:
        return ThreatResult("unavailable", source, "The database sent an unreadable answer.")

    matches = data.get("matches") if isinstance(data, dict) else None
    if matches:
        types = tuple(sorted({m.get("threatType", "UNKNOWN") for m in matches if isinstance(m, dict)}))
        return ThreatResult("match", source, "Listed as a known threat.", threat_types=types)
    return ThreatResult("no_match", source, "Not found in the database. This does not prove the site is safe.")
