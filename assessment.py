"""assessment.py - Combines local URL findings and the threat-intelligence result."""
from __future__ import annotations

from dataclasses import dataclass

from threat_checker import ThreatResult
from url_analyzer import UrlAnalysis

ORANGE_MIN = 1   # score 1-3  -> orange
RED_MIN = 4      # score 4+   -> red


@dataclass
class Assessment:
    level: str          # "green", "orange", "red" or "unknown"
    headline: str
    explanation: str
    next_steps: list[str]


def build_assessment(analysis: UrlAnalysis, threat: ThreatResult | None) -> Assessment:
    if not analysis.valid:
        return Assessment(
            "unknown", "Unable to determine",
            analysis.error or "The address could not be checked.",
            ["Check the spelling and try again.",
             "Use a full address such as https://example.com."])

    # A real (not simulated) database match is reported separately and first.
    if threat is not None and threat.status == "match":
        label = "SIMULATED TEST RESULT: " if threat.simulated else ""
        return Assessment(
            "red", f"{label}High caution - listed in a known-threat database",
            f"{threat.source} lists this address as a known threat"
            + (f" ({', '.join(threat.threat_types)})." if threat.threat_types else ".")
            + " This comes from the database, not from LoginGuard's own rules.",
            ["Do not open this website or enter any information.",
             "If someone sent you this link, do not trust the sender's message.",
             "If you already entered a password, change it right away on the real site."])

    score = analysis.score
    if score >= RED_MIN:
        return Assessment(
            "red", "High caution",
            f"Several or strong warning patterns were found (score {score}). "
            "This is a warning, not proof that the site is a phishing site.",
            ["Do not enter passwords or personal details.",
             "Type the official website address yourself instead of using this link.",
             "Ask the person or company that sent the link through another channel."])
    if score >= ORANGE_MIN:
        return Assessment(
            "orange", "Suspicious signs",
            f"Some warning patterns were found (score {score}). They deserve attention "
            "but are not proof of anything.",
            ["Look closely at the main domain name before continuing.",
             "Avoid entering a password unless you are sure it is the real site.",
             "Open the official site by typing its address yourself."])
    return Assessment(
        "green", "No obvious warning signs",
        "None of LoginGuard's configured warning patterns were found. "
        "This does NOT guarantee the website is safe.",
        ["Still be careful with passwords and payments.",
         "Check that the domain is exactly what you expect."])
