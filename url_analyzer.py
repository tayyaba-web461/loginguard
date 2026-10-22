"""url_analyzer.py - Rule-based URL analysis.

This file only looks at the TEXT of a URL. It never opens, downloads or
runs anything from the website.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048

LOGIN_WORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "account", "secure",
    "update", "password", "banking", "wallet", "confirm",
)
BRAND_WORDS = (
    "paypal", "google", "facebook", "instagram", "microsoft", "apple",
    "amazon", "netflix", "whatsapp", "paytm", "hdfc", "icici",
)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at",
}
# Small list of two-part endings so "shop.example.co.in" is read correctly.
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "co.in", "net.in", "org.in", "ac.in", "gov.in",
    "com.au", "com.br", "co.jp", "com.cn",
}


@dataclass
class Finding:
    code: str
    title: str
    points: int
    explanation: str


@dataclass
class UrlAnalysis:
    valid: bool
    original: str
    error: str | None = None
    normalized: str | None = None
    hostname: str | None = None
    notes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(f.points for f in self.findings)


def parse_url(raw: str):
    """Check the input and split it into parts. Raises ValueError if bad."""
    text = (raw or "").strip()
    if not text:
        raise ValueError("Please enter a website address.")
    if len(text) > MAX_URL_LENGTH:
        raise ValueError(f"That address is too long (limit is {MAX_URL_LENGTH} characters).")
    if re.search(r"[\s\x00-\x1f\x7f]", text):
        raise ValueError("The address contains spaces or hidden control characters.")

    note = None
    if "://" not in text:
        text = "https://" + text
        note = "No http:// or https:// was typed, so https:// was assumed for this check."

    try:
        parts = urlsplit(text)
        host = parts.hostname
        parts.port  # raises ValueError if the port is not a valid number
    except ValueError:
        raise ValueError("That does not look like a valid web address.") from None

    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// addresses can be checked.")
    if not host:
        raise ValueError("No website name was found in the address.")
    if not _is_ip_like(host) and ("." not in host or "" in host.split(".")):
        raise ValueError("That does not look like a public website name (example: example.com).")
    return parts, note


def _is_ip_like(host: str) -> bool:
    """True for normal IPs and for tricky forms like 3232235777 or 0xC0A80001."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d+|0x[0-9a-f]+", host))


def split_host(host: str):
    """Return (registered_domain, list_of_subdomain_labels)."""
    labels = host.split(".")
    n = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES else 2
    if len(labels) <= n:
        return host, []
    return ".".join(labels[-n:]), labels[:-n]


def analyze_url(raw: str) -> UrlAnalysis:
    """Run every rule and return the findings. Never visits the URL."""
    try:
        parts, note = parse_url(raw)
    except ValueError as err:
        return UrlAnalysis(valid=False, original=raw or "", error=str(err))

    host = parts.hostname
    scheme = parts.scheme.lower()
    normalized = parts.geturl()
    result = UrlAnalysis(valid=True, original=raw, normalized=normalized, hostname=host)
    if note:
        result.notes.append(note)

    full_lower = normalized.lower()
    login_related = any(w in full_lower for w in LOGIN_WORDS)
    add = result.findings.append

    # 1. HTTP instead of HTTPS
    if scheme == "http":
        if login_related:
            add(Finding("http_login", "Not encrypted (HTTP) and looks login-related", 2,
                        "The address uses http:// and has words like 'login' or 'verify'. "
                        "Information typed on HTTP pages can be read by others on the network."))
        else:
            add(Finding("http", "Not encrypted (HTTP)", 1,
                        "The address uses http:// instead of https://. "
                        "Avoid typing any private information on it."))

    # 2. IP address as hostname
    if _is_ip_like(host):
        add(Finding("ip_host", "IP address used instead of a website name", 3,
                    "Real companies almost always use a normal name like example.com, "
                    "not a string of numbers."))
        registered, subdomains = host, []
    else:
        registered, subdomains = split_host(host)

    # 3. Too many subdomains
    if len(subdomains) >= 3:
        add(Finding("many_subdomains", "Many subdomains", 2,
                    f"The address has {len(subdomains)} parts before the main domain. "
                    "Attackers sometimes stack names to hide the real domain."))

    # 4. Encoded / international characters
    labels = host.split(".")
    if any(l.startswith("xn--") for l in labels) or not host.isascii():
        add(Finding("idn", "International (encoded) characters in the domain", 2,
                    "Some letters can look like others (for example, Cyrillic 'а' vs. Latin 'a'). "
                    "This is a known trick for look-alike domains, though many real sites use it."))

    # 5. Username/password inside the URL
    if parts.username is not None or "@" in parts.netloc:
        add(Finding("userinfo", "Username or '@' inside the address", 3,
                    "In 'https://trusted.com@other.com', the real website is the part AFTER the '@'. "
                    "This trick makes a link look like it belongs to a trusted site."))

    # 6. Brand name used but not the real domain
    if not _is_ip_like(host):
        main_label = registered.split(".")[0]
        for brand in BRAND_WORDS:
            if brand in host and main_label != brand:
                add(Finding("brand_mismatch", "Famous brand name inside a different domain", 2,
                            "The address contains a well-known brand name, but the main domain "
                            "is something else. Check carefully that the main domain is the real one."))
                break

    # 7. URL shortener
    if registered in SHORTENERS:
        add(Finding("shortener", "Link shortener", 1,
                    "Short links hide the real destination. LoginGuard does not follow links, "
                    "so it cannot tell where this one goes."))

    # 8. Unusual port
    if parts.port not in (None, 80, 443):
        add(Finding("odd_port", "Unusual port number", 1,
                    f"The address uses port {parts.port}. Normal websites rarely do this."))

    # 9. Many hyphens in the host
    if host.count("-") >= 3:
        add(Finding("hyphens", "Many hyphens in the domain", 1,
                    "Long hyphenated names (like secure-login-update-bank.com) are common in fake sites."))

    # 10. Very long URL
    if len(normalized) > 100:
        add(Finding("long_url", "Very long address", 1,
                    "Long addresses can hide the important part. Look at the main domain carefully."))

    # 11. Login-style words
    if login_related:
        add(Finding("login_words", "Login-style words in the address", 1,
                    "Words like 'login', 'verify' or 'secure' are common in phishing links, "
                    "but also in many real sites."))

    return result
