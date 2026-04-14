"""
SafeClick — feature_extractor.py

Extracts phishing-detection features from URLs and raw HTML.
Used by both the ML model pipeline and the rule-based scoring engine.

Coding standard: PEP 8 + Google Python Style Guide
https://google.github.io/styleguide/pyguide.html
"""

import math
import re
import urllib.parse

# ─── Phishing keyword list ─────────────────────────────────────────────────────
# Words commonly found in phishing URLs. The more that appear, the higher
# the risk score. Extend this set to improve detection coverage.

PHISHING_KEYWORDS: set[str] = {
    "login", "verify", "update", "secure", "account",
    "banking", "paypal", "amazon", "apple", "microsoft",
    "signin", "password", "credential", "confirm", "suspend",
    "urgent", "click", "free", "prize", "winner", "validate",
}

# ─── Known URL-shortening services ────────────────────────────────────────────
# Shortened URLs hide the real destination. Any match adds risk points.

URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "t.co", "short.link", "rb.gy", "cutt.ly",
    "tiny.cc", "shorturl.at", "bl.ink", "snip.ly", "rebrand.ly",
    "shorte.st", "adf.ly", "bc.vc", "lnkd.in", "mcaf.ee",
}

# ─── Suspicious top-level domains ─────────────────────────────────────────────
# These free TLDs are frequently abused for phishing campaigns.

SUSPICIOUS_TLDS: set[str] = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work"}


# ─── Utility functions ─────────────────────────────────────────────────────────


def shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string.

    High entropy suggests auto-generated (random) domain names, which are
    common in phishing campaigns to avoid blocklists.

    Args:
        text: The string to measure (typically a domain name).

    Returns:
        A float representing the entropy. Higher = more random.
    """
    if not text:
        return 0.0

    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def count_subdomains(domain: str) -> int:
    """Returns the number of subdomains in a domain string.

    For example: sub1.sub2.example.com → 2 subdomains.
    Excessive subdomains (> 2) are a phishing indicator.

    Args:
        domain: A normalized domain string (no scheme, no path).

    Returns:
        The subdomain count as an integer.
    """
    parts = domain.split(".")
    return max(0, len(parts) - 2)


def normalize_domain(raw_domain: str) -> str:
    """Converts internationalized (IDN/punycode) domains to ASCII.

    Phishing pages sometimes use Unicode lookalike characters
    (e.g. pаypal.com with a Cyrillic 'а') to deceive users.
    Normalizing ensures comparisons work correctly.

    Args:
        raw_domain: The raw domain string from a parsed URL.

    Returns:
        ASCII-encoded domain string. Falls back to the original on error.
    """
    try:
        return raw_domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return raw_domain


def is_url_shortened(url: str) -> int:
    """Checks if a URL passes through a known shortening service.

    Args:
        url: The full URL string.

    Returns:
        1 if shortened, 0 otherwise.
    """
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "")
    return int(domain in URL_SHORTENERS)


# ─── URL feature extraction ───────────────────────────────────────────────────


def extract(url: str) -> dict:
    """Extracts all URL-level phishing features from a single URL.

    This function is the primary feature source for the ML model.
    The output key order must remain stable — to_vector() depends on it.

    HTML-dependent signals (iframes, form handlers, external resources)
    are extracted separately by the browser and passed in html_features.

    Args:
        url: A fully qualified URL string (must begin with http:// or https://).

    Returns:
        A dict of 20 named features. All values are int or float.

    Example:
        >>> features = extract("http://paypal-login.tk/verify")
        >>> features["has_ip"]
        0
        >>> features["suspicious_tld"]
        1
    """
    parsed     = urllib.parse.urlparse(url)
    raw_domain = parsed.netloc.lower().replace("www.", "")
    domain     = normalize_domain(raw_domain)
    path       = parsed.path.lower()
    query      = parsed.query
    full_url   = url.lower()

    # ── Length features ──────────────────────────────────────────────────────
    url_length    = len(url)
    domain_length = len(domain)
    path_length   = len(path)

    # ── Structural red flags ─────────────────────────────────────────────────
    # Raw IP addresses in place of domain names are a strong phishing signal.
    has_ip       = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", domain))
    has_at       = "@" in url          # '@' tricks parsers into using a fake domain
    double_slash = url.count("//") > 1  # Hidden redirect via extra slash
    has_port     = bool(parsed.port and parsed.port not in (80, 443))
    is_shortened = is_url_shortened(url)

    # ── Content signals ───────────────────────────────────────────────────────
    phishing_word_count = sum(word in full_url for word in PHISHING_KEYWORDS)
    digit_count_domain  = sum(char.isdigit() for char in domain)
    hyphen_count        = domain.count("-")
    dot_count           = url.count(".")
    special_chars       = sum(url.count(char) for char in ["@", "!", "~", "%", "="])

    # ── Structural composition ────────────────────────────────────────────────
    subdomain_count = count_subdomains(domain)
    path_depth      = path.count("/")
    query_params    = len(urllib.parse.parse_qs(query))
    tld             = domain.split(".")[-1] if "." in domain else ""
    suspicious_tld  = tld in SUSPICIOUS_TLDS

    # ── Protocol ─────────────────────────────────────────────────────────────
    has_https   = parsed.scheme == "https"
    has_encoded = "%" in url  # Percent-encoded chars can hide phishing words

    # ── Entropy ──────────────────────────────────────────────────────────────
    domain_entropy = shannon_entropy(domain)

    return {
        "url_length":          url_length,
        "domain_length":       domain_length,
        "path_length":         path_length,
        "has_ip":              int(has_ip),
        "has_at":              int(has_at),
        "double_slash":        int(double_slash),
        "has_port":            int(has_port),
        "is_shortened":        is_shortened,
        "phishing_words":      phishing_word_count,
        "digit_count_domain":  digit_count_domain,
        "hyphen_count":        hyphen_count,
        "dot_count":           dot_count,
        "special_chars":       special_chars,
        "subdomain_count":     subdomain_count,
        "path_depth":          path_depth,
        "query_params":        query_params,
        "suspicious_tld":      int(suspicious_tld),
        "has_https":           int(has_https),
        "has_encoded":         int(has_encoded),
        "domain_entropy":      round(domain_entropy, 4),
    }


def to_vector(features: dict) -> list:
    """Converts a feature dict to a fixed-order list for the ML model.

    The ML model was trained on features in a specific column order.
    This function enforces that order regardless of dict insertion order.

    Args:
        features: The dict returned by extract().

    Returns:
        A list of 20 numeric values in the expected column order.
    """
    ordered_keys = [
        "url_length", "domain_length", "path_length",
        "has_ip", "has_at", "double_slash", "has_port",
        "is_shortened",
        "phishing_words", "digit_count_domain", "hyphen_count",
        "dot_count", "special_chars", "subdomain_count",
        "path_depth", "query_params", "suspicious_tld",
        "has_https", "has_encoded", "domain_entropy",
    ]
    return [features[key] for key in ordered_keys]


# ─── HTML feature extraction (server-side) ────────────────────────────────────
# These functions are called when the browser sends raw page HTML.
# They mirror the DOM-based checks in content.js but run on the server.


def has_iframe_redirection(html: str) -> int:
    """Detects hidden or invisible iframes in raw HTML.

    Hidden iframes are used to silently redirect users or load
    malicious content without their knowledge.

    Checks for:
    - frameborder=0 (invisible border)
    - width or height of 0 or 1 pixel

    Args:
        html: Raw HTML string of the page.

    Returns:
        1 if a suspicious iframe is found, 0 otherwise.
    """
    iframe_tags = re.findall(r"<iframe[^>]*>", html, re.IGNORECASE)

    for tag in iframe_tags:
        # Check for zero border
        if re.search(r'frameborder\s*=\s*["\']?0["\']?', tag, re.IGNORECASE):
            return 1

        # Check for near-zero dimensions
        width_match  = re.search(r'width\s*=\s*["\']?(\d+)', tag, re.IGNORECASE)
        height_match = re.search(r'height\s*=\s*["\']?(\d+)', tag, re.IGNORECASE)

        if width_match and int(width_match.group(1)) <= 1:
            return 1
        if height_match and int(height_match.group(1)) <= 1:
            return 1

    return 0


def sfh_score(html: str, current_domain: str) -> int:
    """Analyzes Server Form Handler (SFH) attributes in raw HTML.

    Examines <form action="..."> values to detect credential harvesting:
    - Empty or about:blank action → form data captured by script (score: 2)
    - Action pointing to an external domain → submits data elsewhere (score: 1)
    - No forms, or all relative paths → legitimate (score: 0)

    Args:
        html:           Raw HTML string of the page.
        current_domain: Normalized domain of the current page (no www.).

    Returns:
        An integer score: 0 = legitimate, 1 = suspicious, 2 = phishing.
    """
    form_tags = re.findall(r"<form[^>]*>", html, re.IGNORECASE)
    if not form_tags:
        return 0  # No forms — not a credential harvesting page

    worst_score = 0

    for tag in form_tags:
        action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)

        if not action_match:
            worst_score = max(worst_score, 2)  # No action attr → phishing
            continue

        action = action_match.group(1).strip().lower()

        if not action or action == "about:blank":
            worst_score = max(worst_score, 2)  # Blank action → data harvested by JS

        elif action.startswith("http") or action.startswith("//"):
            # Absolute URL — check if it targets the same domain
            normalized = action if action.startswith("http") else "http:" + action
            parsed      = urllib.parse.urlparse(normalized)
            form_domain = parsed.netloc.lower().replace("www.", "")

            if form_domain and form_domain != current_domain:
                worst_score = max(worst_score, 1)  # Submits to external domain

        # Relative paths ("/submit", "process.php") are benign — no penalty

    return worst_score


def external_resources_ratio(html: str, current_domain: str) -> int:
    """Measures the proportion of page resources loaded from external domains.

    Phishing pages often copy a real site's look by hot-linking all
    images and scripts from the legitimate domain while hosting only
    the fake form locally.

    Scoring thresholds:
    - < 22% external  → 0 (legitimate)
    - 22–61% external → 1 (suspicious)
    - > 61% external  → 2 (phishing)

    Args:
        html:           Raw HTML string of the page.
        current_domain: Normalized domain of the current page (no www.).

    Returns:
        An integer score: 0 = legitimate, 1 = suspicious, 2 = phishing.
    """
    resource_patterns = [
        r'<img[^>]+src\s*=\s*["\']([^"\']+)["\']',
        r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']',
        r'<link[^>]+href\s*=\s*["\']([^"\']+)["\']',
    ]

    resources: list[str] = []
    for pattern in resource_patterns:
        resources.extend(re.findall(pattern, html, re.IGNORECASE))

    if not resources:
        return 0

    external_count = 0
    for resource_url in resources:
        if not (resource_url.startswith("http") or resource_url.startswith("//")):
            continue  # Relative path — same domain, skip

        normalized = resource_url if resource_url.startswith("http") else "http:" + resource_url
        parsed      = urllib.parse.urlparse(normalized)
        res_domain  = parsed.netloc.lower().replace("www.", "")

        if res_domain and res_domain != current_domain:
            external_count += 1

    ratio = external_count / len(resources)

    if ratio > 0.61:
        return 2
    if ratio >= 0.22:
        return 1
    return 0
