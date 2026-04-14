"""
SafeClick — main.py

FastAPI server that receives URLs (and optional HTML signals from the browser)
and returns a phishing risk assessment combining ML model predictions
with a rule-based scoring engine.

Usage:
    uvicorn main:app --reload                  # Development
    uvicorn main:app --host 0.0.0.0 --port 10000  # Production (e.g. Render)

Coding standard: PEP 8 + Google Python Style Guide
https://google.github.io/styleguide/pyguide.html
"""

import os
import re

import joblib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from feature_extractor import (
    extract,
    to_vector,
)

# ─── App setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SafeClick API",
    description=(
        "AI-powered phishing URL detection — returns risk level, "
        "risk score, and human-readable reasons."
    ),
    version="1.1.0",
)

raw_origins = os.getenv("SAFECLICK_CORS_ORIGINS", "*").strip()
allow_origins = ["*"] if raw_origins == "*" else [
    origin.strip() for origin in raw_origins.split(",") if origin.strip()
]

# Allow requests from any origin so the Chrome extension can reach this server.
# In production you may restrict this to your extension's origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ─── ML model loading ─────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")
model = None

if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print(f"✅  Model loaded from {MODEL_PATH}")
    except Exception as exc:  # pragma: no cover
        model = None
        print(f"⚠️   Failed to load model ({exc}) — using rule-based detection only.")
else:
    print(f"⚠️   No model found at {MODEL_PATH} — using rule-based detection only.")


# ─── Request / response schemas ───────────────────────────────────────────────


class HtmlFeatures(BaseModel):
    """Optional page-level signals extracted by content.js in the browser.

    All fields default to 0 so the endpoint still works for URL-only calls
    (e.g. from curl or the popup's re-scan button, which have no DOM access).

    Attributes:
        has_iframe_redirection: 1 if a hidden iframe was found, else 0.
        sfh_score: Form handler score — 0 (safe), 1 (suspicious), 2 (phishing).
        external_resources_ratio: External asset ratio — 0, 1, or 2.
    """

    has_iframe_redirection:   int = 0
    sfh_score:                int = 0
    external_resources_ratio: int = 0


class URLRequest(BaseModel):
    """Incoming analysis request from the Chrome extension.

    Attributes:
        url:           The full URL to analyze.
        html_features: Optional DOM signals from the browser content script.
    """

    url:           str
    html_features: HtmlFeatures | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        """Validates and sanitizes the incoming URL.

        Args:
            value: Raw URL string from the request body.

        Returns:
            Cleaned URL string.

        Raises:
            ValueError: If the URL is empty, too long, missing a scheme,
                        or contains invalid characters.
        """
        value = value.strip()

        if not value:
            raise ValueError("URL cannot be empty.")

        if len(value) > 2048:
            raise ValueError("URL exceeds maximum allowed length of 2048 characters.")

        if not re.match(r"^https?://", value, re.IGNORECASE):
            raise ValueError("URL must begin with http:// or https://")

        if any(ord(char) < 32 for char in value):
            raise ValueError("URL contains invalid control characters.")

        return value


# ─── Rule-based scoring engine ────────────────────────────────────────────────


def compute_rule_score(features: dict, html_features: HtmlFeatures | None = None) -> tuple[int, list[str]]:
    """Assigns a numeric risk score based on URL and HTML heuristics.

    Each rule contributes a fixed number of points. The points are summed
    and then combined with the ML model probability in classify().

    Args:
        features:      Feature dict from extract().
        html_features: Optional DOM signals from the browser.

    Returns:
        A tuple of (score, reasons) where:
        - score is an integer (higher = more dangerous)
        - reasons is a list of human-readable explanation strings
    """
    score:   int       = 0
    reasons: list[str] = []

    # ── URL-level rules ───────────────────────────────────────────────────────

    if features["has_ip"]:
        score += 40
        reasons.append("Uses a raw IP address instead of a domain name")

    if not features["has_https"]:
        score += 20
        reasons.append("No secure HTTPS connection")

    if features["phishing_words"] >= 2:
        score += 25
        reasons.append("Contains multiple phishing-related keywords")

    if features["url_length"] > 100:
        score += 15
        reasons.append("Unusually long URL")

    if features["subdomain_count"] > 2:
        score += 20
        reasons.append("Excessive number of subdomains")

    if features["domain_entropy"] > 3.8:
        score += 15
        reasons.append("Domain name appears to be auto-generated")

    if features["has_at"]:
        score += 30
        reasons.append("Contains @ symbol in URL (classic phishing trick)")

    if features["suspicious_tld"]:
        score += 20
        reasons.append("Uses a high-risk free domain extension (.tk, .ml, .xyz…)")

    if features["double_slash"]:
        score += 15
        reasons.append("Hidden redirect detected (double-slash in path)")

    if features["is_shortened"]:
        score += 25
        reasons.append("URL passes through a shortening service — destination unknown")

    # ── HTML-level rules (only when the browser sends DOM signals) ────────────

    if html_features is not None:

        if html_features.has_iframe_redirection:
            score += 35
            reasons.append("Page contains a hidden iframe (silent redirect technique)")

        if html_features.sfh_score == 2:
            score += 30
            reasons.append("Form submits to a blank handler — likely harvesting credentials")
        elif html_features.sfh_score == 1:
            score += 15
            reasons.append("Form submits to an external domain different from the current site")

        if html_features.external_resources_ratio == 2:
            score += 35
            reasons.append("Over 61% of page resources are loaded from external domains")
        elif html_features.external_resources_ratio == 1:
            score += 20
            reasons.append("Significant portion of page resources come from external domains")

    return score, reasons


# ─── Classification ───────────────────────────────────────────────────────────


def classify(
    features: dict,
    html_features: HtmlFeatures | None = None,
) -> tuple[str, list[str], float, float | None, float, int]:
    """Combines ML model probability with rule-based score to classify a URL.

    When the model is available, the final score is a weighted blend:
        final = (ml_probability × 70%) + (rule_score × 30%)

    When no model is loaded, only the rule-based score is used.

    Thresholds:
        final >= 50 → dangerous
        final >= 25 → suspicious
        final <  25 → safe

    Args:
        features:      URL feature dict from extract().
        html_features: Optional DOM signals from the browser.

    Returns:
        A tuple of (level, reasons, risk_score, ml_probability, final_score, rule_score)
        where:
        - level is "safe", "suspicious", or "dangerous"
        - reasons is a list of human-readable explanation strings
        - risk_score is the normalized final score (0.0–1.0)
        - ml_probability is the model phishing probability (0.0–1.0) or None
        - final_score is the blended score in 0–100 used for thresholds
        - rule_score is the raw rule-based score in 0–100+
    """
    rule_score, reasons = compute_rule_score(features, html_features)

    if model:
        vector         = to_vector(features)
        ml_probability = float(model.predict_proba([vector])[0][1])
        final_score    = (ml_probability * 100 * 0.7) + (rule_score * 0.3)
    else:
        ml_probability = None
        final_score    = float(rule_score)

    final_score = max(0.0, min(final_score, 100.0))
    risk_score  = round(final_score / 100, 2)
    ml_score    = round(ml_probability, 2) if ml_probability is not None else None

    if final_score >= 50:
        return "dangerous", reasons, risk_score, ml_score, round(final_score, 1), rule_score
    if final_score >= 25:
        return "suspicious", reasons, risk_score, ml_score, round(final_score, 1), rule_score
    return "safe", [], risk_score, ml_score, round(final_score, 1), rule_score


# ─── API endpoints ────────────────────────────────────────────────────────────


@app.post("/analyze")
def analyze(request: URLRequest):
    """Analyzes a URL for phishing risk.

    Accepts a URL and optional HTML features from the browser, runs the
    full detection pipeline, and returns a structured risk assessment.

    Args:
        request: URLRequest body with url and optional html_features.

    Returns:
        A JSON object with:
        - url:            The analyzed URL.
        - risk_level:     "safe", "suspicious", or "dangerous".
        - risk_score:     Final normalized risk score (0.0–1.0).
        - final_score:    Final blended score used for classification (0–100).
        - ml_probability: Model phishing probability (0.0–1.0), or null if no model.
        - rule_score:     Raw rule-based score before blending.
        - message:        Human-readable summary.
        - reasons:        List of specific threat signals found.
        - features:       Full URL feature dict (for debugging / popup display).
    """
    features = extract(request.url)
    level, reasons, risk_score, ml_probability, final_score, rule_score = classify(
        features,
        request.html_features,
    )

    messages = {
        "safe":       "Site appears safe.",
        "suspicious": "Suspicious site — proceed with caution.",
        "dangerous":  "Warning! Potential phishing site detected.",
    }

    return {
        "url":            request.url,
        "risk_level":     level,
        "risk_score":     risk_score,
        "final_score":    final_score,
        "ml_probability": ml_probability,
        "rule_score":     rule_score,
        "message":        messages[level],
        "reasons":        reasons,
        "features":       features,
    }


@app.get("/")
def root():
    """Returns a lightweight API status payload for browser root checks."""
    return {
        "name": "SafeClick API",
        "status": "running",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health():
    """Health check endpoint used by uptime monitors and deployment platforms.

    Returns:
        A JSON object confirming the server is running and whether the
        ML model was successfully loaded.
    """
    return {
        "status":       "running",
        "model_loaded": model is not None,
    }
