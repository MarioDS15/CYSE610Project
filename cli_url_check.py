#!/usr/bin/env python3
"""
Command-line tool for checking URL phishing risk.

This uses the heuristic-based `quick_url_check` helper to avoid any
requirement for a pre-trained model. It reports whether the URL is
considered phishing as well as the associated confidence score.
"""

import os
import sys
from typing import Any, Dict, Tuple

# Ensure the project modules are importable when running from the repo root
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
ML_PATH = os.path.join(PROJECT_ROOT, "ML")
URL_PATH = os.path.join(ML_PATH, "URL")

if ML_PATH not in sys.path:
    sys.path.append(ML_PATH)
if URL_PATH not in sys.path:
    sys.path.append(URL_PATH)

from example_usage import quick_url_check  # noqa: E402  (import after sys.path tweak)


def cli_check_url(url: str) -> Tuple[str, float, Dict[str, Any]]:
    """
    Analyze a URL and return its phishing status and confidence.

    Returns:
        status (str): "PHISHING" or "SAFE"
        confidence (float): Confidence score between 0 and 1
        details (dict): Full result dictionary from quick_url_check
    """
    details = quick_url_check(url)
    status = "PHISHING" if details["is_phishing"] else "SAFE"
    confidence = details["confidence"]
    return status, confidence, details


def _format_bool(flag: bool) -> str:
    return "yes" if flag else "no"


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] in {"-h", "--help"}:
        print("Usage: python cli_url_check.py <url>")
        print("Example: python cli_url_check.py https://www.google.com")
        sys.exit(1)

    url = sys.argv[1]

    status, confidence, details = cli_check_url(url)

    print(f"URL: {url}")
    print(f"Prediction: {status}")
    print(f"Confidence: {confidence:.3f}")
    print(f"Risk Score: {details['risk_score']}/100")
    print(f"Risk Level: {details['risk_level']}")

    suspicious = details.get("suspicious_factors", {})
    domain = details.get("domain_factors", {})

    print("\nKey Indicators:")
    print(f"  Suspicious keywords: {_format_bool(suspicious.get('has_suspicious_keywords', False))}")
    print(f"  Brand impersonation: {_format_bool(suspicious.get('has_brand_names', False))}")
    print(f"  Suspicious TLD: {_format_bool(suspicious.get('has_suspicious_tld', False))}")
    print(f"  URL shortener: {_format_bool(suspicious.get('is_shortened', False))}")
    print(f"  IP address in URL: {_format_bool(suspicious.get('has_ip_address', False))}")
    print(f"  Numbers in domain: {_format_bool(domain.get('has_numbers', False))}")
    print(f"  URL length: {details['domain_factors'].get('domain_length', 0)} characters in domain")


if __name__ == "__main__":
    main()

