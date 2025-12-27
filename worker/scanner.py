from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class Finding:
    severity: str
    title: str
    description: str | None = None
    evidence: str | None = None
    recommendation: str | None = None


def scan_target(url: str, timeout_seconds: int, user_agent: str) -> list[Finding]:
    """Lightweight MVP scanner (HTTP-based).

    This is intentionally simple to be deployable anywhere.

    Later we can replace/extend with WPScan, Nuclei, etc.
    """

    findings: list[Finding] = []

    headers = {"User-Agent": user_agent}

    # 1) Basic reachability
    try:
        r = requests.get(url, timeout=timeout_seconds, headers=headers, allow_redirects=True)
    except requests.RequestException as e:
        findings.append(
            Finding(
                severity="high",
                title="Target not reachable",
                description="The target URL could not be reached.",
                evidence=str(e),
                recommendation="Verify the domain resolves and the server is reachable from the internet.",
            )
        )
        return findings

    findings.append(
        Finding(
            severity="info",
            title="Target reachable",
            description=f"HTTP {r.status_code} received.",
            evidence=f"Final URL: {r.url}",
        )
    )

    # 2) WordPress heuristics
    body_lower = (r.text or "").lower()
    if "wp-content" in body_lower or "wp-includes" in body_lower:
        findings.append(
            Finding(
                severity="info",
                title="WordPress footprint detected",
                description="The page content contains typical WordPress paths.",
                evidence="Found wp-content/wp-includes in HTML.",
            )
        )
    else:
        findings.append(
            Finding(
                severity="low",
                title="No obvious WordPress footprint",
                description="No wp-content/wp-includes strings found in the HTML.",
                recommendation="If this is a WordPress site, it may be hidden behind caching/WAF or using a headless setup.",
            )
        )

    # 3) Exposed REST users endpoint
    try:
        users = requests.get(
            url.rstrip("/") + "/wp-json/wp/v2/users",
            timeout=timeout_seconds,
            headers=headers,
            allow_redirects=True,
        )
        if users.status_code == 200 and users.headers.get("content-type", "").lower().startswith("application/json"):
            findings.append(
                Finding(
                    severity="medium",
                    title="Possible user enumeration via REST API",
                    description="The WordPress REST users endpoint returned JSON.",
                    evidence=f"GET /wp-json/wp/v2/users -> {users.status_code}",
                    recommendation="Restrict user endpoints or require authentication. Consider security plugins or custom rules.",
                )
            )
    except requests.RequestException:
        pass

    # 4) Missing security headers
    headers_lower: dict[str, Any] = {k.lower(): v for k, v in r.headers.items()}
    for header, severity, recommendation in [
        ("content-security-policy", "medium", "Add a Content-Security-Policy to reduce XSS risk."),
        ("x-frame-options", "low", "Add X-Frame-Options or frame-ancestors to reduce clickjacking risk."),
        ("strict-transport-security", "low", "Enable HSTS if the site is served over HTTPS."),
    ]:
        if header not in headers_lower:
            findings.append(
                Finding(
                    severity=severity,
                    title=f"Missing security header: {header}",
                    recommendation=recommendation,
                )
            )

    return findings
