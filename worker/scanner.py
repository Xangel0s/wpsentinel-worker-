import re
import json
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any
import requests


@dataclass
class Finding:
    severity: str
    title: str
    description: str | None = None
    evidence: str | None = None
    recommendation: str | None = None


@dataclass
class ScanMetrics:
    start_time: int
    plugins_analyzed: int = 0
    themes_analyzed: int = 0
    endpoints_checked: int = 0
    vulnerabilities_found: int = 0
    no_new_findings_count: int = 0
    last_findings_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'scan_duration': time.time() * 1000 - self.start_time,
            'plugins_analyzed': self.plugins_analyzed,
            'themes_analyzed': self.themes_analyzed,
            'endpoints_checked': self.endpoints_checked,
            'vulnerabilities_found': self.vulnerabilities_found,
            'no_new_findings_count': self.no_new_findings_count
        }


def scan_target(url: str, timeout_seconds: int, user_agent: str) -> tuple[list[Finding], ScanMetrics]:
    """Enhanced WordPress scanner."""
    metrics = ScanMetrics(start_time=int(time.time() * 1000))
    findings: list[Finding] = []
    headers = {"User-Agent": user_agent}

    # 1) Basic reachability
    try:
        r = requests.get(url, timeout=timeout_seconds, headers=headers, allow_redirects=True)
        r.raise_for_status()
    except requests.RequestException as e:
        findings.append(
            Finding(
                severity="high",
                title="Target not reachable",
                description="The target URL could not be reached or returned an error.",
                evidence=str(e),
                recommendation="Verify the domain resolves and the server is reachable.",
            )
        )
        return findings, metrics

    findings.append(Finding(severity="info", title="Target reachable", evidence=f"Final URL: {r.url} (HTTP {r.status_code})"))

    body = r.text
    body_lower = body.lower()

    # 2) WordPress Version Detection
    wp_version = None
    # Meta generator tag
    meta_gen = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', body)
    if meta_gen:
        wp_version = meta_gen.group(1)
        findings.append(Finding(severity="info", title=f"WordPress version detected: {wp_version}", evidence="Found in meta generator tag."))
    
    # Check for /readme.html
    try:
        readme = requests.get(url.rstrip("/") + "/readme.html", timeout=5, headers=headers)
        if readme.status_code == 200:
            version_match = re.search(r"<br />\s*Version ([\d.]+)", readme.text)
            if version_match:
                found_v = version_match.group(1)
                if not wp_version or found_v != wp_version:
                    wp_version = found_v
                    findings.append(Finding(severity="info", title=f"WordPress version found in readme.html: {wp_version}"))
            findings.append(Finding(severity="low", title="Public readme.html found", description="Exposing readme.html can reveal the WordPress version.", recommendation="Delete readme.html or restrict access."))
    except: pass

    # 3) Theme Detection
    theme_match = re.search(r"/wp-content/themes/([^/]+)/", body)
    if theme_match:
        theme_name = theme_match.group(1)
        findings.append(Finding(severity="info", title=f"Active theme detected: {theme_name}"))

    # 4) Plugin Detection
    # Scan for common plugins in HTML (only alphanumeric, hyphens, and underscores)
    plugins = set(re.findall(r"/wp-content/plugins/([a-zA-Z0-9\-_]+)/", body))
    if plugins:
        findings.append(
            Finding(
                severity="info",
                title=f"Detected {len(plugins)} plugins",
                description="The following plugins were identified in the page source.",
                evidence=", ".join(list(plugins)[:10]) + ("..." if len(plugins) > 10 else ""),
            )
        )

    # 5) Sensitive Files & Endpoints
    # Check for xmlrpc.php
    try:
        xmlrpc = requests.get(url.rstrip("/") + "/xmlrpc.php", timeout=5, headers=headers)
        if xmlrpc.status_code == 405 or "XML-RPC server accepts POST requests only" in xmlrpc.text:
            findings.append(
                Finding(
                    severity="low",
                    title="XML-RPC enabled",
                    description="XML-RPC can be used for DDoS and brute-force attacks.",
                    recommendation="Disable XML-RPC if not needed or restrict access.",
                )
            )
    except: pass

    # 6) Exposed REST users endpoint
    try:
        users = requests.get(url.rstrip("/") + "/wp-json/wp/v2/users", timeout=5, headers=headers)
        if users.status_code == 200 and "application/json" in users.headers.get("Content-Type", "").lower():
            findings.append(
                Finding(
                    severity="medium",
                    title="User enumeration via REST API",
                    description="The WordPress REST users endpoint returned JSON data.",
                    evidence=f"GET /wp-json/wp/v2/users returned 200",
                    recommendation="Restrict access to the REST API users endpoint.",
                )
            )
    except: pass

    # 7) Security Headers
    headers_lower = {k.lower(): v for k, v in r.headers.items()}
    for header, severity, rec in [
        ("content-security-policy", "medium", "Add a Content-Security-Policy header."),
        ("x-frame-options", "low", "Add X-Frame-Options or frame-ancestors."),
        ("strict-transport-security", "low", "Enable HSTS if using HTTPS."),
    ]:
        if header not in headers_lower:
            findings.append(Finding(severity=severity, title=f"Missing security header: {header}", recommendation=rec))
            metrics.endpoints_checked += 1

    # Update metrics with final counts
    metrics.vulnerabilities_found = sum(1 for f in findings if f.severity in {"low", "medium", "high", "critical"})
    
    return findings, metrics
