"""
SecureScan - Core Scanning Engine
----------------------------------
Performs a set of safe, read-only checks against a target web application:
  - HTTP security header analysis
  - TLS/SSL certificate inspection
  - Cookie flag analysis
  - Server / technology banner disclosure
  - Common open port sweep
  - Sensitive file / path exposure check
  - Lightweight reflected XSS probe (non-executing marker string)
  - Lightweight error-based SQL injection probe

NOTE: This tool is intended for authorized testing of applications you own
or have explicit permission to assess. It performs no destructive actions.
"""

import re
import socket
import ssl
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests

requests.packages.urllib3.disable_warnings()

TIMEOUT = 6
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/wp-config.php.bak", "/config.php.bak",
    "/.DS_Store", "/backup.zip", "/.htaccess", "/server-status",
    "/phpinfo.php", "/.aws/credentials",
]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sqlite3.OperationalError", "psql: error", "ORA-01756",
    "pg_query()", "SQLSTATE", "Microsoft OLE DB Provider for SQL Server",
]

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}


def _finding(check, severity, title, detail, recommendation):
    return {
        "id": str(uuid.uuid4())[:8],
        "check": check,
        "severity": severity,
        "title": title,
        "detail": detail,
        "recommendation": recommendation,
    }


def normalize_url(target):
    target = target.strip()
    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target
    return target


def check_security_headers(resp, findings):
    headers = {k.lower(): v for k, v in resp.headers.items()}
    required = {
        "content-security-policy": ("medium", "Content-Security-Policy is missing",
            "Add a CSP to restrict where scripts, styles, and frames may load from."),
        "x-frame-options": ("medium", "X-Frame-Options is missing",
            "Set to SAMEORIGIN or DENY to prevent clickjacking via iframes."),
        "strict-transport-security": ("high", "HTTP Strict-Transport-Security (HSTS) is missing",
            "Add Strict-Transport-Security to force browsers to use HTTPS only."),
        "x-content-type-options": ("low", "X-Content-Type-Options is missing",
            "Set to 'nosniff' to stop browsers from MIME-sniffing responses."),
        "referrer-policy": ("low", "Referrer-Policy is missing",
            "Set a restrictive Referrer-Policy such as 'strict-origin-when-cross-origin'."),
        "permissions-policy": ("info", "Permissions-Policy is missing",
            "Define a Permissions-Policy to limit access to browser features (camera, mic, etc)."),
    }
    for header, (sev, title, rec) in required.items():
        if header not in headers:
            findings.append(_finding("Security Headers", sev, title,
                f"The response did not include a '{header}' header.", rec))
    if "server" in headers:
        findings.append(_finding("Information Disclosure", "low",
            "Server banner reveals software details",
            f"Server header value: '{headers['server']}'.",
            "Suppress or genericize the Server header to avoid revealing stack details."))
    if "x-powered-by" in headers:
        findings.append(_finding("Information Disclosure", "low",
            "X-Powered-By header reveals technology stack",
            f"X-Powered-By value: '{headers['x-powered-by']}'.",
            "Remove the X-Powered-By header from responses."))


def check_cookies(resp, findings):
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie._rest).lower():
            issues.append("missing HttpOnly flag")
        samesite = cookie._rest.get("SameSite") if hasattr(cookie, "_rest") else None
        if not samesite:
            issues.append("missing SameSite attribute")
        if issues:
            findings.append(_finding("Cookie Security", "medium",
                f"Cookie '{cookie.name}' has weak attributes",
                f"Issues: {', '.join(issues)}.",
                "Set Secure, HttpOnly, and SameSite=Lax/Strict on session cookies."))


def check_tls(parsed_url, findings):
    if parsed_url.scheme != "https":
        findings.append(_finding("Transport Security", "critical",
            "Site is not served over HTTPS",
            "The target responded on plain HTTP, exposing traffic to interception.",
            "Serve the entire application over HTTPS and redirect HTTP to HTTPS."))
        return
    host = parsed_url.hostname
    port = parsed_url.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append(_finding("Transport Security", "critical",
                        "TLS certificate has expired",
                        f"Certificate expired {abs(days_left)} day(s) ago.",
                        "Renew the TLS certificate immediately."))
                elif days_left < 14:
                    findings.append(_finding("Transport Security", "high",
                        "TLS certificate is expiring soon",
                        f"Certificate expires in {days_left} day(s).",
                        "Renew the certificate before it expires to avoid a browser warning outage."))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {"issuer": issuer.get("organizationName", "Unknown"), "expires": cert["notAfter"], "days_left": days_left}
    except ssl.SSLCertVerificationError as e:
        findings.append(_finding("Transport Security", "critical",
            "TLS certificate validation failed",
            str(e),
            "Install a valid certificate from a trusted CA covering the exact hostname."))
    except Exception as e:
        findings.append(_finding("Transport Security", "info",
            "Could not fully verify TLS configuration",
            str(e),
            "Manually verify the certificate chain and TLS configuration."))
    return None


def check_open_ports(host, findings):
    open_ports = []
    for port, name in COMMON_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((host, port)) == 0:
                    open_ports.append((port, name))
        except Exception:
            continue
    risky = {21, 23, 3306, 3389}
    for port, name in open_ports:
        if port in risky:
            findings.append(_finding("Network Exposure", "high",
                f"Port {port} ({name}) is open and internet-reachable",
                f"An unauthenticated TCP handshake succeeded on port {port}.",
                "Restrict this port to trusted networks via firewall rules or a VPN."))
        elif port not in (80, 443):
            findings.append(_finding("Network Exposure", "low",
                f"Port {port} ({name}) is open",
                f"An unauthenticated TCP handshake succeeded on port {port}.",
                "Confirm this service needs to be publicly reachable; close it if not."))
    return open_ports


def check_sensitive_paths(base_url, findings):
    exposed = []
    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(urljoin(base_url, path), timeout=TIMEOUT, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                exposed.append(path)
                findings.append(_finding("Sensitive Exposure", "high",
                    f"Potentially sensitive path is publicly accessible: {path}",
                    f"Request to {path} returned HTTP 200.",
                    "Remove the file from the public web root or block access at the web server level."))
        except requests.RequestException:
            continue
    return exposed


def check_reflected_xss(base_url, findings):
    marker = "sscan" + str(uuid.uuid4())[:6] + "<x>"
    test_url = base_url.rstrip("/") + "/?q=" + marker
    try:
        r = requests.get(test_url, timeout=TIMEOUT, verify=False)
        if marker in r.text:
            findings.append(_finding("Input Validation", "high",
                "Unsanitized input reflected in page response",
                "A harmless marker string sent via the 'q' query parameter was echoed back "
                "into the page without encoding, suggesting a possible reflected XSS vector.",
                "HTML-encode all user-controlled output and apply a strict Content-Security-Policy."))
    except requests.RequestException:
        pass


def check_sqli_signatures(base_url, findings):
    payloads = ["'", "' OR '1'='1", "1;--"]
    for payload in payloads:
        test_url = base_url.rstrip("/") + "/?id=" + requests.utils.quote(payload)
        try:
            r = requests.get(test_url, timeout=TIMEOUT, verify=False)
            lowered = r.text.lower()
            for sig in SQLI_ERROR_SIGNATURES:
                if sig.lower() in lowered:
                    findings.append(_finding("Input Validation", "critical",
                        "Possible SQL injection vulnerability detected",
                        f"A database error signature ('{sig}') appeared after sending a test payload "
                        f"to a query parameter.",
                        "Use parameterized queries / prepared statements and never build SQL via string concatenation."))
                    return
        except requests.RequestException:
            continue


def compute_grade(findings):
    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHT.get(f["severity"], 0)
    score = max(score, 0)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def run_scan(target):
    start = time.time()
    url = normalize_url(target)
    parsed = urlparse(url)
    findings = []
    meta = {"target": url, "host": parsed.hostname}

    try:
        resp = requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
    except requests.exceptions.SSLError:
        return {"ok": False, "error": "TLS handshake failed — the certificate could not be validated.", "target": url}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": "Could not connect to the target. Check the domain and that it's publicly reachable.", "target": url}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "The target took too long to respond.", "target": url}
    except requests.RequestException as e:
        return {"ok": False, "error": f"Could not reach target: {e}", "target": url}

    meta["status_code"] = resp.status_code
    meta["final_url"] = resp.url

    check_security_headers(resp, findings)
    check_cookies(resp, findings)
    tls_info = check_tls(parsed, findings)
    if tls_info:
        meta["tls"] = tls_info
    open_ports = check_open_ports(parsed.hostname, findings)
    meta["open_ports"] = [{"port": p, "service": n} for p, n in open_ports]
    exposed = check_sensitive_paths(url, findings)
    meta["exposed_paths"] = exposed
    check_reflected_xss(url, findings)
    check_sqli_signatures(url, findings)

    score, grade = compute_grade(findings)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] += 1

    findings.sort(key=lambda f: SEVERITY_WEIGHT.get(f["severity"], 0), reverse=True)

    return {
        "ok": True,
        "meta": meta,
        "findings": findings,
        "counts": counts,
        "score": score,
        "grade": grade,
        "duration_ms": int((time.time() - start) * 1000),
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
