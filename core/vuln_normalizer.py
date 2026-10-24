"""
Enterprise Vulnerability Normalization, Enrichment & Classification Engine for YemenScan.
Aligns vulnerability findings with global commercial standards:
- CVSS v3.1 / v4.0 Quantitative Severity Calibration (FIRST.org)
- MITRE CWE Hierarchy & Canonical Taxonomies
- OWASP Top 10:2021 & OWASP API Security Top 10:2023
- CISA Known Exploited Vulnerabilities (KEV) Detection & BOD 22-01 Directives
- Exploit Prediction Scoring System (EPSS) Integration (FIRST.org)
- Commercial Risk Priority Matrix (P1-P5 Actionable Triage)
- Cryptographic Finding Fingerprinting for Deduplication
"""

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


# ==============================================================================
# 1. Official CVSS v3.1 / v4.0 Qualitative Severity Rating Scale (FIRST.org)
# ==============================================================================
def calculate_severity_from_cvss(score: Optional[float], default: str = "info") -> str:
    """
    Computes strict qualitative severity from numeric CVSS score
    in compliance with FIRST CVSS v3.1 & v4.0 specifications.
    
    Qualitative Rating Scale:
      - None / Info: 0.0
      - Low:         0.1 - 3.9
      - Medium:      4.0 - 6.9
      - High:        7.0 - 8.9
      - Critical:    9.0 - 10.0
    """
    if score is None:
        return str(default).strip().lower()

    try:
        s = float(score)
    except (ValueError, TypeError):
        return str(default).strip().lower()

    # Enforce standard bounds [0.0, 10.0]
    s = max(0.0, min(10.0, round(s, 1)))

    if s >= 9.0:
        return "critical"
    elif s >= 7.0:
        return "high"
    elif s >= 4.0:
        return "medium"
    elif s > 0.0:
        return "low"
    else:
        return "info"


# ==============================================================================
# 2. Comprehensive CWE Knowledge Base & OWASP Cross-Mapping (Web 2021 & API 2023)
# ==============================================================================
CWE_CATALOG: Dict[str, Dict[str, Any]] = {
    # --- Injection Flaws ---
    "CWE-89": {
        "title": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "owasp_2021": "A03:2021-Injection",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 9.8,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "remediation": "Use parameterized queries (Prepared Statements) or an Object-Relational Mapper (ORM). Never concatenate untrusted user inputs directly into SQL queries.",
    },
    "CWE-78": {
        "title": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "owasp_2021": "A03:2021-Injection",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 9.8,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "remediation": "Avoid invoking shell interpreters from code. Use native language APIs with argument arrays, and enforce strict allowlist validation on command arguments.",
    },
    "CWE-79": {
        "title": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "owasp_2021": "A03:2021-Injection",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 6.1,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "remediation": "Contextually encode all user-supplied data before rendering it in HTML, JavaScript, CSS, or attributes. Implement a strict Content Security Policy (CSP).",
    },
    "CWE-94": {
        "title": "Improper Control of Generation of Code ('Code Injection')",
        "owasp_2021": "A03:2021-Injection",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 9.8,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "remediation": "Do not pass untrusted data to dynamic code evaluation constructs (such as eval, Function, or exec). Utilize strict serialization schemas.",
    },
    "CWE-1336": {
        "title": "Improper Neutralization of Special Elements Used in a Template Engine ('Server-Side Template Injection')",
        "owasp_2021": "A03:2021-Injection",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 9.8,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "remediation": "Ensure template expressions and user parameters are strictly decoupled. Run template rendering engines in sandboxed modes with disabled system calls.",
    },
    "CWE-93": {
        "title": "Improper Neutralization of CRLF Sequences ('CRLF Injection / HTTP Response Splitting')",
        "owasp_2021": "A03:2021-Injection",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 6.1,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "remediation": "Strip carriage return (\\r) and line feed (\\n) characters from user inputs before incorporating them into HTTP headers or log outputs.",
    },

    # --- Broken Access Control & Authorization ---
    "CWE-22": {
        "title": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "owasp_2021": "A01:2021-Broken Access Control",
        "owasp_api_2023": "API1:2023-Broken Object Level Authorization",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Resolve target file paths using absolute canonicalization (e.g. os.path.realpath) and verify they remain within the intended base directory. Reject filenames containing '../'.",
    },
    "CWE-862": {
        "title": "Missing Authorization",
        "owasp_2021": "A01:2021-Broken Access Control",
        "owasp_api_2023": "API1:2023-Broken Object Level Authorization",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Enforce server-side role and permission checks on every requested endpoint and object record. Deny access by default unless explicitly permitted.",
    },
    "CWE-863": {
        "title": "Incorrect Authorization (Privilege Escalation)",
        "owasp_2021": "A01:2021-Broken Access Control",
        "owasp_api_2023": "API5:2023-Broken Function Level Authorization",
        "default_cvss": 8.1,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "remediation": "Verify that user identity matches the requested object owner at the database query layer. Prevent client-driven role manipulation.",
    },
    "CWE-639": {
        "title": "Authorization Bypass Through User-Controlled Key ('Insecure Direct Object References - IDOR / BOLA')",
        "owasp_2021": "A01:2021-Broken Access Control",
        "owasp_api_2023": "API1:2023-Broken Object Level Authorization",
        "default_cvss": 8.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "remediation": "Implement robust server-side authorization checks verifying that the authenticated user possesses explicit ownership or permission for the requested object ID.",
    },
    "CWE-284": {
        "title": "Improper Access Control",
        "owasp_2021": "A01:2021-Broken Access Control",
        "owasp_api_2023": "API1:2023-Broken Object Level Authorization",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Centralize access control enforcement. Apply the principle of least privilege across all API endpoints, routes, and resources.",
    },
    "CWE-352": {
        "title": "Cross-Site Request Forgery (CSRF)",
        "owasp_2021": "A01:2021-Broken Access Control",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 6.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "remediation": "Implement anti-CSRF synchronizer tokens for all state-changing requests (POST, PUT, DELETE). Set SameSite=Lax or SameSite=Strict on session cookies.",
    },
    "CWE-601": {
        "title": "URL Redirection to Untrusted Site ('Open Redirect')",
        "owasp_2021": "A01:2021-Broken Access Control",
        "owasp_api_2023": "API1:2023-Broken Object Level Authorization",
        "default_cvss": 6.1,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "remediation": "Avoid accepting arbitrary external URLs for client redirects. Maintain a strict server-side allowlist of permitted destination domains, or use relative paths only.",
    },
    "CWE-1385": {
        "title": "Missing Origin Verification in External Resources ('Subdomain Takeover')",
        "owasp_2021": "A01:2021-Broken Access Control",
        "owasp_api_2023": "API9:2023-Improper Inventory Management",
        "default_cvss": 8.6,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "remediation": "Continuously audit external DNS CNAME, MX, and alias records. Immediately reclaim abandoned third-party service mappings (e.g. S3, GitHub Pages, Azure).",
    },

    # --- Authentication & Credentials ---
    "CWE-287": {
        "title": "Improper Authentication",
        "owasp_2021": "A07:2021-Identification and Authentication Failures",
        "owasp_api_2023": "API2:2023-Broken Authentication",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Enforce strong authentication mechanisms, implement rate-limiting and brute-force defenses, mandate Multi-Factor Authentication (MFA), and protect session tokens.",
    },
    "CWE-798": {
        "title": "Use of Hard-coded Credentials ('Exposed API Keys and Secrets')",
        "owasp_2021": "A07:2021-Identification and Authentication Failures",
        "owasp_api_2023": "API2:2023-Broken Authentication",
        "default_cvss": 8.8,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "remediation": "Revoke exposed credentials immediately. Move all API keys, database credentials, and signing secrets to an enterprise Key Management Service (KMS) or secure environment variables.",
    },
    "CWE-522": {
        "title": "Insufficiently Protected Credentials",
        "owasp_2021": "A07:2021-Identification and Authentication Failures",
        "owasp_api_2023": "API2:2023-Broken Authentication",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Hash stored passwords using strong adaptive functions (Argon2id, bcrypt, PBKDF2). Ensure credentials in transit are always encrypted over TLS 1.3.",
    },
    "CWE-384": {
        "title": "Session Fixation",
        "owasp_2021": "A07:2021-Identification and Authentication Failures",
        "owasp_api_2023": "API2:2023-Broken Authentication",
        "default_cvss": 6.8,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "remediation": "Regenerate session tokens upon every successful user login or privilege state transition. Invalidate old session identifiers server-side.",
    },

    # --- Cryptographic Failures ---
    "CWE-319": {
        "title": "Cleartext Transmission of Sensitive Information",
        "owasp_2021": "A02:2021-Cryptographic Failures",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Enforce HTTPS/TLS 1.2+ across all web endpoints. Configure HTTP Strict Transport Security (HSTS) with long max-age and includeSubDomains.",
    },
    "CWE-326": {
        "title": "Inadequate Encryption Strength ('Weak TLS / Deprecated Ciphers')",
        "owasp_2021": "A02:2021-Cryptographic Failures",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 5.9,
        "default_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Disable deprecated SSLv3, TLS 1.0, and TLS 1.1 protocols. Enforce TLS 1.2/1.3 with forward-secrecy cipher suites (ECDHE-ECDSA/RSA-AES-GCM).",
    },
    "CWE-327": {
        "title": "Use of a Broken or Risky Cryptographic Algorithm",
        "owasp_2021": "A02:2021-Cryptographic Failures",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Replace legacy algorithms (MD5, SHA1, DES, RC4) with modern standards (SHA-256, SHA-3, AES-GCM, ChaCha20-Poly1305).",
    },
    "CWE-916": {
        "title": "Use of Password Hash With Insufficient Computational Effort",
        "owasp_2021": "A02:2021-Cryptographic Failures",
        "owasp_api_2023": "API2:2023-Broken Authentication",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Use memory-hard password hashing algorithms (Argon2id or bcrypt with appropriate work factor) instead of fast general-purpose hashes.",
    },

    # --- Security Misconfigurations & Defensive Failures ---
    "CWE-16": {
        "title": "Configuration ('Security Misconfiguration')",
        "owasp_2021": "A05:2021-Security Misconfiguration",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 5.3,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "remediation": "Harden server configurations, disable unnecessary HTTP methods (TRACE, DEBUG), remove default test scripts, and maintain regular patch management.",
    },
    "CWE-693": {
        "title": "Protection Mechanism Failure ('Missing Security Headers')",
        "owasp_2021": "A05:2021-Security Misconfiguration",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 4.3,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "remediation": "Deploy essential defensive HTTP security headers: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Content-Type-Options: nosniff, Referrer-Policy, and Permissions-Policy.",
    },
    "CWE-1021": {
        "title": "Improper Restriction of Rendered UI Layers or Frames ('Clickjacking')",
        "owasp_2021": "A05:2021-Security Misconfiguration",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 4.3,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "remediation": "Send the 'X-Frame-Options: SAMEORIGIN' header or configure CSP 'frame-ancestors' directive to restrict framing to trusted origins.",
    },
    "CWE-942": {
        "title": "Permissive Cross-Domain Policy with Untrusted Domains ('CORS Misconfiguration')",
        "owasp_2021": "A05:2021-Security Misconfiguration",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 6.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "remediation": "Do not dynamically reflect Origin headers or set 'Access-Control-Allow-Origin: *' when credentials are enabled. Validate requesting origins against a static domain whitelist.",
    },
    "CWE-1004": {
        "title": "Sensitive Cookie Without 'HttpOnly' Flag",
        "owasp_2021": "A05:2021-Security Misconfiguration",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 4.3,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "remediation": "Set the HttpOnly, Secure, and SameSite attributes on all sensitive and session cookies to prevent client-side JavaScript access.",
    },
    "CWE-548": {
        "title": "Exposure of Information Through Directory Listing",
        "owasp_2021": "A01:2021-Broken Access Control",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 5.3,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "remediation": "Disable directory indexing / Options -Indexes in web server configurations (Apache, Nginx, IIS) to prevent attackers from browsing file directories.",
    },
    "CWE-200": {
        "title": "Exposure of Sensitive Information to an Unauthorized Actor",
        "owasp_2021": "A01:2021-Broken Access Control",
        "owasp_api_2023": "API3:2023-Broken Object Property Level Authorization",
        "default_cvss": 5.3,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "remediation": "Filter API responses to return only authorized data fields. Prevent exposing system stack traces, internal IP addresses, or sensitive credentials in HTTP responses.",
    },
    "CWE-209": {
        "title": "Generation of Error Message Containing Sensitive Information ('Debug / Stack Trace Leak')",
        "owasp_2021": "A05:2021-Security Misconfiguration",
        "owasp_api_2023": "API3:2023-Broken Object Property Level Authorization",
        "default_cvss": 5.3,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "remediation": "Configure production error handlers to return generic error messages. Log detailed debugging information and stack traces to secure server-side logs only.",
    },
    "CWE-611": {
        "title": "Improper Restriction of XML External Entity Reference ('XXE')",
        "owasp_2021": "A05:2021-Security Misconfiguration",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Disable external entity resolution (DTD) in all XML parsers. Where possible, migrate data payloads from XML to JSON.",
    },

    # --- Insecure Design & Software Integrity ---
    "CWE-434": {
        "title": "Unrestricted Upload of File with Dangerous Type",
        "owasp_2021": "A04:2021-Insecure Design",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 8.8,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "remediation": "Validate file extensions and MIME types against a strict whitelist. Store uploaded files outside the web root on isolated storage (e.g. S3) and disable execution permissions.",
    },
    "CWE-502": {
        "title": "Deserialization of Untrusted Data",
        "owasp_2021": "A08:2021-Software and Data Integrity Failures",
        "owasp_api_2023": "API8:2023-Security Misconfiguration",
        "default_cvss": 9.8,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "remediation": "Do not accept serialized objects from untrusted sources. Use safer data interchange formats such as JSON or Protocol Buffers. If deserialization is mandatory, implement cryptographic signatures and strict type whitelisting.",
    },
    "CWE-770": {
        "title": "Allocation of Resources Without Limits or Throttling ('Rate Limiting Missing')",
        "owasp_2021": "A04:2021-Insecure Design",
        "owasp_api_2023": "API4:2023-Unrestricted Resource Consumption",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "remediation": "Implement rate limiting per client IP or token, set execution timeouts, and limit maximum request payload sizes to defend against Denial of Service.",
    },
    "CWE-400": {
        "title": "Uncontrolled Resource Consumption ('Denial of Service')",
        "owasp_2021": "A04:2021-Insecure Design",
        "owasp_api_2023": "API4:2023-Unrestricted Resource Consumption",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "remediation": "Enforce request quotas, connection limits, and request size boundaries at the API gateway layer.",
    },
    "CWE-829": {
        "title": "Inclusion of Functionality from Untrusted Sphere ('Vulnerable / Outdated Components')",
        "owasp_2021": "A06:2021-Vulnerable and Outdated Components",
        "owasp_api_2023": "API10:2023-Unsafe Consumption of APIs",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Continuously scan open-source dependencies using Software Composition Analysis (SCA). Upgrade outdated libraries and remove unmaintained packages.",
    },

    # --- SSRF ---
    "CWE-918": {
        "title": "Server-Side Request Forgery (SSRF)",
        "owasp_2021": "A10:2021-Server-Side Request Forgery (SSRF)",
        "owasp_api_2023": "API7:2023-Server Side Request Forgery",
        "default_cvss": 8.6,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "remediation": "Validate and sanitize all outbound destination URLs against a strict whitelist. Block requests directed to internal subnets, RFC 1918 IPs, and cloud metadata endpoints (169.254.169.254).",
    },
}


# ==============================================================================
# 3. Known High-Profile Exploited Vulnerabilities (CISA KEV Catalog & Heuristics)
# ==============================================================================
# Comprehensive, curated dataset of actively weaponized CVEs in perimeter scans
CISA_KEV_CATALOG: Dict[str, Dict[str, Any]] = {
    "CVE-2024-4577": {
        "name": "PHP CGI Argument Injection Vulnerability",
        "vendor": "PHP Group",
        "product": "PHP",
        "cwe": "CWE-78",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.96,
        "action": "Apply vendor security updates immediately. Update to PHP 8.3.8, 8.2.20, or 8.1.29+.",
    },
    "CVE-2024-6387": {
        "name": "OpenSSH regreSSHion Signal Handler Race Condition RCE",
        "vendor": "OpenSSH",
        "product": "OpenSSH",
        "cwe": "CWE-78",
        "baseline_cvss": 8.1,
        "baseline_epss": 0.91,
        "action": "Update OpenSSH to version 9.8p1 or newer immediately.",
    },
    "CVE-2024-3400": {
        "name": "Palo Alto Networks PAN-OS GlobalProtect Command Injection",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "cwe": "CWE-78",
        "baseline_cvss": 10.0,
        "baseline_epss": 0.95,
        "action": "Apply manufacturer security hotfixes or disable device telemetry until patched.",
    },
    "CVE-2024-21887": {
        "name": "Ivanti Connect Secure and Policy Secure Command Injection",
        "vendor": "Ivanti",
        "product": "Connect Secure / Policy Secure",
        "cwe": "CWE-78",
        "baseline_cvss": 9.1,
        "baseline_epss": 0.97,
        "action": "Apply Ivanti security patches and perform external perimeter compromise assessment.",
    },
    "CVE-2024-1709": {
        "name": "ConnectWise ScreenConnect Authentication Bypass",
        "vendor": "ConnectWise",
        "product": "ScreenConnect",
        "cwe": "CWE-287",
        "baseline_cvss": 10.0,
        "baseline_epss": 0.97,
        "action": "Upgrade ScreenConnect to version 23.9.8 or later immediately.",
    },
    "CVE-2023-4966": {
        "name": "Citrix Bleed - NetScaler ADC / Gateway Sensitive Info Disclosure",
        "vendor": "Citrix",
        "product": "NetScaler ADC / NetScaler Gateway",
        "cwe": "CWE-200",
        "baseline_cvss": 7.5,
        "baseline_epss": 0.97,
        "action": "Apply vendor patches and terminate all active ICA sessions.",
    },
    "CVE-2023-34362": {
        "name": "Progress MOVEit Transfer SQL Injection Vulnerability",
        "vendor": "Progress",
        "product": "MOVEit Transfer",
        "cwe": "CWE-89",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.97,
        "action": "Apply Progress security patches and review web server access logs for anomalous ASPX scripts.",
    },
    "CVE-2023-27997": {
        "name": "Fortinet FortiOS SSL-VPN Heap-Based Buffer Overflow",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "cwe": "CWE-78",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.96,
        "action": "Upgrade FortiOS firmware to patched releases immediately.",
    },
    "CVE-2023-22515": {
        "name": "Atlassian Confluence Data Center and Server Broken Access Control",
        "vendor": "Atlassian",
        "product": "Confluence",
        "cwe": "CWE-862",
        "baseline_cvss": 10.0,
        "baseline_epss": 0.96,
        "action": "Upgrade Confluence to fixed releases or restrict external network access.",
    },
    "CVE-2023-27350": {
        "name": "PaperCut MF/NG Authentication Bypass Vulnerability",
        "vendor": "PaperCut",
        "product": "MF / NG",
        "cwe": "CWE-287",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.97,
        "action": "Upgrade PaperCut application to patched version 20.1.7, 21.2.11, or 22.0.9+.",
    },
    "CVE-2022-22965": {
        "name": "Spring Framework Spring4Shell Remote Code Execution",
        "vendor": "VMware",
        "product": "Spring Framework",
        "cwe": "CWE-94",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.96,
        "action": "Upgrade Spring Framework to version 5.3.18 or 5.2.20+.",
    },
    "CVE-2022-26134": {
        "name": "Atlassian Confluence OGNL Injection Remote Code Execution",
        "vendor": "Atlassian",
        "product": "Confluence Server",
        "cwe": "CWE-94",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.97,
        "action": "Upgrade Confluence to patched versions 7.18.0.1+.",
    },
    "CVE-2021-44228": {
        "name": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "vendor": "Apache",
        "product": "Log4j",
        "cwe": "CWE-502",
        "baseline_cvss": 10.0,
        "baseline_epss": 0.97,
        "action": "Upgrade Log4j to version 2.17.1 or higher and disable JNDI lookup functionality.",
    },
    "CVE-2021-26855": {
        "name": "Microsoft Exchange Server SSRF Vulnerability (ProxyLogon)",
        "vendor": "Microsoft",
        "product": "Exchange Server",
        "cwe": "CWE-918",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.97,
        "action": "Apply cumulative security updates released by Microsoft.",
    },
    "CVE-2021-34473": {
        "name": "Microsoft Exchange Server Pre-Auth Path Confusion RCE (ProxyShell)",
        "vendor": "Microsoft",
        "product": "Exchange Server",
        "cwe": "CWE-94",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.97,
        "action": "Apply official Microsoft Exchange Security Update rollups.",
    },
    "CVE-2020-5902": {
        "name": "F5 BIG-IP TMUI Remote Code Execution Vulnerability",
        "vendor": "F5",
        "product": "BIG-IP",
        "cwe": "CWE-22",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.97,
        "action": "Update BIG-IP software or block external access to TMUI portal.",
    },
    "CVE-2019-19781": {
        "name": "Citrix ADC and Gateway Directory Traversal / RCE",
        "vendor": "Citrix",
        "product": "Citrix ADC / Gateway",
        "cwe": "CWE-22",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.97,
        "action": "Apply manufacturer security updates or responder policies.",
    },
    "CVE-2019-11510": {
        "name": "Pulse Connect Secure SSL VPN Arbitrary File Reading",
        "vendor": "Ivanti (Pulse Secure)",
        "product": "Pulse Connect Secure",
        "cwe": "CWE-22",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.97,
        "action": "Upgrade Pulse Connect Secure firmware immediately.",
    },
    "CVE-2018-13379": {
        "name": "Fortinet FortiOS SSL VPN Path Traversal Credential Leak",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "cwe": "CWE-22",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.97,
        "action": "Upgrade FortiOS firmware to version 6.0.5, 6.2.1, or 6.4.0+.",
    },
    "CVE-2017-5638": {
        "name": "Apache Struts 2 Jakarta Multipart Parser RCE",
        "vendor": "Apache",
        "product": "Struts 2",
        "cwe": "CWE-78",
        "baseline_cvss": 10.0,
        "baseline_epss": 0.97,
        "action": "Upgrade to Struts 2.3.32 or 2.5.10.1 or change multipart parser implementation.",
    },
    "CVE-2014-0160": {
        "name": "OpenSSL Heartbeat Information Disclosure (Heartbleed)",
        "vendor": "OpenSSL",
        "product": "OpenSSL",
        "cwe": "CWE-200",
        "baseline_cvss": 7.5,
        "baseline_epss": 0.96,
        "action": "Upgrade OpenSSL to 1.0.1g+ and re-issue all SSL/TLS private keys.",
    },
    "CVE-2014-6271": {
        "name": "GNU Bash Environment Variable Command Injection (Shellshock)",
        "vendor": "GNU",
        "product": "Bash",
        "cwe": "CWE-78",
        "baseline_cvss": 9.8,
        "baseline_epss": 0.97,
        "action": "Update bash packages to patched distributor builds.",
    },
}

# Fast lookup set of high-profile KEV entries
CISA_KEV_SAMPLES = set(CISA_KEV_CATALOG.keys())


# ==============================================================================
# 4. Fingerprint & Deduplication Engine
# ==============================================================================
def generate_finding_fingerprint(
    affected_url: str,
    title: str,
    cwe_id: Optional[str] = None,
    cve_id: Optional[str] = None
) -> str:
    """
    Generates a deterministic SHA-256 fingerprint for vulnerability deduplication.
    Normalizes the URL (stripping query parameter values while preserving keys).
    """
    parsed = urlparse(affected_url or "")
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")

    # Normalize query string: retain keys in sorted order, strip values
    norm_query = ""
    if parsed.query:
        keys = sorted(set(k.split("=")[0].lower() for k in parsed.query.split("&") if k))
        norm_query = "?" + "&".join(keys)

    canonical_target = f"{scheme}://{netloc}{path}{norm_query}"
    signature = f"{canonical_target}|{cve_id or ''}|{cwe_id or ''}|{title.strip().lower()}"

    return hashlib.sha256(signature.encode("utf-8")).hexdigest()


# ==============================================================================
# 5. Core Normalizer & Enrichment Pipeline
# ==============================================================================
def normalize_vulnerability(vuln_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Applies comprehensive enterprise normalization to a raw vulnerability dictionary:
    1. Extracts and canonicalizes CVE ID (CVE-YYYY-NNNN) and CWE ID (CWE-XXX).
    2. Enforces CVSS v3.1 / v4.0 calculation and resolves severity contradictions.
    3. Incurs OWASP Top 10:2021 & OWASP API 2023 mappings from CWE matrix.
    4. Enriches with canonical title, description, and standard remediation.
    5. Flags CISA KEV presence, extracts EPSS probability, and computes risk priority.
    6. Generates unique deduplication fingerprint.
    """
    # 1. Clean and canonicalize identifiers
    cve_id = _extract_cve(vuln_data)
    cwe_id = _extract_cwe(vuln_data)

    # 2. Extract CVSS Metrics
    cvss_score, cvss_vector = _extract_cvss(vuln_data)
    cwe_meta = CWE_CATALOG.get(cwe_id) if cwe_id else None

    # 3. Calibrate Severity strictly by CVSS score (Commercial standard rule)
    raw_sev = (
        vuln_data.get("severity")
        or (vuln_data.get("info", {}) if isinstance(vuln_data.get("info"), dict) else {}).get("severity")
    )
    raw_sev_clean = str(raw_sev).strip().upper() if raw_sev else ""

    # If raw severity is explicitly INFO and scanner did not supply CVSS, keep it as INFO (0.0)
    if cvss_score is None and raw_sev_clean == "INFO":
        cvss_score = 0.0
    elif cvss_score is None and cwe_meta:
        # If scanner did not supply CVSS, check if our CWE catalog has a baseline
        cvss_score = cwe_meta.get("default_cvss")
        if not cvss_vector:
            cvss_vector = cwe_meta.get("default_vector")

    if cvss_score is None and raw_sev:
        sev_fallback_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.0, "INFO": 0.0}
        cvss_score = sev_fallback_map.get(raw_sev_clean)

    calibrated_severity = calculate_severity_from_cvss(cvss_score, default=str(raw_sev or "info"))

    # 4. Resolve OWASP Category (Web 2021 & API 2023)
    owasp_category = vuln_data.get("owasp_category")
    if (not owasp_category or owasp_category in ("General", "Unknown")) and cwe_meta:
        owasp_category = cwe_meta.get("owasp_2021")

    owasp_api_category = vuln_data.get("owasp_api_category")
    if (not owasp_api_category or owasp_api_category in ("General", "Unknown")) and cwe_meta:
        owasp_api_category = cwe_meta.get("owasp_api_2023")

    # 5. Canonical Title & Description
    title = (
        vuln_data.get("title")
        or (vuln_data.get("info", {}) if isinstance(vuln_data.get("info"), dict) else {}).get("name")
        or vuln_data.get("name")
    )
    if not title and cwe_meta:
        title = cwe_meta.get("title")
    title = str(title or "Unknown Vulnerability").strip()

    description = (
        vuln_data.get("description")
        or (vuln_data.get("info", {}) if isinstance(vuln_data.get("info"), dict) else {}).get("description")
        or ""
    )

    # 6. Actionable Remediation
    remediation = (
        vuln_data.get("standard_remediation")
        or vuln_data.get("remediation")
        or (vuln_data.get("info", {}) if isinstance(vuln_data.get("info"), dict) else {}).get("remediation")
    )
    if not remediation and cwe_meta:
        remediation = cwe_meta.get("remediation", "")

    # 7. Threat Intelligence: CISA KEV & EPSS Scoring
    is_cisa_kev, cisa_meta = _check_cisa_kev(cve_id)
    epss_score, epss_percentile = _extract_epss(vuln_data, cve_id, cisa_meta)

    # Enrich missing parameters from CISA KEV metadata if available
    if is_cisa_kev and cisa_meta:
        if not remediation:
            remediation = cisa_meta.get("action", "")
        if not cwe_id and cisa_meta.get("cwe"):
            cwe_id = cisa_meta["cwe"]
            cwe_meta = CWE_CATALOG.get(cwe_id)
            if not owasp_category and cwe_meta:
                owasp_category = cwe_meta.get("owasp_2021")
            if not owasp_api_category and cwe_meta:
                owasp_api_category = cwe_meta.get("owasp_api_2023")
        if cvss_score is None:
            cvss_score = cisa_meta.get("baseline_cvss", 9.8)
            calibrated_severity = calculate_severity_from_cvss(cvss_score)
        if title == "Unknown Vulnerability" and cisa_meta.get("name"):
            title = cisa_meta["name"]

    # 8. Commercial Risk Priority Matrix (P1-P5)
    risk_priority = _calculate_risk_priority(
        severity=calibrated_severity,
        cvss_score=cvss_score,
        is_cisa_kev=is_cisa_kev,
        epss_score=epss_score
    )

    # 9. Deduplication Fingerprint
    affected_url = (
        vuln_data.get("affected_url")
        or vuln_data.get("matched-at")
        or vuln_data.get("host")
        or ""
    )
    fingerprint = generate_finding_fingerprint(
        affected_url=affected_url,
        title=title,
        cwe_id=cwe_id,
        cve_id=cve_id
    )

    return {
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": calibrated_severity.upper(),
        "risk_priority": risk_priority,
        "owasp_category": owasp_category,
        "owasp_api_category": owasp_api_category,
        "title": title,
        "description": description,
        "standard_remediation": remediation,
        "is_cisa_kev": is_cisa_kev,
        "cisa_kev_details": cisa_meta,
        "epss_score": epss_score,
        "epss_percentile": epss_percentile,
        "fingerprint": fingerprint,
        "affected_url": affected_url,
    }


# ==============================================================================
# Helper Parsers & Scorers
# ==============================================================================
def _check_cisa_kev(cve_id: Optional[str]) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Checks if a CVE identifier is recorded in the CISA KEV catalog."""
    if not cve_id:
        return False, None

    clean_cve = cve_id.strip().upper()
    if clean_cve in CISA_KEV_CATALOG:
        return True, CISA_KEV_CATALOG[clean_cve]

    return False, None


def _extract_epss(
    data: Dict[str, Any],
    cve_id: Optional[str],
    cisa_meta: Optional[Dict[str, Any]]
) -> Tuple[Optional[float], Optional[float]]:
    """
    Extracts EPSS score and percentile from scanner metadata,
    or falls back to empirical baseline for verified CISA KEV threats.
    """
    score: Optional[float] = None
    percentile: Optional[float] = None

    info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
    classif = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}

    raw_epss = (
        data.get("epss_score")
        or data.get("epss-score")
        or classif.get("epss-score")
        or classif.get("epss_score")
    )
    if raw_epss is not None:
        try:
            score = round(float(raw_epss), 4)
        except (ValueError, TypeError):
            score = None

    raw_perc = (
        data.get("epss_percentile")
        or data.get("epss-percentile")
        or classif.get("epss-percentile")
        or classif.get("epss_percentile")
    )
    if raw_perc is not None:
        try:
            percentile = round(float(raw_perc), 4)
        except (ValueError, TypeError):
            percentile = None

    # Fallback heuristic for known exploited vulnerabilities without raw scanner metrics
    if score is None and cisa_meta and "baseline_epss" in cisa_meta:
        score = cisa_meta["baseline_epss"]
        percentile = 0.98

    return score, percentile


def _calculate_risk_priority(
    severity: str,
    cvss_score: Optional[float],
    is_cisa_kev: bool,
    epss_score: Optional[float]
) -> str:
    """
    Computes actionable risk priority tier (P1-P5) based on CVSS,
    in-the-wild exploitation (CISA KEV), and exploit probability (EPSS).
    """
    score = cvss_score if cvss_score is not None else 0.0
    epss = epss_score if epss_score is not None else 0.0

    # P1 - URGENT: Active exploit in the wild OR Critical CVSS with high probability
    if (is_cisa_kev and score >= 7.0) or score >= 9.0 or epss >= 0.85:
        return "P1 - URGENT (Critical Perimeter Risk)"

    # P2 - HIGH: Weaponized exploit OR High CVSS
    if is_cisa_kev or score >= 7.0 or epss >= 0.50:
        return "P2 - HIGH (Elevated Threat)"

    # P3 - MEDIUM: Standard moderate vulnerability
    if score >= 4.0:
        return "P3 - MEDIUM (Moderate Risk)"

    # P4 - LOW: Minor hygiene / low impact
    if score > 0.0:
        return "P4 - LOW (Defensive Hardening)"

    # P5 - INFORMATIONAL
    return "P5 - INFO (Informational Finding)"


def _extract_cve(data: Dict[str, Any]) -> Optional[str]:
    """Extracts and verifies CVE-YYYY-NNNN format."""
    candidates = []
    for k in ("cve_id", "cve", "cve-id"):
        v = data.get(k)
        if isinstance(v, list) and v:
            candidates.append(str(v[0]))
        elif isinstance(v, str):
            candidates.append(v)

    info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
    classif = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
    for k in ("cve-id", "cve_id"):
        v = classif.get(k)
        if isinstance(v, list) and v:
            candidates.append(str(v[0]))
        elif isinstance(v, str):
            candidates.append(v)

    for item in candidates:
        match = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", str(item), re.IGNORECASE)
        if match:
            return match.group(1).upper()

    search_space = f"{data.get('id', '')} {data.get('title', '')} {data.get('description', '')}"
    match = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", search_space, re.IGNORECASE)
    return match.group(1).upper() if match else None


def _extract_cwe(data: Dict[str, Any]) -> Optional[str]:
    """Extracts and standardizes CWE-XXX format."""
    candidates = []
    for k in ("cwe_id", "cwe", "cwe-id"):
        v = data.get(k)
        if isinstance(v, list) and v:
            candidates.append(str(v[0]))
        elif isinstance(v, str):
            candidates.append(v)

    info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
    classif = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
    for k in ("cwe-id", "cwe_id"):
        v = classif.get(k)
        if isinstance(v, list) and v:
            candidates.append(str(v[0]))
        elif isinstance(v, str):
            candidates.append(v)

    for item in candidates:
        match = re.search(r"\b(?:CWE-)?(\d+)\b", str(item), re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"

    search_space = f"{data.get('id', '')} {data.get('title', '')} {data.get('category', '')} {data.get('name', '')} {data.get('description', '')}".lower()
    match = re.search(r"\bcwe-(\d+)\b", search_space)
    if match:
        return f"CWE-{match.group(1)}"

    # Heuristic Keyword-to-CWE Mapping
    keyword_cwe_map = [
        # Injection
        (r"\b(sql|sqli|sql injection|blind sql)\b", "CWE-89"),
        (r"\b(command injection|argument injection|rce|remote code exec|code execution)\b", "CWE-78"),
        (r"\b(xss|cross[- ]site script)\b", "CWE-79"),
        (r"\b(ssti|template injection|server[- ]side template)\b", "CWE-1336"),
        (r"\b(crlf|response splitting|header injection)\b", "CWE-93"),
        (r"\b(code injection)\b", "CWE-94"),
        
        # Access Control & Traversal
        (r"\b(path traversal|directory traversal|lfi|local file inclusion)\b", "CWE-22"),
        (r"\b(idor|insecure direct object|broken object level auth)\b", "CWE-639"),
        (r"\b(subdomain takeover)\b", "CWE-1385"),
        (r"\b(csrf|cross[- ]site request forgery)\b", "CWE-352"),
        (r"\b(open redirect|url redirection)\b", "CWE-601"),
        (r"\b(directory listing|index of)\b", "CWE-548"),

        # SSRF & Deserialization
        (r"\b(ssrf|server[- ]side request forgery)\b", "CWE-918"),
        (r"\b(deserialization|untrusted deserialization)\b", "CWE-502"),
        (r"\b(xxe|xml external entity)\b", "CWE-611"),

        # Authentication & Secrets
        (r"\b(hardcoded|secret key|api key leak|token leak|credential leak|\.env|env file|configuration file disclosure|environment configuration)\b", "CWE-798"),
        (r"\b(session fixation)\b", "CWE-384"),
        (r"\b(weak password|password hash)\b", "CWE-916"),
        (r"\b(auth bypass|authentication bypass|login bypass)\b", "CWE-287"),

        # Cryptography & Transport
        (r"\b(cleartext|plain text transmission|unencrypted http)\b", "CWE-319"),
        (r"\b(weak ssl|weak tls|ssl certificate|tls cipher|deprecated ssl)\b", "CWE-326"),
        
        # Security Headers & Misconfigurations
        (r"\b(clickjacking|x[- ]frame[- ]options)\b", "CWE-1021"),
        (r"\b(cors|cross[- ]origin resource)\b", "CWE-942"),
        (r"\b(httponly|cookie flag)\b", "CWE-1004"),
        (r"\b(missing security header|content[- ]security[- ]policy|x[- ]content[- ]type[- ]options|strict[- ]transport|permissions[- ]policy)\b", "CWE-693"),
        (r"\b(stack trace|debug info|error disclosure|debug mode)\b", "CWE-209"),
        (r"\b(swagger|openapi|server banner|readme disclosure|robots\.txt|information disclosure|version disclosure|banner disclosure)\b", "CWE-200"),
        (r"\b(waf|firewall|cloudflare|shield active|security baseline)\b", "CWE-16"),
        
        # File Upload & Resources
        (r"\b(file upload|unrestricted upload|arbitrary file upload)\b", "CWE-434"),
        (r"\b(rate limit|resource exhaustion|denial of service|dos)\b", "CWE-770"),
        (r"\b(outdated component|vulnerable library|outdated software)\b", "CWE-829"),
    ]
    for pattern, cwe in keyword_cwe_map:
        if re.search(pattern, search_space):
            return cwe

    return None


def _extract_cvss(data: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    """Extracts CVSS score and vector string (CVSS v3.1 / v4.0)."""
    score = None
    vector = None

    raw_score = data.get("cvss_score") or data.get("cvss-score")
    info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
    classif = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}

    if raw_score is None:
        raw_score = classif.get("cvss-score") or classif.get("cvss_score")
        vector = classif.get("cvss-metrics") or classif.get("cvss_vector")

    if raw_score is not None:
        try:
            score = round(float(raw_score), 1)
        except (ValueError, TypeError):
            score = None

    if not vector:
        vector = data.get("cvss_vector") or data.get("cvss-metrics") or classif.get("cvss-metrics")

    # Validate vector format (CVSS:3.1 or CVSS:4.0 or CVSS:3.0)
    if vector and not re.search(r"CVSS:[34]\.[01]/", str(vector)):
        if "AV:" in str(vector):
            vector = f"CVSS:3.1/{str(vector).strip()}"

    return score, str(vector) if vector else None
