import re
from datetime import datetime, timezone
from typing import Any

import httpx

from app.agents import Agent


SECURITY_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-frame-options": "XFO",
    "x-content-type-options": "XCTO",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

HSTS_MIN_MAX_AGE = 31536000


class AnalyzerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Analyzer Agent")

    async def run(
        self, target_url: str, scan_id: int,
        scanner_output: dict[str, Any] | None = None
    ) -> dict[str, list[dict[str, Any]]]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Analyzing {target_url}")

        headers = await self._get_headers(target_url, scanner_output)
        findings: list[dict[str, Any]] = []

        findings.extend(self._check_headers(headers, target_url))
        findings.extend(await self._check_cors(target_url))
        findings.extend(self._check_cookies(headers))
        findings.extend(await self._check_tls(target_url))
        findings.extend(self._check_info_leakage(headers))

        self.status = "complete"
        await self.log_action("completed", f"Generated {len(findings)} findings")
        return {
            "findings": findings,
            "header_findings": [f for f in findings if f.get("category") == "Security Headers"],
            "cors_issues": [f for f in findings if f.get("category") == "CORS"],
            "cookie_issues": [f for f in findings if f.get("category") == "Cookies"],
            "tls_issues": [f for f in findings if f.get("category") == "TLS"],
            "info_leakage": [f for f in findings if f.get("category") == "Information Disclosure"],
        }

    async def _get_headers(
        self, target_url: str, scanner_output: dict[str, Any] | None
    ) -> dict[str, str]:
        tech = (scanner_output or {}).get("tech_stack", {})
        if isinstance(tech, dict) and "headers" in tech and isinstance(tech["headers"], dict):
            return tech["headers"]

        url = target_url if "://" in target_url else f"https://{target_url}"
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as c:
            try:
                r = await c.get(url)
                return {k.lower(): v for k, v in r.headers.items()}
            except Exception:
                return {}

    def _check_headers(self, headers: dict[str, str], target: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        present = {k.lower() for k in headers}

        if "content-security-policy" not in present:
            findings.append(self._finding(
                "Missing Content Security Policy", "Security Headers", "medium",
                "No CSP header found", "XSS and data injection attacks are easier without CSP",
                "Add: Content-Security-Policy: default-src 'self'", target
            ))
        else:
            csp = headers.get("content-security-policy", "")
            if "unsafe-inline" in csp and "script-src" in csp:
                findings.append(self._finding(
                    "CSP allows unsafe-inline scripts", "Security Headers", "high",
                    "script-src includes 'unsafe-inline'", "Bypasses CSP protection against XSS",
                    "Remove 'unsafe-inline' from script-src; use nonces or hashes", target
                ))

        if "strict-transport-security" not in present:
            sev = "high" if target.startswith("https://") else "medium"
            findings.append(self._finding(
                "Missing HTTP Strict Transport Security", "Security Headers", sev,
                "No HSTS header", "SSL stripping and MITM attacks possible",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", target
            ))
        else:
            hsts = headers.get("strict-transport-security", "")
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < HSTS_MIN_MAX_AGE:
                findings.append(self._finding(
                    "HSTS max-age too short", "Security Headers", "medium",
                    f"HSTS max-age={m.group(1)} < {HSTS_MIN_MAX_AGE}",
                    "Short max-age weakens protection against SSL stripping",
                    f"Set max-age to at least {HSTS_MIN_MAX_AGE}", target
                ))
            if "preload" not in hsts:
                findings.append(self._finding(
                    "HSTS missing preload directive", "Security Headers", "low",
                    "No preload flag in HSTS", "Browser won't preload HSTS",
                    "Add 'preload' to HSTS header and submit to hstspreload.org", target
                ))

        if "x-frame-options" not in present and "frame-ancestors" not in headers.get("content-security-policy", ""):
            findings.append(self._finding(
                "Missing Clickjacking Protection", "Security Headers", "medium",
                "No X-Frame-Options or CSP frame-ancestors",
                "Page can be embedded in malicious iframes",
                "Add: X-Frame-Options: DENY or frame-ancestors 'none'", target
            ))

        if "x-content-type-options" not in present:
            findings.append(self._finding(
                "Missing X-Content-Type-Options", "Security Headers", "low",
                "No X-Content-Type-Options: nosniff",
                "Browser may MIME-sniff responses, enabling drive-download attacks",
                "Add: X-Content-Type-Options: nosniff", target
            ))

        if "referrer-policy" not in present:
            findings.append(self._finding(
                "Missing Referrer-Policy", "Security Headers", "low",
                "No Referrer-Policy header",
                "Referrer URL may leak in cross-origin requests",
                "Add: Referrer-Policy: strict-origin-when-cross-origin", target
            ))

        if "permissions-policy" not in present:
            findings.append(self._finding(
                "Missing Permissions-Policy", "Security Headers", "low",
                "No Permissions-Policy header",
                "Browser features (camera, mic, etc.) unrestricted",
                "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()", target
            ))

        return findings

    async def _check_cors(self, target_url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        url = target_url if "://" in target_url else f"https://{target_url}"

        async with httpx.AsyncClient(timeout=8.0, verify=False) as c:
            try:
                r = await c.options(url, headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "GET"
                })
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "")

                if acao == "*":
                    findings.append(self._finding(
                        "Wildcard CORS allowed", "CORS", "medium",
                        "Access-Control-Allow-Origin: *", "Any origin can read responses",
                        "Restrict to specific trusted origins", target_url
                    ))
                if acao == "https://evil.com":
                    findings.append(self._finding(
                        "Reflected CORS origin", "CORS", "high",
                        "Server echoes Origin header value", "Attacker can read authenticated responses cross-origin",
                        "Validate Origin against an allowlist; do not echo", target_url
                    ))
                if acao and acac.lower() == "true" and acao != "*":
                    findings.append(self._finding(
                        "CORS with credentials from arbitrary origin", "CORS", "high",
                        f"ACAO: {acao}, ACAC: true", "Authenticated cross-origin reads possible",
                        "Restrict ACAO to specific origins and avoid credentialed wildcard", target_url
                    ))
            except Exception:
                pass

        return findings

    def _check_cookies(self, headers: dict[str, str]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        set_cookie = headers.get("set-cookie", "")
        if not set_cookie:
            return findings

        for cookie in set_cookie.split("\n"):
            c = cookie.strip()
            if not c:
                continue
            name = c.split("=")[0] if "=" in c else c

            if "secure" not in c.lower():
                findings.append(self._finding(
                    f"Cookie '{name}' missing Secure flag", "Cookies", "medium",
                    f"Set-Cookie: {c[:80]}...", "Cookie sent over unencrypted HTTP",
                    "Add Secure flag", None
                ))
            if "httponly" not in c.lower():
                findings.append(self._finding(
                    f"Cookie '{name}' missing HttpOnly flag", "Cookies", "medium",
                    f"Set-Cookie: {c[:80]}...", "JavaScript can read cookie",
                    "Add HttpOnly flag", None
                ))
            if "samesite" not in c.lower():
                findings.append(self._finding(
                    f"Cookie '{name}' missing SameSite attribute", "Cookies", "low",
                    f"Set-Cookie: {c[:80]}...", "CSRF protection weakened",
                    "Add SameSite=Lax or SameSite=Strict", None
                ))

        return findings

    async def _check_tls(self, target_url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        host = target_url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=ctx), timeout=5.0
            )
            cert = r.get_extra_info("ssl_object").getpeercert()
            ver = r.get_extra_info("ssl_object").version()
            cipher = r.get_extra_info("ssl_object").cipher()
            w.close()
            await w.wait_closed()

            if ver in ("TLSv1", "TLSv1.0", "TLSv1.1"):
                findings.append(self._finding(
                    f"Outdated TLS version: {ver}", "TLS", "high",
                    f"Server uses {ver}", "Deprecated TLS allows downgrade attacks",
                    "Disable TLS 1.0 and 1.1; use TLS 1.2+", target_url
                ))

            weak = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5"]
            if cipher and any(w in str(cipher[0]).upper() for w in weak):
                findings.append(self._finding(
                    f"Weak cipher: {cipher[0]}", "TLS", "high",
                    f"Cipher suite: {cipher[0]}", "Weak cipher can be broken by attackers",
                    "Disable weak ciphers; use AEAD ciphers (AES-GCM, ChaCha20)", target_url
                ))

            if cert:
                not_after = cert.get("notAfter", "")
                not_before = cert.get("notBefore", "")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    if expiry < datetime.now(timezone.utc):
                        findings.append(self._finding(
                            "Expired SSL certificate", "TLS", "high",
                            f"Expired: {not_after}", "Expired cert triggers browser warnings",
                            "Renew certificate before expiry", target_url
                        ))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                if issuer.get("organizationName") == "self-signed":
                    findings.append(self._finding(
                        "Self-signed SSL certificate", "TLS", "high",
                        "Certificate is self-signed", "Users cannot verify identity",
                        "Use a trusted CA-signed certificate", target_url
                    ))

                hsts_h = None
                async with httpx.AsyncClient(timeout=5.0, verify=False) as c:
                    try:
                        r = await c.get(f"https://{host}")
                        hsts_h = r.headers.get("strict-transport-security", "")
                    except Exception:
                        pass

                if hsts_h and "preload" in hsts_h:
                    findings.append(self._finding(
                        "HSTS preload eligible", "TLS", "info",
                        "HSTS includes preload", "Ready for preload list submission",
                        "Submit to https://hstspreload.org", target_url
                    ))
        except Exception:
            findings.append(self._finding(
                "Could not establish TLS connection", "TLS", "medium",
                f"Failed to connect to {host}:443", "TLS may not be available",
                "Ensure HTTPS is properly configured", target_url
            ))

        return findings

    def _check_info_leakage(self, headers: dict[str, str]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        leaky = {
            "server": "Server version disclosure",
            "x-powered-by": "X-Powered-By disclosure",
            "x-aspnet-version": "ASP.NET version disclosure",
            "x-debug-token": "Debug token disclosure",
            "x-generator": "Generator tag disclosure",
            "x-runtime": "Runtime header disclosure",
        }

        for hdr, title in leaky.items():
            val = headers.get(hdr)
            if val:
                findings.append(self._finding(
                    title, "Information Disclosure", "low",
                    f"Header '{hdr}: {val}'", "Attackers fingerprint stack for targeted exploits",
                    f"Remove or obfuscate the '{hdr}' header in server config", None
                ))

        return findings

    def _finding(
        self, title: str, category: str, severity: str,
        evidence: str, impact: str, fix: str, endpoint: str | None
    ) -> dict[str, Any]:
        return {
            "title": title,
            "category": category,
            "severity": severity,
            "evidence": evidence,
            "impact": impact,
            "fix": fix,
            "endpoint": endpoint or "",
            "cve_id": None,
            "cvss_score": None,
        }
