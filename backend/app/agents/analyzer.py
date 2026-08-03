import asyncio
import ssl
import traceback
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
    "cross-origin-embedder-policy": "COEP",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-resource-policy": "CORP",
    "origin-agent-cluster": "OAC",
}

CSP_DANGEROUS_DIRECTIVES = {
    "unsafe-inline": "script-src allows inline scripts, weakening XSS protection",
    "unsafe-eval": "script-src allows eval(), enabling dynamic code execution",
    "unsafe-hashes": "script-src allows unsafe hashes, reducing CSP effectiveness",
    "unsafe-allow-redirects": "connect-src allows redirects, enabling SSRF risk",
    "data:": "script-src allows data: URIs, enabling inline script injection",
    "blob:": "script-src allows blob: URIs, enabling object URL injection",
    "filesystem:": "script-src allows filesystem: URIs",
}

CSP_MISSING_DIRECTIVES = {
    "default-src": "No default-src fallback; all resource types are unrestricted",
    "script-src": "No script-src directive; inline scripts and eval() are allowed by default",
    "style-src": "No style-src directive; inline styles are allowed by default",
    "img-src": "No img-src directive; images can be loaded from any origin",
    "font-src": "No font-src directive; fonts can be loaded from any origin",
    "connect-src": "No connect-src directive; fetch/XHR can target any origin",
    "frame-src": "No frame-src directive; frames can embed any origin",
    "media-src": "No media-src directive; audio/video can be loaded from any origin",
    "object-src": "No object-src directive; Flash/Java applets can be loaded from any origin",
    "base-uri": "No base-uri directive; base tag injection can redirect relative URLs",
    "form-action": "No form-action directive; forms can submit to any origin",
    "frame-ancestors": "No frame-ancestors directive; clickjacking is possible",
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

        try:
            headers = await self._get_headers(target_url, scanner_output)
        except Exception:
            traceback.print_exc()
            raise

        findings: list[dict[str, Any]] = []

        try:
            findings.extend(self._check_headers(headers, target_url))
        except Exception:
            traceback.print_exc()
            raise

        try:
            findings.extend(await self._check_cors(target_url))
        except Exception:
            traceback.print_exc()
            raise

        try:
            findings.extend(self._check_cookies(headers))
        except Exception:
            traceback.print_exc()
            raise

        try:
            findings.extend(await self._check_tls(target_url))
        except Exception:
            traceback.print_exc()
            raise

        try:
            findings.extend(self._check_info_leakage(headers))
        except Exception:
            traceback.print_exc()
            raise

        try:
            findings.extend(await self._check_http_methods(target_url))
        except Exception:
            traceback.print_exc()
            raise

        self.status = "complete"
        await self.log_action("completed", f"Generated {len(findings)} findings")
        return {
            "findings": findings,
            "header_findings": [f for f in findings if f.get("category") == "Security Headers"],
            "cors_issues": [f for f in findings if f.get("category") == "CORS"],
            "cookie_issues": [f for f in findings if f.get("category") == "Cookies"],
            "tls_issues": [f for f in findings if f.get("category") == "TLS"],
            "info_leakage": [f for f in findings if f.get("category") == "Information Disclosure"],
            "http_method_issues": [f for f in findings if f.get("category") == "HTTP Methods"],
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
            csp_lower = csp.lower()

            for directive, desc in CSP_DANGEROUS_DIRECTIVES.items():
                if directive in csp_lower:
                    sev = "high" if directive in ("unsafe-inline", "unsafe-eval") else "medium"
                    findings.append(self._finding(
                        f"CSP contains dangerous directive: {directive}", "Security Headers", sev,
                        f"CSP {directive}: {desc}", "Reduces CSP protection against injection attacks",
                        f"Remove or restrict the {directive} directive in CSP", target
                    ))

            for directive in CSP_MISSING_DIRECTIVES:
                if directive not in csp_lower and directive not in ("default-src",):
                    findings.append(self._finding(
                        f"CSP missing {directive} directive", "Security Headers", "low",
                        f"CSP does not include {directive}", CSP_MISSING_DIRECTIVES[directive],
                        f"Add {directive} directive to Content-Security-Policy header", target
                    ))

            if "unsafe-inline" in csp_lower and "script-src" in csp_lower:
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

        if "cross-origin-embedder-policy" not in present:
            findings.append(self._finding(
                "Missing Cross-Origin-Embedder-Policy", "Security Headers", "medium",
                "No COEP header", "Page is not isolated from cross-origin embeddings; Spectre/Meltdown mitigations are weakened",
                "Add: Cross-Origin-Embedder-Policy: require-corp", target
            ))

        if "cross-origin-opener-policy" not in present:
            findings.append(self._finding(
                "Missing Cross-Origin-Opener-Policy", "Security Headers", "medium",
                "No COOP header", "Top-level navigations can open the page in a pop-up window and access it via window.opener",
                "Add: Cross-Origin-Opener-Policy: same-origin", target
            ))

        if "cross-origin-resource-policy" not in present:
            findings.append(self._finding(
                "Missing Cross-Origin-Resource-Policy", "Security Headers", "low",
                "No CORP header", "Cross-origin requests can load the resource, enabling data exfiltration",
                "Add: Cross-Origin-Resource-Policy: same-origin", target
            ))

        if "origin-agent-cluster" not in present:
            findings.append(self._finding(
                "Missing Origin-Agent-Cluster", "Security Headers", "low",
                "No OAC header", "The page is not isolated in its own agent cluster; cross-origin attacks may affect it",
                "Add: Origin-Agent-Cluster: ?1", target
            ))

        return findings

    async def _check_cors(self, target_url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        url = target_url if "://" in target_url else f"https://{target_url}"

        async with httpx.AsyncClient(timeout=8.0, verify=False) as c:
            try:
                r1 = await c.options(url, headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "GET"
                })
                acao1 = r1.headers.get("access-control-allow-origin", "")
                acac1 = r1.headers.get("access-control-allow-credentials", "")

                if acao1 == "*":
                    findings.append(self._finding(
                        "Wildcard CORS allowed", "CORS", "medium",
                        "Access-Control-Allow-Origin: *", "Any origin can read responses",
                        "Restrict to specific trusted origins", target_url
                    ))
                elif acao1 == "https://evil.com":
                    is_dynamic_reflection = False
                    try:
                        r2 = await c.options(url, headers={
                            "Origin": "https://attacker-different-test.com",
                            "Access-Control-Request-Method": "GET"
                        })
                        acao2 = r2.headers.get("access-control-allow-origin", "")
                        if acao2 == "https://attacker-different-test.com":
                            is_dynamic_reflection = True
                    except Exception:
                        pass

                    if is_dynamic_reflection:
                        findings.append(self._finding(
                            "Reflected CORS origin (dynamic reflection)", "CORS", "high",
                            "Server reflects arbitrary Origin header values", "Attacker can read authenticated responses cross-origin from any domain",
                            "Validate Origin against a strict allowlist; do not reflect arbitrary origins", target_url
                        ))
                    else:
                        findings.append(self._finding(
                            "Reflected CORS origin (static)", "CORS", "medium",
                            f"Server echoed Origin: {acao1}", "Server may have a permissive CORS policy",
                            "Verify if evil.com is an intentional trusted origin; otherwise restrict to specific origins", target_url
                        ))

                if acao1 and acac1.lower() == "true" and acao1 != "*":
                    is_wildcard_creds = False
                    if acao1 == "https://evil.com":
                        try:
                            r3 = await c.options(url, headers={
                                "Origin": "https://another-test.com",
                                "Access-Control-Request-Method": "GET"
                            })
                            acao3 = r3.headers.get("access-control-allow-origin", "")
                            acac3 = r3.headers.get("access-control-allow-credentials", "")
                            if acao3 == "https://another-test.com" and acac3.lower() == "true":
                                is_wildcard_creds = True
                        except Exception:
                            pass

                    if is_wildcard_creds:
                        findings.append(self._finding(
                            "CORS with credentials from arbitrary origin (dynamic)", "CORS", "high",
                            f"ACAO: {acao1}, ACAC: true (reflected from multiple origins)", "Authenticated cross-origin reads possible from any domain",
                            "Restrict ACAO to a specific allowlist and never enable credentials with reflected origins", target_url
                        ))
                    elif acao1 != "https://evil.com":
                        findings.append(self._finding(
                            "CORS with credentials from non-wildcard origin", "CORS", "low",
                            f"ACAO: {acao1}, ACAC: true", "CORS policy allows credentials from a specific non-wildcard origin",
                            "Verify the allowed origin is intentional and properly restricted", target_url
                        ))
            except Exception:
                pass

        return findings

    def _check_cookies(self, headers: dict[str, str]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        set_cookie = headers.get("set-cookie", "")
        if not set_cookie:
            return findings

        import re as _re
        cookie_pattern = _re.compile(r'^([^=]+)=', _re.IGNORECASE)

        raw_cookies: list[str] = []
        if "\n" in set_cookie:
            raw_cookies = [c.strip() for c in set_cookie.split("\n") if c.strip()]
        elif "," in set_cookie:
            parts = set_cookie.split(",")
            current = ""
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                if cookie_pattern.match(part) and current:
                    raw_cookies.append(current)
                    current = part
                else:
                    current = f"{current}, {part}" if current else part
            if current:
                raw_cookies.append(current)
        else:
            raw_cookies = [set_cookie]

        seen_cookies: set[str] = set()
        for cookie in raw_cookies:
            c = cookie.strip()
            if not c:
                continue
            name = c.split("=")[0].strip() if "=" in c else c.strip()
            if not name or name.lower() in seen_cookies:
                continue
            seen_cookies.add(name.lower())

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

    async def _check_http_methods(self, target_url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        url = target_url if "://" in target_url else f"https://{target_url}"

        async with httpx.AsyncClient(timeout=8.0, verify=False) as c:
            try:
                r = await c.options(url, headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "GET"
                })
                allowed = r.headers.get("access-control-allow-methods", "")
                allow_header = r.headers.get("allow", "")
                methods_str = allowed or allow_header
                methods = [m.strip().upper() for m in methods_str.split(",") if m.strip()]

                dangerous = {"TRACE", "CONNECT", "TRACK"}
                for method in methods:
                    if method in dangerous:
                        findings.append(self._finding(
                            f"HTTP {method} method is enabled", "HTTP Methods", "high",
                            f"Allow header advertises {method}",
                            f"{method} method can be used for cross-site tracing or tunneling attacks",
                            f"Disable the {method} method on the server", target_url
                        ))

                if "PUT" in methods or "DELETE" in methods:
                    state_changing = []
                    if "PUT" in methods:
                        state_changing.append("PUT")
                    if "DELETE" in methods:
                        state_changing.append("DELETE")
                    findings.append(self._finding(
                        f"State-changing HTTP methods exposed: {', '.join(state_changing)}",
                        "HTTP Methods", "medium",
                        f"Allow header advertises {', '.join(state_changing)}",
                        "State-changing methods without proper authorization can be exploited",
                        "Ensure authentication and authorization are enforced for state-changing methods", target_url
                    ))

                if "OPTIONS" in methods and not methods:
                    pass

                if not methods:
                    resp = await c.get(url, headers={"User-Agent": "PhantomScan/1.0"})
                    allow = resp.headers.get("allow", "")
                    if allow:
                        get_methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
                        if "GET" in get_methods and "POST" not in get_methods:
                            findings.append(self._finding(
                                "Only GET method is allowed; POST not advertised", "HTTP Methods", "info",
                                "Allow header only lists GET", "POST endpoints may be hidden or not implemented",
                                "Verify POST endpoints are intentionally hidden or properly secured", target_url
                            ))
            except Exception:
                pass

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
