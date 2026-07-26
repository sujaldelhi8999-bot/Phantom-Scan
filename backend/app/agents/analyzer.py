from typing import Any

import httpx

from app.agents import Agent


class AnalyzerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Analyzer Agent")

    async def run(self, target_url: str, scan_id: int, scanner_output: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Analyzing security headers for {target_url}")
        headers = await self.get_headers(target_url, scanner_output)
        findings = await self.detect_misconfigurations(target_url, headers)
        self.status = "complete"
        await self.log_action("completed", f"Generated {len(findings)} configuration findings")
        return {"findings": findings}

    async def get_headers(self, target_url: str, scanner_output: dict[str, Any] | None) -> dict[str, str]:
        tech_stack = (scanner_output or {}).get("tech_stack", {})
        headers = tech_stack.get("headers")
        if isinstance(headers, dict) and headers:
            return {str(key).lower(): str(value) for key, value in headers.items()}

        url = target_url if "://" in target_url else f"https://{target_url}"
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            try:
                response = await client.get(url)
                return {key.lower(): value for key, value in response.headers.items()}
            except httpx.HTTPError as exc:
                await self.log_action("http_error", f"Could not fetch headers: {exc}")
                return {}

    async def detect_misconfigurations(self, target_url: str, headers: dict[str, str]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if "content-security-policy" not in headers:
            findings.append(await self.build_finding("Missing Content Security Policy", "medium", "Security Headers", "The application does not send a Content-Security-Policy header.", "Attackers can abuse injection flaws to execute untrusted scripts because the browser has no policy limiting script sources.", "Add a strict Content-Security-Policy header at the web server or application middleware."))
        if "strict-transport-security" not in headers:
            severity = "high" if target_url.startswith("https://") else "medium"
            findings.append(await self.build_finding("Missing HTTP Strict Transport Security", severity, "Security Headers", "The application does not send an HSTS header.", "An attacker on the network can attempt SSL stripping or downgrade users to plaintext HTTP where supported.", "Return Strict-Transport-Security: max-age=31536000; includeSubDomains; preload from HTTPS responses."))
        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
            findings.append(await self.build_finding("Missing Clickjacking Protection", "medium", "Security Headers", "The application does not set X-Frame-Options or CSP frame-ancestors.", "Attackers can embed the site in a malicious frame and trick users into clicking sensitive UI elements.", "Set X-Frame-Options: DENY or add frame-ancestors 'none' to Content-Security-Policy."))

        access_control_origin = headers.get("access-control-allow-origin", "")
        access_control_credentials = headers.get("access-control-allow-credentials", "").lower()
        if access_control_origin == "*" and access_control_credentials == "true":
            findings.append(await self.build_finding("Dangerous CORS Configuration", "high", "CORS", "CORS allows every origin while credentials are enabled.", "A malicious origin can send authenticated browser requests and read sensitive API responses.", "Restrict Access-Control-Allow-Origin to trusted origins and disable credentialed wildcard CORS."))
        elif access_control_origin == "*":
            findings.append(await self.build_finding("Permissive CORS Policy", "low", "CORS", "CORS allows requests from every origin.", "Untrusted websites can read non-credentialed API responses exposed by the browser.", "Replace wildcard CORS with an allowlist of trusted frontend origins."))

        if headers.get("server") or headers.get("x-powered-by"):
            findings.append(await self.build_finding("Technology Version Disclosure", "low", "Information Disclosure", "Server technology is exposed in response headers.", "Attackers can fingerprint the stack and prioritize known exploits for the disclosed products.", "Remove or minimize Server and X-Powered-By headers in the web server configuration."))
        return findings

    async def build_finding(self, title: str, severity: str, category: str, description: str, how_exploited: str, fix: str) -> dict[str, Any]:
        return {
            "title": title,
            "severity": severity,
            "category": category,
            "description": description,
            "how_exploited": how_exploited,
            "fix": fix,
            "cve_id": None,
            "cvss_score": None,
        }
