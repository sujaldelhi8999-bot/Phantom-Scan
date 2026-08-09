"""
CI/CD Integration Services - SARIF export, GitHub Actions workflows, PR comments, compliance reports.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from app.database import (
    get_connection,
    get_findings,
    get_scan,
    get_scan_artifacts,
    list_finding_sources,
    list_scan_sources,
    list_source_correlations,
)
from app.models import (
    GitHubActionsWorkflowRequest,
    GitHubActionsWorkflowResponse,
    ComplianceReportRequest,
    ComplianceReportResponse,
)

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

CWE_TO_RULE_ID: dict[str, str] = {
    "CWE-89": "phantomscan/sql-injection",
    "CWE-79": "phantomscan/xss",
    "CWE-918": "phantomscan/ssrf",
    "CWE-352": "phantomscan/csrf",
    "CWE-22": "phantomscan/path-traversal",
    "CWE-78": "phantomscan/os-command-injection",
    "CWE-798": "phantomscan/hardcoded-secret",
    "CWE-502": "phantomscan/insecure-deserialization",
    "CWE-611": "phantomscan/xxe",
    "CWE-287": "phantomscan/auth-bypass",
    "CWE-200": "phantomscan/info-disclosure",
    "CWE-79": "phantomscan/reflected-xss",
}


def _rule_id_for(finding: dict[str, Any]) -> str:
    category = str(finding.get("category") or "").lower()
    for keyword, rule_id in {
        "sql": "phantomscan/sql-injection",
        "xss": "phantomscan/xss",
        "ssrf": "phantomscan/ssrf",
        "csrf": "phantomscan/csrf",
        "command": "phantomscan/os-command-injection",
        "path": "phantomscan/path-traversal",
        "secret": "phantomscan/hardcoded-secret",
        "xxe": "phantomscan/xxe",
        "auth": "phantomscan/auth-bypass",
        "injection": "phantomscan/injection",
    }.items():
        if keyword in category:
            return rule_id
    return "phantomscan/generic-finding"


def _severity_to_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(
        str(severity).lower(), "warning"
    )


async def build_sarif(scan_id: int) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from scan findings."""
    findings = await get_findings(scan_id)
    sources = await list_scan_sources(scan_id)

    tool_names = sorted({str(s.get("source_type") or "phantomscan") for s in sources}) or ["phantomscan"]

    results: list[dict[str, Any]] = []
    for finding in findings:
        location = _finding_location(finding)
        rule_id = _rule_id_for(finding)
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _severity_to_level(str(finding.get("severity") or "medium")),
            "message": {"text": str(finding.get("title") or finding.get("evidence") or "Security finding")},
            "locations": [location] if location else [],
            "properties": {
                "findingId": finding.get("id"),
                "severity": str(finding.get("severity") or "MEDIUM"),
                "confidence": str(finding.get("confidence") or "MEDIUM"),
                "category": str(finding.get("category") or ""),
                "target": str(finding.get("target") or ""),
                "endpoint": str(finding.get("endpoint") or ""),
                "parameter": str(finding.get("parameter") or ""),
                "evidence": str(finding.get("evidence") or "")[:2000],
                "recommendation": str(
                    finding.get("recommendation")
                    or finding.get("fix")
                    or finding.get("recommended_fix")
                    or ""
                )[:2000],
            },
        }
        results.append(result)

    # Tool rules (best-effort from findings)
    rules: dict[str, dict[str, Any]] = {}
    for result in results:
        rule_id = result["ruleId"]
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.split("/")[-1],
                "shortDescription": {"text": result["message"]["text"][:120]},
            }
    rules_list = [
        {
            **rules[rule_id],
            "properties": {
                "tags": ["security", "phantomscan"],
                "precision": "high",
            },
        }
        for rule_id in rules
    ]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PhantomScan",
                        "fullName": "PhantomScan Multi-Source Security Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/",
                        "rules": rules_list,
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
            }
        ],
    }


def _finding_location(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Build a SARIF physical location from a finding."""
    file_path = finding.get("file_path")
    if not file_path:
        return None
    region: dict[str, Any] = {}
    start_line = finding.get("start_line") or finding.get("line")
    if start_line:
        region["startLine"] = int(start_line)
    end_line = finding.get("end_line")
    if end_line:
        region["endLine"] = int(end_line)
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": str(file_path)},
            **({"region": region} if region else {}),
        }
    }


def build_github_actions_workflow(request: GitHubActionsWorkflowRequest) -> GitHubActionsWorkflowResponse:
    """Generate a GitHub Actions workflow YAML for PhantomScan scanning."""
    scan_request = request.scan_config
    source_lines: list[str] = []
    for source in scan_request.sources:
        if source.type == "github":
            source_lines.append(
                f"          - type: github\n"
                f"            repo_url: {source.repo_url}\n"
                f"            branch: {source.branch}\n"
                f"            auth_type: oauth_user\n"
                f"            scan_mode: {source.scan_mode}\n"
            )
        elif source.type == "local":
            source_lines.append(
                f"          - type: local\n"
                f"            path: {source.path}\n"
            )
        elif source.type == "live":
            source_lines.append(
                f"          - type: live\n"
                f"            target_url: {source.target_url}\n"
                f"            authorization_confirmed: false\n"
            )

    fail_on = ", ".join(f'"{sev}"' for sev in request.fail_on_severity)

    trigger_block: list[str]
    if request.trigger == "push":
        trigger_block = ["on:", "  push:", "    branches:", "      - main"]
    elif request.trigger == "schedule":
        cron = request.schedule_cron or "0 2 * * *"
        trigger_block = ["on:", "  schedule:", f"    - cron: '{cron}'"]
    elif request.trigger == "workflow_dispatch":
        trigger_block = ["on:", "  workflow_dispatch:"]
    else:
        trigger_block = ["on:", "  pull_request:"]

    steps: list[str] = []
    steps.append("      - name: Checkout code")
    steps.append("        uses: actions/checkout@v4")
    if any(s.type == "live" for s in scan_request.sources):
        steps.append("")
        steps.append("      - name: Verify target authorization")
        steps.append("        run: echo 'Live target scanning requires manual authorization in PhantomScan'")
    steps.append("")
    steps.append("      - name: Run PhantomScan security scan")
    steps.append("        uses: phantomscan/phantomscan-action@v1")
    steps.append("        with:")
    steps.append("          api-url: ${{ secrets.PHANTOMSCAN_API_URL }}")
    steps.append("          api-key: ${{ secrets.PHANTOMSCAN_API_KEY }}")
    steps.append("          scan-config: |")
    steps.extend(f"            {line}" for line in (["name: PR security scan", f"intensity: {scan_request.intensity}"]))
    steps.append("            sources:")
    steps.extend(f"            {line}" for line in source_lines)
    steps.append("            correlate_findings: true")
    if request.upload_sarif:
        steps.append("")
        steps.append("      - name: Upload SARIF to GitHub Code Scanning")
        steps.append("        uses: github/codeql-action/upload-sarif@v3")
        steps.append("        with:")
        steps.append("          sarif_file: phantomscan-results.sarif")
    if request.comment_on_pr and request.trigger == "pull_request":
        steps.append("")
        steps.append("      - name: Comment findings on PR")
        steps.append("        uses: phantomscan/pr-comment-action@v1")
        steps.append("        with:")
        steps.append("          scan-id: ${{ steps.phantomscan.outputs.scan_id }}")
        steps.append("          fail-on-severity: " + f"[{fail_on}]")

    workflow = "\n".join(
        [
            "name: PhantomScan Security Scan",
            "",
            *trigger_block,
            "jobs:",
            "  security-scan:",
            "    runs-on: ubuntu-latest",
            "    permissions:",
            "      contents: read",
            "      security-events: write",
            "      pull-requests: write",
            "    steps:",
            *steps,
            "",
        ]
    )

    return GitHubActionsWorkflowResponse(workflow_yaml=workflow)


async def generate_compliance_report(request: ComplianceReportRequest) -> ComplianceReportResponse:
    """Generate a compliance report from scan evidence."""
    scan = await get_scan(request.scan_id)
    if scan is None:
        raise ValueError(f"Scan {request.scan_id} not found")
    findings = await get_findings(request.scan_id)
    artifacts = await get_scan_artifacts(request.scan_id) or {}

    framework_defs = {
        "pci_dss": {
            "name": "PCI DSS 4.0",
            "controls": {
                "6.2.3": "Securely implement software development practices",
                "6.4.2": "Automated technical solutions for detection of anomalous behavior",
                "11.3.1": "Automated scans for vulnerabilities",
            },
        },
        "soc2": {
            "name": "SOC 2",
            "controls": {
                "CC7.1": "Systems for continuous monitoring",
                "CC7.2": "Detect and respond to incidents",
                "CC7.3": "Evaluate security events",
            },
        },
        "iso27001": {
            "name": "ISO/IEC 27001",
            "controls": {
                "A.12.6.1": "Management of technical vulnerabilities",
                "A.8.25": "Secure development lifecycle",
                "A.5.10": "Malware protection",
            },
        },
        "hipaa": {
            "name": "HIPAA Security Rule",
            "controls": {
                "164.308(a)(1)": "Security management process",
                "164.312(e)(1)": "Transmission security",
                "164.308(a)(8)": "Evaluation",
            },
        },
        "gdpr": {
            "name": "GDPR",
            "controls": {
                "Art. 32": "Security of processing",
                "Art. 25": "Data protection by design",
            },
        },
        "nist_csf": {
            "name": "NIST Cybersecurity Framework",
            "controls": {
                "PR.IP-12": "Vulnerability management plans",
                "DE.CM-8": "Vulnerability scans",
                "RS.MI-3": "Mitigate vulnerabilities",
            },
        },
        "cis": {
            "name": "CIS Critical Security Controls",
            "controls": {
                "CSC 4": "Secure configuration",
                "CSC 7": "Continuous vulnerability management",
                "CSC 16": "Application software security",
            },
        },
    }

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "INFO").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    by_framework: dict[str, dict[str, Any]] = {}
    for framework in request.frameworks:
        definition = framework_defs.get(framework, {"name": framework, "controls": {}})
        controls: list[dict[str, Any]] = []
        for control_id, control_name in definition["controls"].items():
            control_findings = [
                {
                    "id": f.get("id"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "status": "open" if f.get("remediation_status") != "RESOLVED" else "resolved",
                }
                for f in findings
                if _control_matches(control_id, f)
            ] or []
            controls.append(
                {
                    "id": control_id,
                    "name": control_name,
                    "status": "COMPLIANT" if not control_findings else "NON_COMPLIANT",
                    "findings_count": len(control_findings),
                    "findings": control_findings if request.include_evidence else [],
                }
            )
        overall = "COMPLIANT" if all(c["status"] == "COMPLIANT" for c in controls) else "NON_COMPLIANT"
        by_framework[framework] = {
            "name": definition["name"],
            "overall_status": overall,
            "controls": controls,
        }

    report_id = f"cpl-{uuid.uuid4().hex[:12]}"
    generated_at = datetime.now(timezone.utc)
    expires_at = generated_at + timedelta(days=30)

    summary = {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "frameworks": {fw: by_framework[fw]["overall_status"] for fw in by_framework},
        "scan_target": str(scan.get("target_url") or ""),
        "scan_mode": str(scan.get("mode") or ""),
        "ai_analysis_available": bool(artifacts.get("ai_analyst_output")),
    }

    # Persist report metadata
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            SELECT COUNT(*) AS count FROM pragma_table_info('compliance_reports')
            WHERE name IN ('report_id', 'content')
            """
        )
        row = await cursor.fetchone()
        has_new_columns = int(row["count"]) == 2 if row else False
        content = _render_report(request, by_framework, summary, severity_counts)
        if has_new_columns:
            await connection.execute(
                """
                INSERT INTO compliance_reports (
                    report_id, scan_id, frameworks, format, file_path, download_url, summary, content, generated_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    request.scan_id,
                    json.dumps(request.frameworks),
                    request.format,
                    f"compliance/{report_id}.{request.format}",
                    f"/api/ci/reports/{report_id}/download",
                    json.dumps(summary),
                    content,
                    generated_at.isoformat(),
                    expires_at.isoformat(),
                ),
            )
        else:
            await connection.execute(
                """
                INSERT INTO compliance_reports (scan_id, frameworks, format, file_path, summary, generated_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.scan_id,
                    json.dumps(request.frameworks),
                    request.format,
                    f"compliance/{report_id}.{request.format}",
                    json.dumps(summary),
                    generated_at.isoformat(),
                    expires_at.isoformat(),
                ),
            )
        await connection.commit()

    return ComplianceReportResponse(
        report_id=report_id,
        scan_id=request.scan_id,
        frameworks=list(request.frameworks),
        format=request.format,
        download_url=f"/api/ci/reports/{report_id}/download",
        generated_at=generated_at,
        expires_at=expires_at,
        summary=summary,
    )


def _control_matches(control_id: str, finding: dict[str, Any]) -> bool:
    """Best-effort mapping of findings to compliance controls."""
    category = str(finding.get("category") or "").lower()
    title = str(finding.get("title") or "").lower()
    haystack = f"{category} {title}"
    control_keywords = {
        "6.2.3": ["sql", "injection", "xss", "csrf", "ssrf"],
        "6.4.2": ["xss", "injection", "ssrf", "jwt"],
        "11.3.1": ["sql", "injection", "ssrf", "rce"],
        "CC7.1": ["sql", "injection", "ssrf", "rce", "secret"],
        "CC7.2": ["xss", "csrf", "auth", "session"],
        "CC7.3": ["ssrf", "rce", "command"],
        "A.12.6.1": ["sql", "injection", "xss", "ssrf", "rce"],
        "A.8.25": ["xss", "injection", "csrf"],
        "A.5.10": ["malware", "upload", "webshell"],
        "164.308(a)(1)": ["sql", "injection", "rce", "secret"],
        "164.312(e)(1)": ["tls", "ssl", "crypto"],
        "164.308(a)(8)": ["auth", "session", "access"],
        "Art. 32": ["sql", "injection", "xss", "ssrf", "secret"],
        "Art. 25": ["xss", "csrf", "session", "cors"],
        "PR.IP-12": ["sql", "injection", "xss", "ssrf", "rce"],
        "DE.CM-8": ["secret", "dependency", "tls"],
        "RS.MI-3": ["sql", "injection", "xss", "ssrf"],
        "CSC 4": ["config", "header", "tls", "cors"],
        "CSC 7": ["sql", "injection", "xss", "ssrf", "secret"],
        "CSC 16": ["xss", "injection", "csrf", "upload"],
    }
    keywords = control_keywords.get(control_id, [])
    return any(kw in haystack for kw in keywords)


def _render_report(
    request: ComplianceReportRequest,
    by_framework: dict[str, dict[str, Any]],
    summary: dict[str, Any],
    severity_counts: dict[str, int],
) -> str:
    """Render the report body per format."""
    lines = [
        f"# PhantomScan Compliance Report",
        f"",
        f"- **Scan ID**: {request.scan_id}",
        f"- **Target**: {summary['scan_target']}",
        f"- **Generated**: {datetime.now(timezone.utc).isoformat()}",
        f"- **Total findings**: {summary['total_findings']}",
        f"",
        "## Severity breakdown",
        f"",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if severity_counts.get(sev):
            lines.append(f"- {sev}: {severity_counts[sev]}")
    lines.append("")
    lines.append("## Framework results")
    lines.append("")
    for framework, result in by_framework.items():
        lines.append(f"### {result['name']} — {result['overall_status']}")
        lines.append("")
        for control in result["controls"]:
            lines.append(f"- **{control['id']}** {control['name']}: {control['status']} ({control['findings_count']} findings)")
            if request.include_evidence and control["findings"]:
                for finding in control["findings"][:5]:
                    lines.append(f"  - #{finding['id']} {finding['title']} [{finding['severity']}]")
    lines.append("")
    lines.append("---")
    lines.append("Generated by PhantomScan")
    return "\n".join(lines)


async def save_pr_comment(scan_id: int, pr_number: int, repo_full_name: str, comment: str) -> int:
    """Persist a PR comment record for the PR comment bot."""
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pr_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                pr_number INTEGER NOT NULL,
                repo_full_name TEXT NOT NULL,
                comment TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor = await connection.execute(
            "INSERT INTO pr_comments (scan_id, pr_number, repo_full_name, comment) VALUES (?, ?, ?, ?)",
            (scan_id, pr_number, repo_full_name, comment),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def get_pr_comments(scan_id: int) -> list[dict[str, Any]]:
    """List PR comments for a scan."""
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM pr_comments WHERE scan_id = ? ORDER BY id ASC",
            (scan_id,),
        )
        return [dict(row) for row in await cursor.fetchall()]


async def build_pr_comment(scan_id: int) -> str:
    """Build a PR comment body from scan findings."""
    findings = await get_findings(scan_id)
    correlations = await list_source_correlations(scan_id)
    if not findings:
        return "## PhantomScan Security Scan\n\nNo findings detected. :white_check_mark:"

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "INFO").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines = [
        "## PhantomScan Security Scan Results",
        "",
        f"### Summary",
        "",
        f"- **Findings**: {len(findings)}",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if severity_counts.get(sev):
            lines.append(f"- **{sev}**: {severity_counts[sev]}")
    lines.append("")
    lines.append("### Findings")
    lines.append("")
    for f in findings[:10]:
        lines.append(
            f"- [{str(f.get('severity') or 'INFO').upper()}] **{f.get('title')}** "
            f"(`{f.get('category') or 'n/a'}`) — {str(f.get('endpoint') or f.get('file_path') or f.get('target') or '')}"
        )
    if len(findings) > 10:
        lines.append(f"- ...and {len(findings) - 10} more")
    if correlations:
        lines.append("")
        lines.append(f"### Correlations")
        lines.append("")
        lines.append(f"- {len(correlations)} findings correlated across sources")
    lines.append("")
    lines.append("---")
    lines.append("_Generated by [PhantomScan](https://github.com/)_")
    return "\n".join(lines)
