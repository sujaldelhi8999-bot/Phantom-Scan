from typing import Any

from app.agents import Agent


class FixerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Fixer Agent")
        self.severity_order = ["critical", "high", "medium", "low"]

    async def run(self, findings: list[dict[str, Any]], scan_id: int) -> dict[str, str]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Generating prioritized checklist for {len(findings)} findings")
        report = await self.generate_markdown_report(findings)
        self.status = "complete"
        await self.log_action("completed", "Generated prioritized fix checklist")
        return {"markdown_report": report}

    async def generate_markdown_report(self, findings: list[dict[str, Any]]) -> str:
        grouped = await self.group_by_severity(findings)
        lines = ["# PhantomScan Prioritized Fix Checklist", ""]
        for severity in self.severity_order:
            severity_findings = grouped.get(severity, [])
            lines.append(f"## {severity.title()} Severity")
            if not severity_findings:
                lines.append("- No findings")
                lines.append("")
                continue
            for index, finding in enumerate(severity_findings, start=1):
                title = finding.get("title", "Untitled finding")
                category = finding.get("category", "General")
                fix = finding.get("fix", "Review and remediate this issue according to vendor guidance.")
                cve_id = finding.get("cve_id")
                cve_text = f" ({cve_id})" if cve_id else ""
                lines.append(f"{index}. [ ] {title}{cve_text} - {category}")
                lines.append(f"   Fix: {fix}")
            lines.append("")
        return "\n".join(lines).strip()

    async def group_by_severity(self, findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        grouped = {severity: [] for severity in self.severity_order}
        for finding in findings:
            severity = str(finding.get("severity", "low")).lower()
            grouped.setdefault(severity, []).append(finding)
        return grouped
