import asyncio
import json
from collections.abc import Awaitable
from datetime import datetime, timezone
from typing import Any

from app.agents import Agent
from app.agents.ai_explainer import AIExplainerAgent
from app.agents.ai_security_analyst import AISecurityAnalystAgent
from app.agents.analyzer import AnalyzerAgent
from app.agents.browser_security import BrowserSecurityAgent
from app.agents.cve_matcher import CVEMatcherAgent
from app.agents.fixer import FixerAgent
from app.agents.hindi_explainer import HindiExplainerAgent
from app.agents.notifier import NotifierAgent
from app.agents.sandbox_manager import SandboxManagerAgent
from app.agents.scanner import ScannerAgent
from app.agents.security_assessment import (
    AccessControlAgent,
    ApiSecurityAgent,
    AuthSecurityAgent,
    DependencyAgent,
    InfrastructureAgent,
    InjectionAnalysisAgent,
    SessionSecurityAgent,
    ThreatIntelligenceAgent,
    WebSocketSecurityAgent,
)
from app.agents.shadow_recon import ShadowReconAgent
from app.database import (
    add_audit_log,
    create_finding,
    create_scan,
    get_audit_logs,
    get_findings,
    get_previous_scan_for_target,
    get_scan_artifacts,
    set_scan_artifacts,
    update_scan_progress,
    update_scan_status,
)
from app.models import FindingCreate, ScanRequest
from app.services.active_gate import ActiveTargetGate
from app.services.authorization import TargetAuthorizationService, VerifiedTarget, canonicalize_target
from app.services.execution import SafetyLimits
from app.websockets import scan_event_broker


class OrchestratorAgent(Agent):
    def __init__(self, limits: SafetyLimits | None = None) -> None:
        super().__init__("Orchestrator Agent")
        self.limits = limits or SafetyLimits.from_settings()

    async def run(
        self,
        scan_request: ScanRequest,
        scan_id: int | None = None,
        *,
        verified_target: VerifiedTarget | None = None,
        user_id: str = "local-user",
        authorization_context: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        target = canonicalize_target(scan_request.target_url)
        scan_request = scan_request.model_copy(update={"target_url": target.url})
        verified_target, authorization_context = await self.validate_execution(
            scan_request,
            verified_target,
            user_id,
            authorization_context,
        )

        if scan_id is None:
            scan_id = await create_scan(
                target_url=target.url,
                mode=scan_request.mode,
                intensity=scan_request.intensity,
                selected_tests=json.dumps(scan_request.selected_tests, separators=(",", ":")),
                user_id=user_id,
                authorization_id=verified_target.id if verified_target is not None else None,
                authorization_confirmed=scan_request.authorization_confirmed,
            )

        self.scan_id = scan_id
        self.status = "active"
        await update_scan_status(scan_id, "running")
        await self.set_progress(scan_id, 2, "orchestration_started")
        await self.log_action("started", f"Orchestrating {scan_request.mode} scan for {target.url}")
        await self.publish(scan_id, "orchestrator", {"status": "running", "progress": 2})

        try:
            scanner = ScannerAgent()
            shadow_recon = ShadowReconAgent()
            scanner_event, shadow_event = await self.gather_agents(
                self.run_agent("scanner", scanner.name, scanner.run(target.url, scan_id), scan_id),
                self.run_agent("shadow_recon", shadow_recon.name, shadow_recon.run(target.url, scan_id), scan_id),
            )
            scanner_output = scanner_event["result"]
            shadow_output = shadow_event["result"]
            await set_scan_artifacts(
                scan_id,
                scanner_output=scanner_output,
                shadow_recon_output=shadow_output,
            )
            await self.set_progress(scan_id, 30, "reconnaissance_complete")

            analyzer = AnalyzerAgent()
            cve_matcher = CVEMatcherAgent()
            browser_security = BrowserSecurityAgent(limits=self.limits)
            analysis_tasks = [
                self.run_agent(
                    "analyzer",
                    analyzer.name,
                    analyzer.run(target.url, scan_id, scanner_output),
                    scan_id,
                ),
                self.run_agent(
                    "cve_matcher",
                    cve_matcher.name,
                    cve_matcher.run(scanner_output.get("tech_stack", {}), scan_id),
                    scan_id,
                ),
                self.run_agent(
                    "browser_security",
                    browser_security.name,
                    browser_security.run(
                        target.url,
                        scan_id,
                        mode=scan_request.mode,
                        authorization_context=authorization_context,
                    ),
                    scan_id,
                ),
            ]
            assessment_agents = [
                ("authentication", AuthSecurityAgent()),
                ("access_control", AccessControlAgent()),
                ("api_security", ApiSecurityAgent()),
                ("session_security", SessionSecurityAgent()),
                ("injection_analysis", InjectionAnalysisAgent()),
                ("infrastructure", InfrastructureAgent()),
                ("websocket_security", WebSocketSecurityAgent()),
                ("dependency", DependencyAgent()),
                ("threat_intelligence", ThreatIntelligenceAgent()),
            ]
            for event_name, agent in assessment_agents:
                analysis_tasks.append(
                    self.run_agent(
                        event_name,
                        agent.name,
                        agent.run(target.url, scan_id, scanner_output, shadow_output),
                        scan_id,
                    )
                )

            if scan_request.mode == "pentest":
                sandbox = SandboxManagerAgent(limits=self.limits)
                business_logic_tests = [item.model_dump(mode="json") for item in scan_request.business_logic_tests]
                active_payload = {
                    "engine": "active_security",
                    "scan_id": scan_id,
                    "target_url": target.url,
                    "intensity": scan_request.intensity,
                    "selected_modules": scan_request.selected_tests,
                    "selected_tests": scan_request.selected_tests,
                    "business_logic_tests": business_logic_tests,
                    "workflow_rules": {"business_logic_tests": business_logic_tests},
                    "user_id": user_id,
                    "authorization_id": authorization_context.get("authorization_id"),
                    "authorization_context": authorization_context,
                }
                analysis_tasks.append(
                    self.run_agent(
                        "sandbox_manager",
                        sandbox.name,
                        sandbox.run_active_scan(active_payload, scan_id),
                        scan_id,
                    )
                )

            analysis_events = await self.gather_agents(*analysis_tasks)
            active_result = next(
                (
                    event["result"]
                    for event in analysis_events
                    if event.get("agent") == "sandbox_manager" and isinstance(event.get("result"), dict)
                ),
                None,
            )
            if active_result:
                await set_scan_artifacts(scan_id, active_security_output=active_result)
                for active_event in active_result.get("events", [])[:250]:
                    if not isinstance(active_event, dict):
                        continue
                    event_name = str(active_event.get("event") or "active_security_event")
                    await self.publish(
                        scan_id,
                        event_name,
                        {
                            "details": active_event.get("details"),
                            "selected_module": active_event.get("selected_module"),
                            "result": active_event.get("result"),
                            "request_count": active_event.get("request_count"),
                            "sandbox_id": active_event.get("sandbox_id"),
                        },
                    )
            browser_result = next(
                (
                    event["result"]
                    for event in analysis_events
                    if event.get("agent") == "browser_security" and isinstance(event.get("result"), dict)
                ),
                None,
            )
            if browser_result:
                await set_scan_artifacts(scan_id, browser_security_output=browser_result)
                await self.publish(
                    scan_id,
                    "browser_observation_completed",
                    {
                        "pages": len(browser_result.get("pages", [])),
                        "network_events": len(browser_result.get("network_events", [])),
                        "apis": len(browser_result.get("api_inventory", [])),
                        "findings": len(browser_result.get("findings", [])),
                    },
                )
            request_count = max(
                (int(event["result"].get("request_count", 0)) for event in analysis_events),
                default=0,
            )
            sandbox_id = next(
                (
                    str(event["result"]["sandbox_id"])
                    for event in analysis_events
                    if event["result"].get("sandbox_id")
                ),
                None,
            )
            await self.set_progress(
                scan_id,
                65,
                "analysis_complete",
                request_count=request_count,
                sandbox_id=sandbox_id,
            )
            findings = self.collect_findings(analysis_events, target.url)

            ai_explainer = AIExplainerAgent()
            hindi_explainer = HindiExplainerAgent()
            ai_event, hindi_event = await self.gather_agents(
                self.run_agent(
                    "ai_explainer",
                    ai_explainer.name,
                    ai_explainer.run(findings, scan_id),
                    scan_id,
                ),
                self.run_agent(
                    "hindi_explainer",
                    hindi_explainer.name,
                    hindi_explainer.run(findings, scan_id),
                    scan_id,
                ),
            )
            enriched_findings = ai_event["result"].get("findings", findings)
            hindi_findings = hindi_event["result"].get("findings", [])
            await set_scan_artifacts(scan_id, hindi_findings=hindi_findings)
            await self.set_progress(scan_id, 78, "explanations_complete", request_count=request_count)

            persisted_findings = await self.persist_findings(scan_id, enriched_findings, target.url)
            await self.set_progress(scan_id, 86, "findings_persisted", request_count=request_count)

            fixer = FixerAgent()
            fixer_event = await self.run_agent(
                "fixer",
                fixer.name,
                fixer.run(persisted_findings, scan_id),
                scan_id,
            )
            markdown_report = str(fixer_event["result"].get("markdown_report", ""))
            if active_result and active_result.get("final_report"):
                markdown_report = f"{markdown_report}\n\n{active_result['final_report']}" if markdown_report else str(active_result["final_report"])
            if browser_result:
                browser_report = self.browser_report(browser_result)
                markdown_report = f"{markdown_report}\n\n{browser_report}" if markdown_report else browser_report
            await set_scan_artifacts(scan_id, markdown_report=markdown_report)
            await self.set_progress(scan_id, 93, "report_complete", request_count=request_count)

            artifact_context = {
                "scanner_output": scanner_output,
                "shadow_recon_output": shadow_output,
                "hindi_findings": hindi_findings,
                "markdown_report": markdown_report,
                "active_security_output": active_result,
                "browser_security_output": browser_result,
            }
            ai_analyst_output = await self.run_ai_security_analyst(
                scan_id=scan_id,
                target_url=target.url,
                mode=scan_request.mode,
                intensity=scan_request.intensity,
                findings=persisted_findings,
                artifacts=artifact_context,
                request_count=request_count,
            )
            await set_scan_artifacts(scan_id, ai_analyst_output=ai_analyst_output)
            await self.set_progress(scan_id, 95, "ai_analysis_complete", request_count=request_count)

            summary = {
                "scan_id": scan_id,
                "target_url": target.url,
                "mode": scan_request.mode,
                "intensity": scan_request.intensity,
                "scanner": scanner_output,
                "shadow_recon": shadow_output,
                "findings": persisted_findings,
                "hindi_findings": hindi_findings,
                "markdown_report": markdown_report,
                "active_security": active_result,
                "browser_security": browser_result,
                "ai_analyst_output": ai_analyst_output,
            }
            notifier = NotifierAgent()
            notifier_event = await self.run_agent(
                "notifier",
                notifier.name,
                notifier.run(summary, scan_id),
                scan_id,
            )
            notification_result = notifier_event["result"]
            summary["notification"] = notification_result
            summary["status"] = "complete"
            await set_scan_artifacts(scan_id, notification_result=notification_result)
            await self.set_progress(scan_id, 97, "notification_complete", request_count=request_count)

            await update_scan_status(scan_id, "complete")
            self.status = "complete"
            await self.log_action("completed", f"Scan completed with {len(persisted_findings)} findings")
            await self.publish(scan_id, "scan_complete", {"status": "complete", "progress": 100})
            return summary
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.status = "error"
            await update_scan_status(scan_id, "error", str(exc)[:1000])
            await self.log_action("error", str(exc)[:2000])
            await self.publish(scan_id, "scan_failed", {"status": "error", "error": str(exc)})
            return {"scan_id": scan_id, "status": "error", "error": str(exc)}

    async def run_ai_security_analyst(
        self,
        *,
        scan_id: int,
        target_url: str,
        mode: str,
        intensity: str,
        findings: list[dict[str, Any]],
        artifacts: dict[str, Any],
        request_count: int,
    ) -> dict[str, Any]:
        fallback = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ai_available": False,
            "ai_status": "AI Security Analyst unavailable - deterministic scan output remains available",
            "safety": {"grounded_in_scan_evidence": True, "can_start_active_test": False, "active_tests": "recommend_only"},
            "security_summary": {
                "overall_security_posture": "Unavailable",
                "most_important_risks": [],
                "immediate_attention": "AI analyst did not complete; use persisted findings and reports.",
                "recommended_next_action": "Review persisted findings by severity and confidence.",
            },
            "priorities": [],
            "related_security_chains": [],
            "root_causes": [],
            "remediation_plan": {"IMMEDIATE": [], "TODAY": [], "THIS_WEEK": []},
            "grounding": {"source": "scanner-generated evidence only"},
        }
        try:
            previous_scan = await get_previous_scan_for_target(target_url, scan_id)
            previous_findings = await get_findings(int(previous_scan["id"])) if previous_scan else []
            previous_artifacts = await get_scan_artifacts(int(previous_scan["id"])) if previous_scan else None
            logs = await get_audit_logs(scan_id)
            analyst = AISecurityAnalystAgent()
            event = await self.run_agent(
                "ai_security_analyst",
                analyst.name,
                analyst.run(
                    scan={"id": scan_id, "target_url": target_url, "mode": mode, "intensity": intensity},
                    findings=findings,
                    artifacts=artifacts,
                    previous_scan=previous_scan,
                    previous_findings=previous_findings,
                    previous_artifacts=previous_artifacts,
                    logs=logs,
                ),
                scan_id,
            )
            return event["result"]
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await add_audit_log(
                scan_id,
                "AI Security Analyst Agent",
                "skipped",
                f"AI analyst failed without failing the scan: {exc}"[:2000],
                request_count=request_count,
            )
            return {**fallback, "error": str(exc)[:500]}

    async def gather_agents(self, *operations: Awaitable[dict[str, Any]]) -> list[dict[str, Any]]:
        tasks = [asyncio.create_task(operation) for operation in operations]
        try:
            return await asyncio.gather(*tasks)
        except BaseException:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    async def validate_execution(
        self,
        request: ScanRequest,
        verified_target: VerifiedTarget | None,
        user_id: str,
        authorization_context: dict[str, object] | None = None,
    ) -> tuple[VerifiedTarget | None, dict[str, object]]:
        target = canonicalize_target(request.target_url)
        if request.mode == "defend":
            if request.selected_tests or request.business_logic_tests:
                raise PermissionError("Defend mode cannot invoke active test modules")
            if verified_target is not None or request.authorization_confirmed or request.authorization_id is not None:
                raise PermissionError("Defend mode cannot receive active-test authorization")
            return None, {
                "allowed": True,
                "target_url": target.url,
                "target_origin": target.origin,
                "authorization_status": "NOT_REQUIRED",
                "reason": "Passive defend scan",
                "authorization_id": None,
                "is_lab": False,
            }

        if not request.selected_tests:
            raise PermissionError("Pentest execution requires at least one selected test module")
        if request.business_logic_tests and "business_logic" not in request.selected_tests:
            raise PermissionError("Business logic definitions require the business_logic module")
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit(target.url, user_id, request.authorization_id)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        if decision.authorization_status == "VERIFIED" and not request.authorization_confirmed:
            raise PermissionError("Verified external pentest targets require manual authorization confirmation")
        if verified_target is not None and decision.verified_target is not None and verified_target.id != decision.verified_target.id:
            raise PermissionError("Pentest authorization does not match the requested target")
        return decision.verified_target, decision.to_context()

    async def run_agent(
        self,
        event_name: str,
        agent_name: str,
        operation: Awaitable[dict[str, Any]],
        scan_id: int,
    ) -> dict[str, Any]:
        await self.publish(
            scan_id,
            event_name,
            {"agent": event_name, "agent_name": agent_name, "status": "active"},
        )
        try:
            result = await operation
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await add_audit_log(scan_id, agent_name, "error", str(exc)[:2000])
            await self.publish(
                scan_id,
                event_name,
                {"agent": event_name, "agent_name": agent_name, "status": "error", "error": str(exc)},
            )
            await self.log_action("agent_error", f"{agent_name} failed: {exc}"[:2000])
            raise
        event = {
            "agent": event_name,
            "agent_name": agent_name,
            "status": "complete",
            "result": result,
        }
        await self.publish(scan_id, event_name, event)
        return event

    def collect_findings(self, events: list[dict[str, Any]], target_url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for event in events:
            result = event.get("result", {})
            default_agent = str(event.get("agent_name") or "Orchestrator Agent")
            for finding in result.get("findings", []):
                if isinstance(finding, dict):
                    findings.append({"agent": default_agent, **finding})
            findings.extend(self.cve_matches_to_findings(result.get("cve_matches", []), target_url))
            findings.extend(self.pentest_responses_to_findings(result.get("abnormal_responses", []), target_url))
        return findings

    def cve_matches_to_findings(
        self,
        cve_matches: list[dict[str, Any]],
        target_url: str,
    ) -> list[dict[str, Any]]:
        findings = []
        for match in cve_matches:
            score = match.get("cvss_score")
            cve_id = match.get("cve_id") or "Unknown CVE"
            technology = match.get("technology") or "detected technology"
            findings.append(
                {
                    "title": f"Known vulnerability in {technology}: {cve_id}",
                    "severity": self.cvss_to_severity(score),
                    "confidence": "POTENTIAL",
                    "category": "CVE",
                    "target": target_url,
                    "endpoint": target_url,
                    "description": match.get("description") or "NVD reported a matching CVE for detected technology.",
                    "how_exploited": "A reachable affected version may be targeted with the techniques documented for this CVE.",
                    "fix": "Upgrade the affected package or service to a vendor-supported version that remediates the CVE.",
                    "verification": "Confirm the deployed version is outside the affected range and rerun dependency detection.",
                    "agent": "CVE Matcher Agent",
                    "cve_id": match.get("cve_id"),
                    "cvss_score": score,
                }
            )
        return findings

    def pentest_responses_to_findings(
        self,
        abnormal_responses: list[dict[str, Any]],
        target_url: str,
    ) -> list[dict[str, Any]]:
        findings = []
        for response in abnormal_responses:
            test = response.get("test", "Pentest check")
            findings.append(
                {
                    "title": f"Abnormal response during {test}",
                    "severity": "HIGH" if test in {"SQL Injection", "Open Redirect", "Auth Bypass"} else "MEDIUM",
                    "confidence": "MEDIUM",
                    "category": "Pentest",
                    "target": target_url,
                    "endpoint": response.get("url") or target_url,
                    "description": f"The endpoint responded abnormally to {test}.",
                    "how_exploited": "An attacker may replay the observed request pattern to probe the abnormal behavior.",
                    "fix": "Validate inputs and enforce authorization on every protected route.",
                    "verification": "Repeat the authorized request after remediation and confirm the abnormal response is absent.",
                    "agent": "Pentest Agent",
                    "cve_id": None,
                    "cvss_score": None,
                }
            )
        return findings

    @staticmethod
    def cvss_to_severity(score: Any) -> str:
        if score is None:
            return "MEDIUM"
        try:
            score_value = float(score)
        except (TypeError, ValueError):
            return "MEDIUM"
        if score_value >= 9.0:
            return "CRITICAL"
        if score_value >= 7.0:
            return "HIGH"
        if score_value >= 4.0:
            return "MEDIUM"
        return "LOW"

    async def persist_findings(
        self,
        scan_id: int,
        findings: list[dict[str, Any]],
        target_url: str,
    ) -> list[dict[str, Any]]:
        existing = await get_findings(scan_id)
        seen = {
            self.finding_key(FindingCreate(**{name: row.get(name) for name in FindingCreate.model_fields}))
            for row in existing
        }
        for finding in findings:
            try:
                normalized = self.normalize_finding(finding, target_url)
            except ValueError as exc:
                await add_audit_log(scan_id, self.name, "finding_skipped", str(exc)[:2000])
                continue
            key = self.finding_key(normalized)
            if key in seen:
                continue
            finding_id = await create_finding(scan_id, normalized)
            await self.publish(
                scan_id,
                "finding_created",
                {"finding_id": finding_id, "title": normalized.title, "severity": normalized.severity},
            )
            seen.add(key)
        return await get_findings(scan_id)

    @staticmethod
    def normalize_finding(finding: dict[str, Any], target_url: str) -> FindingCreate:
        def first_text(*names: str, default: str = "") -> str:
            for name in names:
                value = finding.get(name)
                if value is not None and str(value).strip():
                    return str(value).strip()
            return default

        severity = str(finding.get("severity") or "INFO").upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            severity = "INFO"
        confidence = str(finding.get("confidence") or "MEDIUM").upper()
        if confidence not in {"CONFIRMED", "HIGH", "MEDIUM", "LOW", "POTENTIAL"}:
            confidence = "POTENTIAL"
        remediation_status = str(finding.get("remediation_status") or "OPEN").upper()
        if remediation_status not in {"OPEN", "IN_PROGRESS", "RESOLVED"}:
            remediation_status = "OPEN"
        verification_status = str(finding.get("verification_status") or "NOT_VERIFIED").upper()
        if verification_status not in {"NOT_VERIFIED", "FIX_VERIFIED", "ISSUE_STILL_PRESENT", "VERIFY_FAILED"}:
            verification_status = "NOT_VERIFIED"
        risk_status = str(finding.get("risk_status") or "ACTIVE").upper()
        if risk_status not in {"ACTIVE", "FALSE_POSITIVE", "ACCEPTED_RISK"}:
            risk_status = "ACTIVE"

        title = first_text("title", "name", "issue", "vulnerability")
        category = first_text("category", "type", "module", default="Security")
        agent = first_text("agent", "source", default="Orchestrator Agent")
        if not title:
            raise ValueError("Finding is missing a title")

        return FindingCreate(
            title=title[:300],
            category=category[:120],
            severity=severity,
            confidence=confidence,
            target=first_text("target", "target_url", default=target_url)[:2048],
            endpoint=first_text("endpoint", "url", "path", default=target_url)[:2048],
            evidence=first_text("evidence", "description", "details", default="")[:12000],
            impact=first_text("impact", "how_exploited", "risk", default="")[:4000],
            recommendation=first_text("recommendation", "fix", "remediation", default="")[:6000],
            verification=first_text(
                "verification",
                default="Rerun the relevant PhantomScan analysis after remediation and confirm the evidence is absent.",
            )[:4000],
            agent=agent[:120],
            timestamp=finding.get("timestamp") or datetime.now(timezone.utc),
            cve_id=str(finding["cve_id"])[:40] if finding.get("cve_id") else None,
            cvss_score=finding.get("cvss_score"),
            parameter=first_text("parameter", default="")[:200] or None,
            module=first_text("module", "selected_module", default="")[:120] or None,
            recommended_fix=first_text("recommended_fix", "recommendation", "fix", default="")[:6000] or None,
            remediation_status=remediation_status,
            verification_status=verification_status,
            risk_status=risk_status,
        )

    @staticmethod
    def finding_key(finding: FindingCreate) -> tuple[Any, ...]:
        data = finding.model_dump(mode="json")
        return tuple(data[name] for name in FindingCreate.model_fields if name != "timestamp")

    async def set_progress(
        self,
        scan_id: int,
        progress: int,
        phase: str,
        *,
        request_count: int | None = None,
        sandbox_id: str | None = None,
    ) -> None:
        await update_scan_progress(
            scan_id,
            progress,
            request_count=request_count,
            sandbox_id=sandbox_id,
        )
        payload: dict[str, Any] = {"progress": progress, "phase": phase, "status": "running"}
        if request_count is not None:
            payload["request_count"] = request_count
        if sandbox_id is not None:
            payload["sandbox_id"] = sandbox_id
        await self.publish(scan_id, "scan_progress", payload)

    async def publish(self, scan_id: int, event: str, payload: dict[str, Any]) -> None:
        await scan_event_broker.publish(
            scan_id,
            {"event": event, "type": event, "payload": payload},
        )

    @staticmethod
    def browser_report(browser_result: dict[str, Any]) -> str:
        safety = browser_result.get("safety", {})
        lines = [
            "# Browser Observation Report",
            f"Engine: {browser_result.get('browser_engine', 'unknown')}",
            f"Pages visited: {len(browser_result.get('pages', []))}",
            f"Network events: {len(browser_result.get('network_events', []))}",
            f"APIs discovered: {len(browser_result.get('api_inventory', []))}",
            f"Console events: {len(browser_result.get('console_events', []))}",
            f"WebSockets: {len(browser_result.get('websockets', []))}",
            f"Safety pause: {safety.get('pause_reason') or 'none'}",
        ]
        for finding in browser_result.get("findings", [])[:10]:
            lines.append(f"- [{finding.get('severity')}/{finding.get('confidence')}] {finding.get('title')}")
        return "\n".join(lines)
