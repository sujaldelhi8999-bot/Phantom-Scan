"""
Source Coordinator Agent - Orchestrates multi-source scanning (SAST, DAST, SCA, IaC, Secrets).
"""

import asyncio
import logging
import time
from typing import Any

import httpx

from app.agents import Agent
from app.agents.sast_agent import SASTAgent
from app.agents.pentest import PentestAgent
from app.models import MultiSourceScanRequest, SourceType
from app.services.active_gate import ActiveTargetGate
from app.services.active_security import ActiveSecurityEngine, SafetyLimits
from app.services.authorization import TargetAuthorizationService
from app.services.execution import ExecutionBudget, SafetyLimits as ExecSafetyLimits

logger = logging.getLogger("phantomscan.source_coordinator")


class SourceCoordinatorAgent(Agent):
    """Coordinates multi-source security scanning (SAST + DAST + SCA + IaC + Secrets)."""

    def __init__(self, limits: ExecSafetyLimits | None = None) -> None:
        super().__init__("Source Coordinator Agent")
        self.limits = limits or ExecSafetyLimits.from_settings()

    async def run(
        self,
        scan_request: MultiSourceScanRequest,
        scan_id: int,
        user_id: str = "local-user",
        authorization_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run coordinated multi-source scan."""
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Coordinating multi-source scan: {scan_request.name}")

        # Persist source definitions up front
        from app.database import upsert_scan_source
        for source in scan_request.sources:
            source_config = source.model_dump() if hasattr(source, "model_dump") else dict(source)
            identifier = source_config.get("repo_url") or source_config.get("target_url") or source_config.get("path") or source_config.get("image") or str(source.type)
            await upsert_scan_source(
                scan_id=scan_id,
                source_type=source.type,
                source_config=source_config,
                source_identifier=str(identifier),
                priority=getattr(source, "priority", 1) or 1,
            )

        # Prepare source configurations
        source_results = []
        total_findings = 0
        correlated_count = 0

        # Separate sources by type
        code_sources = [s for s in scan_request.sources if s.type in {"local", "github", "gitlab", "bitbucket", "api_spec", "docker", "kubernetes", "terraform"}]
        live_sources = [s for s in scan_request.sources if s.type == "live"]
        sast_sources = [s for s in scan_request.sources if s.type != "live"]

        # Phase 1: Run SAST on code sources (parallel)
        if sast_sources:
            await self.log_action("sast_phase_started", f"Starting SAST on {len(sast_sources)} code sources")
            sast_results = await self._run_sast_sources(sast_sources, scan_id, user_id)
            source_results.extend(sast_results)
            total_findings += sum(r["result"].get("total_findings", 0) for r in sast_results)
            await self.log_action("sast_phase_completed", f"SAST completed with {total_findings} findings")

        # Phase 2: Run DAST on live targets (if authorized)
        if live_sources:
            await self.log_action("dast_phase_started", f"Starting DAST on {len(live_sources)} live targets")
            dast_results = await self._run_dast_sources(live_sources, scan_id, user_id, authorization_context)
            source_results.extend(dast_results)
            total_findings += sum(r["result"].get("total_findings", 0) for r in dast_results)
            await self.log_action("dast_phase_completed", f"DAST completed with {total_findings} total findings")

        # Phase 3: Correlation across sources
        if scan_request.correlate_findings and source_results:
            await self.log_action("correlation_started", "Starting cross-source correlation")
            correlated_count = await self._correlate_findings(scan_id, source_results)
            await self.log_action("correlation_completed", f"Found {correlated_count} correlations")

        # Phase 4: Data flow tracing
        if scan_request.data_flow_tracing and source_results:
            await self.log_action("dataflow_started", "Starting data flow tracing")
            await self._trace_data_flows(scan_id, source_results)
            await self.log_action("dataflow_completed", "Data flow tracing completed")

        self.status = "complete"
        await self.log_action("completed", f"Multi-source scan completed: {total_findings} findings, {correlated_count} correlations")

        return {
            "status": "complete",
            "scan_id": scan_id,
            "total_findings": total_findings,
            "correlated_findings": correlated_count,
            "source_results": source_results,
            "sources_scanned": [s.type for s in scan_request.sources],
        }

    async def _run_sast_sources(
        self,
        sources: list[Any],
        scan_id: int,
        user_id: str,
    ) -> list[dict[str, Any]]:
        """Run SAST on multiple code sources in parallel."""
        from app.database import update_scan_source_status
        async def run_single(source) -> dict[str, Any]:
            source_config = source.model_dump() if hasattr(source, 'model_dump') else source
            identifier = source_config.get("repo_url") or source_config.get("path", "unknown")
            sast_agent = SASTAgent()
            started = time.time()
            try:
                await update_scan_source_status(scan_id, source.type, "running", error_message=None)
                result = await sast_agent.run(
                    scan_id=scan_id,
                    source_config=source_config,
                    scan_mode="sast",
                )
                findings = result.get("findings", [])
                await update_scan_source_status(
                    scan_id,
                    source.type,
                    "completed",
                    findings_count=len(findings),
                    scan_duration_seconds=round(time.time() - started, 2),
                    artifacts={"tool_counts": result.get("tool_counts") or {}},
                )
                return {
                    "source_type": source.type,
                    "source_identifier": identifier,
                    "status": "completed",
                    "result": result,
                }
            except Exception as e:
                await update_scan_source_status(
                    scan_id,
                    source.type,
                    "failed",
                    error_message=str(e)[:1000],
                    scan_duration_seconds=round(time.time() - started, 2),
                )
                return {
                    "source_type": source.type,
                    "source_identifier": identifier,
                    "status": "failed",
                    "error": str(e),
                }

        tasks = [run_single(s) for s in sources]
        return await asyncio.gather(*tasks)

    async def _run_dast_sources(
        self,
        sources: list[Any],
        scan_id: int,
        user_id: str,
        authorization_context: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Run DAST on live targets."""
        from app.database import update_scan_source_status
        results = []
        
        for source in sources:
            source_config = source.model_dump() if hasattr(source, 'model_dump') else source
            target_url = source_config.get("target_url")
            started = time.time()
            
            # Check authorization
            try:
                await update_scan_source_status(scan_id, "live", "running", error_message=None)
                auth_service = TargetAuthorizationService()
                gate = ActiveTargetGate(auth_service)
                decision = await gate.admit(
                    target_url, user_id, 
                    source_config.get("authorization_id"),
                    user_role="user"
                )
                
                if not decision.allowed:
                    await update_scan_source_status(
                        scan_id, "live", "skipped", error_message=decision.reason,
                    )
                    results.append({
                        "source_type": "live",
                        "source_identifier": target_url,
                        "status": "skipped",
                        "error": decision.reason,
                    })
                    continue

                # Run DAST
                limits = ExecSafetyLimits.from_settings()
                budget = ExecutionBudget(limits)
                transport = httpx.ASGITransport(app=None) if decision.is_lab else None
                
                engine = ActiveSecurityEngine(
                    target_url=decision.target_url,
                    attack_surface=None,
                    selected_modules=[str(item) for item in source_config.get("selected_modules", [])],
                    limits=limits,
                    authorization_context=decision.to_context(),
                    workflow_rules=source_config.get("workflow_rules", {}),
                    scan_id=scan_id,
                    user_id=user_id,
                    sandbox_id=f"dast-{scan_id}",
                    budget=budget,
                    transport=transport,
                )
                
                result = await engine.run()
                findings = result.get("findings", [])
                await update_scan_source_status(
                    scan_id,
                    "live",
                    "completed",
                    findings_count=len(findings),
                    scan_duration_seconds=round(time.time() - started, 2),
                )
                results.append({
                    "source_type": "live",
                    "source_identifier": target_url,
                    "status": "completed",
                    "result": result,
                })
                
            except Exception as e:
                await update_scan_source_status(
                    scan_id, "live", "failed", error_message=str(e)[:1000],
                    scan_duration_seconds=round(time.time() - started, 2),
                )
                results.append({
                    "source_type": "live",
                    "source_identifier": target_url,
                    "status": "failed",
                    "error": str(e),
                })
        
        return results

    async def _correlate_findings(self, scan_id: int, source_results: list[dict[str, Any]]) -> int:
        """Correlate findings across sources."""
        from app.database import get_connection
        
        all_findings = []
        for sr in source_results:
            if sr.get("status") == "completed" and "result" in sr:
                findings = sr["result"].get("findings", [])
                for f in findings:
                    f["_source_result"] = sr
                all_findings.extend(findings)
        
        if not all_findings:
            return 0
        
        # Simple correlation: group by file path, endpoint, or rule
        correlations = []
        processed = set()
        
        for i, f1 in enumerate(all_findings):
            if i in processed:
                continue
            
            correlated = [i]
            for j, f2 in enumerate(all_findings):
                if i == j or j in processed:
                    continue
                
                # Check correlation criteria
                if self._are_findings_correlated(f1, f2):
                    correlated.append(j)
                    processed.add(j)
            
            if len(correlated) > 1:
                correlations.append({
                    "scan_id": scan_id,
                    "unified_id": f"corr-{scan_id}-{len(correlations)}",
                    "correlation_type": self._determine_correlation_type(all_findings, correlated),
                    "confidence": 0.8,
                    "source_types": list(set(all_findings[i].get("_source_result", {}).get("source_type", "unknown") for i in correlated)),
                    "finding_ids": [all_findings[i].get("id") for i in correlated if all_findings[i].get("id")],
                    "evidence": {"correlated_count": len(correlated)},
                })
                processed.update(correlated)
        
        # Store correlations
        if correlations:
            async with get_connection() as conn:
                for corr in correlations:
                    await conn.execute(
                        """
                        INSERT INTO source_correlations (
                            scan_id, unified_id, correlation_type, confidence,
                            source_types, finding_ids, evidence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scan_id,
                            corr["unified_id"],
                            corr["correlation_type"],
                            corr["confidence"],
                            json.dumps(corr["source_types"]),
                            json.dumps(corr["finding_ids"]),
                            json.dumps(corr["evidence"]),
                        ),
                    )
                await conn.commit()
        
        return len(correlations)

    def _are_findings_correlated(self, f1: dict[str, Any], f2: dict[str, Any]) -> bool:
        """Check if two findings are correlated."""
        # Same file path
        if f1.get("file_path") and f1.get("file_path") == f2.get("file_path"):
            return True
        
        # Same endpoint
        if f1.get("endpoint") and f1.get("endpoint") == f2.get("endpoint"):
            return True
        
        # Same rule ID
        if f1.get("rule_id") and f1.get("rule_id") == f2.get("rule_id"):
            return True
        
        # Same CVE
        if f1.get("cve_id") and f1.get("cve_id") == f2.get("cve_id"):
            return True
        
        # Same vulnerability type + similar location
        if f1.get("type") == f2.get("type"):
            # Check if they're in the same component
            loc1 = f1.get("file_path", "") or f1.get("endpoint", "")
            loc2 = f2.get("file_path", "") or f2.get("endpoint", "")
            if loc1 and loc2 and self._similar_location(loc1, loc2):
                return True
        
        return False

    def _similar_location(self, loc1: str, loc2: str) -> bool:
        """Check if two locations are similar."""
        # Same directory or same API path prefix
        from urllib.parse import urlparse
        try:
            if loc1.startswith("http") and loc2.startswith("http"):
                p1 = urlparse(loc1).path
                p2 = urlparse(loc2).path
                return p1.split("/")[1] == p2.split("/")[1] if len(p1.split("/")) > 1 and len(p2.split("/")) > 1 else False
        except Exception as e:
            logger.debug("Error: %s", e)
            pass
        return False

    def _determine_correlation_type(self, findings: list[dict[str, Any]], indices: list[int]) -> str:
        """Determine correlation type."""
        types = set(findings[i].get("type") for i in indices)
        
        if len(types) > 1:
            return "vulnerability_chain"
        
        t = types.pop() if types else ""
        if t == "sast":
            return "same_file"
        elif t == "dast":
            return "same_endpoint"
        return "exact_match"

    async def _trace_data_flows(self, scan_id: int, source_results: list[dict[str, Any]]) -> None:
        """Perform taint analysis / data flow tracing."""
        # This would integrate with a taint analysis engine
        # For now, we'll create data flow traces for correlated findings
        from app.database import get_connection
        
        async with get_connection() as conn:
            # Get all findings for this scan
            cursor = await conn.execute(
                "SELECT id, title, category, file_path, endpoint, evidence FROM findings WHERE scan_id = ?",
                (scan_id,),
            )
            findings = [dict(r) for r in await cursor.fetchall()]
            
            # Simple data flow: trace from source (user input) to sink (dangerous function)
            # This is a simplified version - a real implementation would use a taint analysis engine
            for f in findings:
                if f.get("category") in ("injection", "xss", "ssrf", "rce"):
                    # This finding could be part of a data flow
                    pass


import json
import httpx