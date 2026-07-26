import os
import tempfile
from datetime import datetime, timezone
from unittest import IsolatedAsyncioTestCase, TestCase

_db_fd, _db_path = tempfile.mkstemp(suffix=".sqlite3")
os.close(_db_fd)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")
os.environ.setdefault("MAX_TOTAL_REQUESTS", "50")
os.environ.setdefault("MAX_REQUESTS_PER_SECOND", "100")

import httpx
from fastapi.testclient import TestClient

from app.config import get_settings

get_settings.cache_clear()

from app.database import (
    create_authorized_target,
    create_finding,
    create_scan,
    get_finding,
    get_findings,
    get_scan_artifacts,
    initialize_database,
    set_scan_artifacts,
    update_authorized_target,
)
from app.lab import set_scenario_state
from app.models import FindingCreate
from app.services.active_gate import ActiveTargetGate
from app.services.active_security import ActiveSecurityEngine, SecurityTestPlanner
from app.services.authorization import TargetAuthorizationService
from app.services.execution import SafetyLimits
from app.services.jobs import ScanJobManager
from main import app


def limits(max_total_requests: int = 50) -> SafetyLimits:
    return SafetyLimits(
        max_scan_duration=10,
        max_requests_per_second=100,
        max_total_requests=max_total_requests,
        max_concurrent_scans=2,
        max_redirect_depth=0,
        max_response_size=200_000,
    )


async def make_scan(target_url: str = "http://localhost/lab/phantombank") -> int:
    await initialize_database()
    return await create_scan(
        target_url=target_url,
        mode="pentest",
        intensity="low",
        selected_tests='["xss"]',
        user_id="local-user",
        authorization_confirmed=False,
    )


class ActiveGateAndPlannerTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_scenario_state("VULNERABLE")

    async def test_lab_target_allowed(self) -> None:
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit("http://localhost/lab/phantombank", "local-user")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.authorization_status, "TRAINING")

    async def test_localhost_allowed(self) -> None:
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit("http://127.0.0.1:8000/demo", "local-user")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.authorization_status, "ALLOWLIST")

    async def test_external_unverified_blocked(self) -> None:
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit("https://example.com", "local-user")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.authorization_status, "BLOCKED")

    async def test_verified_target_accepted(self) -> None:
        authorization_id = await create_authorized_target(
            "local-user",
            "owned.example",
            "https://owned.example",
            "http",
            "demo-hash",
            "2099-01-01T00:00:00+00:00",
        )
        await update_authorized_target(
            authorization_id,
            "VERIFIED",
            "2026-01-01T00:00:00+00:00",
            "2099-01-01T00:00:00+00:00",
        )
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit(
            "https://owned.example/app",
            "local-user",
            authorization_id,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.authorization_status, "VERIFIED")

    async def test_planner_chooses_relevant_modules(self) -> None:
        attack_surface = {
            "surfaces": [
                {"id": "search", "module_hints": ["xss", "input_security"], "path": "/search", "parameters": ["q"]},
                {"id": "admin", "module_hints": ["access_control"], "path": "/admin", "parameters": []},
            ]
        }
        plan = SecurityTestPlanner().create_plan(attack_surface, ["xss", "graphql", "access_control"])
        self.assertEqual([item["module"] for item in plan["modules"]], ["xss", "access_control"])


class ActiveEngineTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_scenario_state("VULNERABLE")

    async def run_engine(self, selected_modules: list[str], max_total_requests: int = 50) -> dict:
        scan_id = await make_scan()
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit("http://localhost/lab/phantombank", "local-user")
        engine = ActiveSecurityEngine(
            target_url=decision.target_url,
            attack_surface=None,
            selected_modules=selected_modules,
            limits=limits(max_total_requests),
            authorization_context=decision.to_context(),
            workflow_rules={},
            scan_id=scan_id,
            user_id="local-user",
            sandbox_id="test-sandbox",
            transport=httpx.ASGITransport(app=app),
        )
        return await engine.run()

    async def test_request_limit_enforced(self) -> None:
        result = await self.run_engine(["xss"], max_total_requests=1)
        self.assertEqual(result["status"], "limited")
        self.assertEqual(result["request_count"], 1)

    async def test_timeout_enforced(self) -> None:
        scan_id = await make_scan()
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit("http://localhost/lab/phantombank", "local-user")
        engine = ActiveSecurityEngine(
            target_url=decision.target_url,
            attack_surface=None,
            selected_modules=["xss"],
            limits=SafetyLimits(
                max_scan_duration=0,
                max_requests_per_second=100,
                max_total_requests=50,
                max_concurrent_scans=2,
                max_redirect_depth=0,
                max_response_size=200_000,
            ),
            authorization_context=decision.to_context(),
            workflow_rules={},
            scan_id=scan_id,
            user_id="local-user",
            sandbox_id="timeout-test",
            transport=httpx.ASGITransport(app=app),
        )
        result = await engine.run()
        self.assertEqual(result["status"], "limited")

    async def test_lab_vulnerable_produces_finding(self) -> None:
        result = await self.run_engine(["xss", "access_control", "business_logic"])
        modules = {finding.get("module") for finding in result["findings"]}
        self.assertIn("xss", modules)
        self.assertIn("access_control", modules)
        self.assertIn("business_logic", modules)

    async def test_confidence_and_remediation_are_calculated_from_evidence(self) -> None:
        result = await self.run_engine(["xss"])
        finding = next(item for item in result["findings"] if item.get("module") == "xss")
        self.assertEqual(finding["confidence"], "HIGH")
        self.assertTrue(finding.get("recommended_fix"))
        self.assertTrue(finding.get("verification"))
        self.assertLess(result["score"]["score"], 100)

    async def test_patched_scenario_passes_selected_checks(self) -> None:
        set_scenario_state("PATCHED")
        result = await self.run_engine(
            [
                "input_security",
                "injection",
                "xss",
                "auth_session",
                "access_control",
                "csrf",
                "file_upload",
                "path_handling",
                "api_security",
                "graphql",
                "websocket",
                "jwt",
                "redirect",
                "cors",
                "security_headers",
                "tls_https",
                "sensitive_exposure",
                "business_logic",
            ]
        )
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["findings"], [])

    async def test_finding_saved_shape(self) -> None:
        scan_id = await make_scan()
        finding_id = await create_finding(
            scan_id,
            FindingCreate(
                title="Output encoding demo",
                category="Output Encoding",
                severity="MEDIUM",
                confidence="HIGH",
                target="http://localhost/lab/phantombank",
                endpoint="http://localhost/lab/phantombank/search",
                evidence="safe evidence",
                impact="impact",
                recommendation="fix it",
                verification="rerun",
                agent="Active Security Engine",
                timestamp=datetime.now(timezone.utc),
                parameter="q",
                module="xss",
                recommended_fix="Encode output",
            ),
        )
        saved = await get_finding(finding_id)
        self.assertIsNotNone(saved)
        self.assertEqual(saved["module"], "xss")
        self.assertEqual(saved["parameter"], "q")
        self.assertEqual(saved["recommended_fix"], "Encode output")
        self.assertEqual(saved["verification_status"], "NOT_VERIFIED")

    async def test_active_security_artifact_saved(self) -> None:
        scan_id = await make_scan()
        await set_scan_artifacts(
            scan_id,
            active_security_output={
                "test_plan": {"modules": [{"module": "xss", "surfaces": []}]},
                "events": [{"event": "test_started"}],
                "evidence": [],
                "findings": [],
                "score": {"score": 100},
            },
        )
        artifacts = await get_scan_artifacts(scan_id)
        self.assertIsNotNone(artifacts)
        self.assertEqual(artifacts["active_security_output"]["score"]["score"], 100)

    async def test_job_manager_stop_cancels_queued_scan(self) -> None:
        scan_id = await make_scan("http://localhost/queued")
        manager = ScanJobManager(limits())
        status = await manager.stop(scan_id)
        self.assertEqual(status, "cancelled")


class FindingVerificationApiTests(TestCase):
    def test_active_map_route_returns_lab_plan_and_limits(self) -> None:
        with TestClient(app, base_url="http://localhost") as client:
            response = client.post(
                "/api/active/map",
                json={"target_url": "http://localhost/lab/phantombank", "selected_modules": ["xss"]},
            )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["gate"]["authorization_status"], "TRAINING")
        self.assertGreaterEqual(len(payload["surfaces"]), 1)
        self.assertEqual(payload["plan"]["modules"][0]["module"], "xss")
        self.assertIn("max_requests", payload["limits"])

    def test_websocket_snapshot_emitted(self) -> None:
        async def setup() -> int:
            return await make_scan("http://localhost/lab/phantombank")

        import asyncio

        scan_id = asyncio.run(setup())
        with TestClient(app, base_url="http://localhost") as client:
            with client.websocket_connect(f"/ws/scan/{scan_id}") as websocket:
                message = websocket.receive_json()
        self.assertEqual(message["event"], "snapshot")
        self.assertEqual(message["scan_id"], scan_id)

    def test_fix_verification_api_marks_patched_lab_finding_fixed(self) -> None:
        async def setup() -> int:
            await initialize_database()
            set_scenario_state("VULNERABLE")
            scan_id = await create_scan(
                target_url="http://localhost/lab/phantombank",
                mode="pentest",
                intensity="low",
                selected_tests='["xss"]',
                user_id="local-user",
            )
            return await create_finding(
                scan_id,
                {
                    "title": "HTML-like input marker reflected without encoding",
                    "category": "Output Encoding",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "target": "http://localhost/lab/phantombank",
                    "endpoint": "http://localhost/lab/phantombank/search",
                    "evidence": "safe evidence",
                    "impact": "impact",
                    "recommendation": "fix it",
                    "verification": "rerun",
                    "agent": "Active Security Engine",
                    "timestamp": datetime.now(timezone.utc),
                    "parameter": "q",
                    "module": "xss",
                    "recommended_fix": "Encode output",
                },
            )

        import asyncio

        finding_id = asyncio.run(setup())
        set_scenario_state("PATCHED")
        with TestClient(app, base_url="http://localhost") as client:
            response = client.post(f"/api/findings/{finding_id}/verify")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "FIX_VERIFIED")

        async def load_status() -> str:
            row = await get_finding(finding_id)
            assert row is not None
            return str(row["verification_status"])

        self.assertEqual(asyncio.run(load_status()), "FIX_VERIFIED")
