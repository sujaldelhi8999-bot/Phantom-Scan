"""
SAST Agent - Runs static application security testing using Semgrep and other tools.
"""

import asyncio
import json
import tempfile
import uuid
from pathlib import Path
from typing import Any

import httpx

from app.agents import Agent
from app.config import BASE_DIR
from app.services.execution import SafetyLimits


class SASTAgent(Agent):
    """Runs Static Application Security Testing (SAST) using Semgrep, truffleHog, gitleaks, etc."""

    def __init__(self, limits: SafetyLimits | None = None, memory_limit_mb: int = 512) -> None:
        super().__init__("SAST Agent")
        self.limits = limits or SafetyLimits.from_settings()
        self.memory_limit_bytes = memory_limit_mb * 1024 * 1024
        self.process: asyncio.subprocess.Process | None = None
        self.sandbox_id: str | None = None
        self._memory_exceeded = False

    async def run(
        self,
        scan_id: int,
        source_config: dict[str, Any],
        *,
        target_url: str | None = None,
        scan_mode: str = "sast",
    ) -> dict[str, Any]:
        """Run SAST scan on source code."""
        self.scan_id = scan_id
        self.status = "active"
        self.sandbox_id = f"sast-sandbox-{uuid.uuid4().hex[:12]}"
        await self.log_action("sast_started", f"Starting SAST scan for {source_config.get('type', 'unknown')} source")

        source_type = source_config.get("type", "local")
        target_path = source_config.get("path", "/app")

        with tempfile.TemporaryDirectory(prefix="phantomscan-sast-") as sandbox_directory:
            environment = self.restricted_environment()
            kwargs: dict[str, Any] = {}
            if os.name != "nt":
                import resource
                def apply_limits():
                    resource.setrlimit(resource.RLIMIT_AS, (self.memory_limit_bytes, self.memory_limit_bytes))
                    resource.setrlimit(resource.RLIMIT_CPU, (self.limits.max_scan_duration, self.limits.max_scan_duration + 1))
                    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
                    resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
                kwargs["preexec_fn"] = apply_limits

            # Prepare payload for worker
            payload = {
                "scan_id": scan_id,
                "source_config": source_config,
                "sandbox_id": self.sandbox_id,
                "limits": {
                    "max_scan_duration": self.limits.max_scan_duration,
                    "max_total_requests": self.limits.max_total_requests,
                },
            }

            # Handle GitHub source - clone repo
            if source_config.get("type") == "github":
                repo_url = source_config.get("repo_url")
                branch = source_config.get("branch", "main")
                # In sandbox, we'll clone the repo
                payload["source_config"] = {**source_config, "cloned": True}

            self.process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "app.workers.sast_worker",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=sandbox_directory,
                env=environment,
                **kwargs,
            )
            
            monitor = asyncio.create_task(self.monitor_memory(self.process))
            try:
                stdout, stderr = await asyncio.wait_for(
                    self.process.communicate(json.dumps(payload).encode("utf-8")),
                    timeout=self.limits.max_scan_duration,
                )
            except asyncio.TimeoutError as exc:
                await self.terminate()
                raise RuntimeError("SAST worker exceeded the scan time limit") from exc
            except asyncio.CancelledError:
                await asyncio.shield(self.terminate())
                raise
            finally:
                monitor.cancel()
                await asyncio.gather(monitor, return_exceptions=True)

        if self._memory_exceeded:
            raise RuntimeError("SAST worker exceeded its memory limit")
        if self.process.returncode != 0:
            error_text = stderr.decode("utf-8", errors="replace")[:2000]
            raise RuntimeError(f"SAST worker failed: {error_text or 'unknown worker error'}")
        
        try:
            result = json.loads(stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError("SAST worker returned invalid structured output") from exc
        
        if not isinstance(result, dict) or result.get("status") != "complete":
            raise RuntimeError(str(result.get("error", "SAST worker did not complete")))

        self.status = "complete"
        await self.log_action("sast_completed", f"SAST scan completed with {result['result'].get('total_findings', 0)} findings")
        
        return {
            **result["result"],
            "sandbox_id": self.sandbox_id,
        }

    def restricted_environment(self) -> dict[str, str]:
        import os
        allowed_names = {
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "DATABASE_URL",
            "ACTIVE_TARGET_ALLOWLIST",
            "PYTHONIOENCODING",
            "PYTHONUTF8",
            "GITHUB_TOKEN",
            "GITHUB_CLIENT_ID",
            "GITHUB_CLIENT_SECRET",
        }
        environment = {name: value for name, value in os.environ.items() if name in allowed_names}
        environment.update(
            {
                "PYTHONPATH": str(BASE_DIR),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1",
                "PHANTOMSCAN_SANDBOX": "1",
                "PHANTOMSCAN_SAST": "1",
            }
        )
        return environment

    async def monitor_memory(self, process: asyncio.subprocess.Process) -> None:
        import psutil
        while process.returncode is None:
            try:
                parent = psutil.Process(process.pid)
                rss = parent.memory_info().rss + sum(child.memory_info().rss for child in parent.children(recursive=True))
                if rss > self.memory_limit_bytes:
                    self._memory_exceeded = True
                    await self.terminate()
                    return
            except psutil.Error:
                return
            await asyncio.sleep(0.25)

    async def terminate(self) -> None:
        import psutil
        if self.process is None or self.process.returncode is not None:
            return
        try:
            parent = psutil.Process(self.process.pid)
            children = parent.children(recursive=True)
            for process in children:
                try:
                    process.kill()
                except psutil.Error:
                    continue
            try:
                parent.kill()
            except psutil.Error:
                pass
            await asyncio.to_thread(psutil.wait_procs, [parent, *children], 3)
        except psutil.Error:
            try:
                self.process.kill()
            except ProcessLookupError:
                pass
        try:
            await self.process.wait()
        except ProcessLookupError:
            return