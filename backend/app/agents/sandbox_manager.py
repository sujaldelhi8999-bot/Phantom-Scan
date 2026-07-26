import asyncio
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

import psutil

from app.agents import Agent
from app.config import BASE_DIR
from app.services.execution import SafetyLimits


class SandboxExecutionError(RuntimeError):
    pass


def apply_unix_resource_limits(memory_limit_bytes: int, cpu_seconds: int) -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
    except (ImportError, OSError, ValueError):
        return


class SandboxManagerAgent(Agent):
    def __init__(self, limits: SafetyLimits | None = None, memory_limit_mb: int = 256) -> None:
        super().__init__("Sandbox Manager Agent")
        self.limits = limits or SafetyLimits.from_settings()
        self.memory_limit_bytes = memory_limit_mb * 1024 * 1024
        self.process: asyncio.subprocess.Process | None = None
        self.sandbox_id: str | None = None
        self._memory_exceeded = False

    async def run_active_scan(self, payload: dict[str, Any], scan_id: int) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        self.sandbox_id = f"sandbox-{uuid.uuid4().hex[:12]}"
        payload = {
            **payload,
            "sandbox_id": self.sandbox_id,
            "limits": {
                "max_scan_duration": self.limits.max_scan_duration,
                "max_requests_per_second": self.limits.max_requests_per_second,
                "max_total_requests": self.limits.max_total_requests,
                "max_concurrent_scans": self.limits.max_concurrent_scans,
                "max_redirect_depth": self.limits.max_redirect_depth,
                "max_response_size": self.limits.max_response_size,
            },
        }
        await self.log_action("sandbox_created", self.sandbox_id)

        with tempfile.TemporaryDirectory(prefix="phantomscan-") as sandbox_directory:
            environment = self.restricted_environment()
            kwargs: dict[str, Any] = {}
            if os.name != "nt":
                kwargs["preexec_fn"] = lambda: apply_unix_resource_limits(
                    self.memory_limit_bytes,
                    self.limits.max_scan_duration,
                )
            self.process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "app.workers.active_worker",
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
                raise SandboxExecutionError("Active worker exceeded the scan time limit") from exc
            except asyncio.CancelledError:
                await asyncio.shield(self.terminate())
                raise
            finally:
                monitor.cancel()
                await asyncio.gather(monitor, return_exceptions=True)

        if self._memory_exceeded:
            raise SandboxExecutionError("Active worker exceeded its memory limit")
        if self.process.returncode != 0:
            error_text = stderr.decode("utf-8", errors="replace")[:2000]
            raise SandboxExecutionError(f"Active worker failed: {error_text or 'unknown worker error'}")
        try:
            result = json.loads(stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise SandboxExecutionError("Active worker returned invalid structured output") from exc
        if not isinstance(result, dict) or result.get("status") != "complete":
            raise SandboxExecutionError(str(result.get("error", "Active worker did not complete")))

        self.status = "complete"
        await self.log_action("sandbox_destroyed", self.sandbox_id)
        return {
            **result["result"],
            "sandbox_id": self.sandbox_id,
        }

    def restricted_environment(self) -> dict[str, str]:
        allowed_names = {
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "DATABASE_URL",
            "ACTIVE_TARGET_ALLOWLIST",
            "PYTHONIOENCODING",
            "PYTHONUTF8",
        }
        environment = {name: value for name, value in os.environ.items() if name in allowed_names}
        environment.update(
            {
                "PYTHONPATH": str(BASE_DIR),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1",
                "PHANTOMSCAN_SANDBOX": "1",
            }
        )
        return environment

    async def monitor_memory(self, process: asyncio.subprocess.Process) -> None:
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
