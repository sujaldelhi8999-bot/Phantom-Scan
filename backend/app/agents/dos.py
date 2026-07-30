import asyncio
import logging
import uuid
from datetime import datetime

import httpx

from app.database import get_connection

logger = logging.getLogger("phantomscan.dos")


INTENSITY_CONFIG = {
    "low": {"rps": 2, "max_duration": 300},
    "medium": {"rps": 10, "max_duration": 120},
    "high": {"rps": 50, "max_duration": 30},
    "critical": {"rps": 100, "max_duration": 10},
}


class DoSAgent:
    def __init__(self, target_url: str, intensity: str = "low", duration: int = 60):
        self.target_url = target_url
        self.intensity = intensity
        self.duration = duration
        self.job_id: str | None = None
        self.running = False

        config = INTENSITY_CONFIG.get(intensity, INTENSITY_CONFIG["low"])
        self.rps = config["rps"]
        max_duration = config["max_duration"]
        if self.duration > max_duration:
            self.duration = max_duration

        self.stats = {
            "requests_sent": 0,
            "responses_received": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
        }

    async def start(self) -> dict:
        self.running = True
        self.stats["start_time"] = datetime.utcnow().isoformat()
        self.job_id = uuid.uuid4().hex[:8]

        await self._create_job()
        asyncio.create_task(self._attack_loop())

        return {
            "job_id": self.job_id,
            "status": "started",
            "target": self.target_url,
            "intensity": self.intensity,
            "rps": self.rps,
            "duration": self.duration,
            "message": f"DoS attack started on {self.target_url} at {self.rps} req/s",
        }

    async def stop(self) -> dict:
        self.running = False
        self.stats["end_time"] = datetime.utcnow().isoformat()
        await self._update_job("stopped")
        return {"job_id": self.job_id, "status": "stopped", "stats": self.stats}

    async def get_status(self) -> dict:
        return {
            "job_id": self.job_id,
            "running": self.running,
            "target": self.target_url,
            "intensity": self.intensity,
            "rps": self.rps,
            "stats": self.stats,
            "duration_elapsed": self._get_elapsed_seconds(),
        }

    async def _attack_loop(self):
        import time as time_mod

        start = time_mod.monotonic()
        deadline = start + self.duration
        window = 0.1
        batch = max(1, int(self.rps * window))

        while self.running and time_mod.monotonic() < deadline:
            if not self.running:
                break

            tasks = []
            for _ in range(batch):
                if not self.running:
                    break
                tasks.append(self._send_request())

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            next_slot = start + (self.stats["requests_sent"] / self.rps)
            now = time_mod.monotonic()
            if next_slot > now:
                await asyncio.sleep(next_slot - now)

        self.running = False
        self.stats["end_time"] = datetime.utcnow().isoformat()
        await self._update_job("completed")

    async def _send_request(self):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    self.target_url,
                    headers={
                        "User-Agent": "PhantomScan-DoS-Test",
                        "Cache-Control": "no-cache",
                    },
                    follow_redirects=False,
                )
                self.stats["responses_received"] += 1
                self.stats["requests_sent"] += 1

                if response.status_code in (500, 502, 503, 504):
                    logger.info("[DoSAgent] Server error: %s on %s", response.status_code, self.target_url)

        except httpx.TimeoutException:
            self.stats["errors"] += 1
            self.stats["requests_sent"] += 1
        except httpx.ConnectError:
            self.stats["errors"] += 1
            self.stats["requests_sent"] += 1
        except Exception:
            self.stats["errors"] += 1
            self.stats["requests_sent"] += 1

        if self.stats["requests_sent"] % 10 == 0:
            await self._update_stats()

    async def _create_job(self):
        async with get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO dos_jobs (job_id, target_url, intensity, duration, status)
                VALUES (?, ?, ?, ?, 'running')
                """,
                (self.job_id, self.target_url, self.intensity, self.duration),
            )
            await conn.commit()

    async def _update_job(self, status: str):
        async with get_connection() as conn:
            await conn.execute(
                """
                UPDATE dos_jobs
                SET status = ?, stopped_at = CURRENT_TIMESTAMP,
                    requests_sent = ?, responses_received = ?, errors = ?
                WHERE job_id = ?
                """,
                (status, self.stats["requests_sent"], self.stats["responses_received"], self.stats["errors"], self.job_id),
            )
            await conn.commit()

    async def _update_stats(self):
        async with get_connection() as conn:
            await conn.execute(
                """
                UPDATE dos_jobs
                SET requests_sent = ?, responses_received = ?, errors = ?
                WHERE job_id = ?
                """,
                (self.stats["requests_sent"], self.stats["responses_received"], self.stats["errors"], self.job_id),
            )
            await conn.commit()

    def _get_elapsed_seconds(self) -> int:
        if self.stats["start_time"]:
            start = datetime.fromisoformat(self.stats["start_time"])
            return int((datetime.utcnow() - start).total_seconds())
        return 0
