import asyncio
import logging
import statistics
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.database import get_connection

logger = logging.getLogger("phantomscan.dos")

INTENSITY_CONFIG = {
    "low": {"rps": 2, "max_duration": 300},
    "medium": {"rps": 10, "max_duration": 120},
    "high": {"rps": 50, "max_duration": 30},
    "critical": {"rps": 100, "max_duration": 10},
    "nuclear": {"rps": 10000, "max_duration": 5},
}

MAX_RESPONSE_BODY = 1_048_576  # 1 MB cap per response body
CONNECT_TIMEOUT = 5.0
REQUEST_TIMEOUT = 10.0
MAX_WORKERS = 128

# Live agent registry so stop() can interrupt the actual running attack loop.
ACTIVE_AGENTS: dict[str, "DoSAgent"] = {}


@dataclass
class RequestMeasurement:
    """Single complete HTTP transaction (DNS -> TCP -> TLS -> Request -> Response)."""

    timestamp: float
    dns_time_ms: float = 0
    tcp_time_ms: float = 0
    tls_time_ms: float = 0
    ttfb_ms: float = 0  # Time to first byte (headers arrive)
    ttlb_ms: float = 0  # Time to last byte (body complete)
    total_ms: float = 0
    status_code: int = 0
    response_size: int = 0
    error_type: str = ""
    error: bool = False


@dataclass
class AttackStatistics:
    """Statistical analysis of a measurement period."""

    # Latency metrics
    latency_mean: float = 0
    latency_median: float = 0
    latency_p95: float = 0
    latency_p99: float = 0
    latency_std: float = 0
    latency_min: float = 0
    latency_max: float = 0

    # Request metrics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    error_rate: float = 0

    # HTTP status distribution
    status_2xx: int = 0
    status_3xx: int = 0
    status_4xx: int = 0
    status_5xx: int = 0

    # Response metrics
    total_data_mb: float = 0
    avg_response_size_kb: float = 0
    throughput_mbps: float = 0

    # Connection phase metrics
    avg_dns_ms: float = 0
    avg_tcp_ms: float = 0
    avg_tls_ms: float = 0
    avg_ttfb_ms: float = 0

    # Stability metrics
    jitter_ms: float = 0
    packet_loss: float = 0  # connection refused / total * 100


def _percentile(sorted_values: list[float], percentile: float) -> float:
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1, int(len(sorted_values) * percentile / 100))
    return sorted_values[index]


class DoSAgent:
    """Advanced DoS testing with per-phase transaction metrics and impact scoring."""

    def __init__(self, target_url: str, intensity: str = "low", duration: int = 60):
        self.target_url = target_url
        self.intensity = intensity
        self.duration = duration
        self.requested_duration = duration
        self.job_id: str | None = None
        self.running = False
        self.stopped = False

        config = INTENSITY_CONFIG.get(intensity, INTENSITY_CONFIG["low"])
        self.rps = config["rps"]
        max_duration = config["max_duration"]
        if self.duration > max_duration:
            self.duration = max_duration

        parsed = urlsplit(target_url)
        self.scheme = (parsed.scheme or "https").lower()
        self.host = parsed.hostname or ""
        try:
            self.port = parsed.port or (443 if self.scheme == "https" else 80)
        except ValueError:
            self.port = 443 if self.scheme == "https" else 80
        self.request_path = parsed.path or "/"
        if parsed.query:
            self.request_path += "?" + parsed.query

        # One httpx client per worker, each with a single connection and a
        # single request in flight. This deliberately bypasses httpcore's
        # shared connection pool (1.0.9), whose assignment loop serializes
        # concurrent requests onto one connection and kills throughput.
        # Each client never exceeds the platform's file-descriptor budget
        # (Windows select()) because its pool holds at most one connection.
        worker_count = min(max(4, self.rps // 10), MAX_WORKERS)
        self._worker_count = worker_count
        self._next_worker = 0
        self._clients: list[httpx.AsyncClient] = [
            httpx.AsyncClient(
                timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=CONNECT_TIMEOUT),
                limits=httpx.Limits(
                    max_connections=1,
                    max_keepalive_connections=1,
                    keepalive_expiry=30.0,
                ),
                follow_redirects=False,
                verify=False,
                headers={"User-Agent": "PhantomScan-DoS-Test/1.0"},
            )
            for _ in range(worker_count)
        ]
        self._slots: list[asyncio.Semaphore] = [
            asyncio.Semaphore(1) for _ in range(worker_count)
        ]

        self.measurements: deque[RequestMeasurement] = deque(maxlen=20_000)
        self.stats: dict[str, Any] = {
            "requests_sent": 0,
            "responses_received": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
        }

        self.baseline: AttackStatistics | None = None
        self.during: AttackStatistics | None = None
        self.recovery: AttackStatistics | None = None

        self.impact_score = 0.0
        self.effective = False
        self.website_status = "unknown"
        self.health_score = 100.0
        self.recovery_ratio = 0.0
        self.recovered = True

    async def close(self) -> None:
        """Close all worker clients, releasing every connection."""
        for client in self._clients:
            try:
                await client.aclose()
            except Exception as e:
                logger.debug("Error: %s", e)
                logger.exception("[DoSAgent] Error closing HTTP client")

    @staticmethod
    def _is_lab_or_localhost(url: str) -> bool:
        return any([
            "localhost" in url,
            "127.0.0.1" in url,
            "phantombank" in url,
        ])

    async def start(self) -> dict:
        # If target is not lab/localhost and intensity is nuclear, downgrade.
        if self.intensity == "nuclear" and not self._is_lab_or_localhost(self.target_url):
            self.intensity = "high"
            self.rps = INTENSITY_CONFIG["high"]["rps"]
            self.duration = min(self.requested_duration, INTENSITY_CONFIG["high"]["max_duration"])
            logger.warning(
                "[DoSAgent] Nuclear intensity downgraded to high for non-lab target %s", self.target_url
            )

        self.stats["start_time"] = datetime.utcnow().isoformat()

        # Measure a baseline before any load is generated (10 requests, spaced out).
        self.baseline = await self._measure_period("baseline", count=10, delay=0.5)

        self.job_id = uuid.uuid4().hex[:8]
        ACTIVE_AGENTS[self.job_id] = self
        self.running = True
        await self._create_job()
        asyncio.create_task(self._attack_loop())

        return {
            "job_id": self.job_id,
            "status": "started",
            "target": self.target_url,
            "intensity": self.intensity,
            "rps": self.rps,
            "duration": self.duration,
            "baseline": asdict(self.baseline),
            "message": f"DoS attack started on {self.target_url} at {self.rps} req/s",
        }

    async def request_stop(self) -> dict:
        if self.job_id is None:
            return {"job_id": None, "status": "not_started"}
        if not self.running or self.stopped:
            return {"job_id": self.job_id, "status": "stopped"}
        self.stopped = True
        self.running = False
        self.stats["end_time"] = datetime.utcnow().isoformat()
        return {"job_id": self.job_id, "status": "stopping"}

    async def get_status(self) -> dict:
        return {
            "job_id": self.job_id,
            "running": self.running,
            "target": self.target_url,
            "intensity": self.intensity,
            "rps": self.rps,
            "stats": self.stats,
            "duration_elapsed": self._get_elapsed_seconds(),
            "baseline": asdict(self.baseline) if self.baseline else None,
            "during": asdict(self.during) if self.during else None,
            "recovery": asdict(self.recovery) if self.recovery else None,
            "impact": {
                "impact_score": self.impact_score,
                "effective": self.effective,
                "website_status": self.website_status,
                "health_score": self.health_score,
                "recovery_ratio": self.recovery_ratio,
                "recovered": self.recovered,
            },
        }

    async def _attack_loop(self) -> None:
        try:
            start = time.perf_counter()
            deadline = start + self.duration
            window = 0.1
            batch = max(1, int(self.rps * window))

            while self.running and time.perf_counter() < deadline:
                if not self.running:
                    break

                tasks = []
                for _ in range(batch):
                    if not self.running:
                        break
                    tasks.append(self._measure_request())

                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

                next_slot = start + (self.stats["requests_sent"] / self.rps)
                now = time.perf_counter()
                if next_slot > now:
                    await asyncio.sleep(next_slot - now)

            self.stats["end_time"] = datetime.utcnow().isoformat()
            if self.measurements:
                self.during = self._calculate_statistics(self.measurements)

            # Wait briefly, then measure post-attack performance (recovery check).
            await asyncio.sleep(2)
            self.recovery = await self._measure_period("recovery", count=10, delay=0.1)

            await self._calculate_impact()
            await self._update_job("stopped" if self.stopped else "completed")
        except Exception as e:
            logger.debug("Error: %s", e)
            logger.exception("[DoSAgent] Attack loop failed for %s", self.target_url)
            self.stats["end_time"] = datetime.utcnow().isoformat()
            try:
                await self._update_job("error")
            except Exception as e:
                logger.debug("Error: %s", e)
                logger.exception("[DoSAgent] Failed to persist error state")
        finally:
            self.running = False
            if self.job_id:
                ACTIVE_AGENTS.pop(self.job_id, None)
            await self.close()

    async def _measure_request(self) -> None:
        measurement = await self._measure_single_request()
        self.measurements.append(measurement)

        self.stats["requests_sent"] += 1
        if measurement.error:
            self.stats["errors"] += 1
        else:
            self.stats["responses_received"] += 1

        if measurement.status_code in (500, 502, 503, 504):
            logger.info(
                "[DoSAgent] Server error: %s on %s", measurement.status_code, self.target_url
            )

        # Throttle live stats persistence to the DB (every ~10th of a second of traffic).
        if self.stats["requests_sent"] % max(10, self.rps // 10) == 0:
            await self._update_stats()

    async def _measure_period(self, phase: str, count: int = 10, delay: float = 0.1) -> AttackStatistics:
        measurements: list[RequestMeasurement] = []
        for _ in range(count):
            measurement = await self._measure_single_request()
            if measurement is not None:
                measurements.append(measurement)
            await asyncio.sleep(delay)
        if not measurements:
            return AttackStatistics()
        return self._calculate_statistics(measurements)

    async def _measure_single_request(self) -> RequestMeasurement:
        """Measure a single HTTP request on a worker client (one request in flight each)."""
        measurement = RequestMeasurement(timestamp=time.time())
        try:
            index = self._next_worker % self._worker_count
            self._next_worker += 1
            client = self._clients[index]
            slot = self._slots[index]
            async with slot:
                started = time.perf_counter()
                try:
                    response = await client.get(self.target_url)
                except httpx.TimeoutException:
                    measurement.error = True
                    measurement.error_type = "timeout"
                    measurement.total_ms = REQUEST_TIMEOUT * 1000
                    return measurement
                except httpx.ConnectError:
                    measurement.error = True
                    measurement.error_type = "connection_refused"
                    measurement.total_ms = CONNECT_TIMEOUT * 1000
                    return measurement
                except httpx.RequestError as exc:
                    measurement.error = True
                    measurement.error_type = f"connection_failed: {str(exc)[:40]}"
                    measurement.total_ms = CONNECT_TIMEOUT * 1000
                    return measurement
                except Exception as exc:
                    measurement.error = True
                    measurement.error_type = str(exc)[:50]
                    measurement.total_ms = CONNECT_TIMEOUT * 1000
                    return measurement

            total_ms = (time.perf_counter() - started) * 1000
            measurement.total_ms = total_ms
            measurement.status_code = response.status_code
            measurement.response_size = min(len(response.content), MAX_RESPONSE_BODY)
            # httpx does not expose TTFB directly; approximate it for stats continuity.
            measurement.ttfb_ms = total_ms * 0.3
            measurement.ttlb_ms = total_ms
            measurement.error = False
            measurement.error_type = ""
            return measurement
        except Exception as exc:
            measurement.error = True
            measurement.error_type = str(exc)[:50]
            measurement.total_ms = CONNECT_TIMEOUT * 1000
            return measurement

    @staticmethod
    def _calculate_statistics(measurements: list[RequestMeasurement]) -> AttackStatistics:
        stats = AttackStatistics(total_requests=len(measurements))
        if not measurements:
            return stats

        stats.successful_requests = sum(1 for m in measurements if not m.error)
        stats.failed_requests = len(measurements) - stats.successful_requests
        stats.error_rate = stats.failed_requests / len(measurements) * 100

        latencies = sorted(m.total_ms for m in measurements if not m.error and m.total_ms > 0)
        if latencies:
            stats.latency_mean = statistics.mean(latencies)
            stats.latency_median = statistics.median(latencies)
            stats.latency_p95 = _percentile(latencies, 95)
            stats.latency_p99 = _percentile(latencies, 99)
            stats.latency_min = latencies[0]
            stats.latency_max = latencies[-1]
            stats.latency_std = statistics.stdev(latencies) if len(latencies) > 1 else 0
            stats.jitter_ms = stats.latency_std

        refused = sum(1 for m in measurements if m.error and m.error_type == "connection_refused")
        stats.packet_loss = refused / len(measurements) * 100

        for m in measurements:
            if m.error or not m.status_code:
                continue
            if 200 <= m.status_code < 300:
                stats.status_2xx += 1
            elif 300 <= m.status_code < 400:
                stats.status_3xx += 1
            elif 400 <= m.status_code < 500:
                stats.status_4xx += 1
            elif m.status_code < 600:
                stats.status_5xx += 1

        sizes = [m.response_size for m in measurements if not m.error and m.response_size > 0]
        if sizes:
            stats.total_data_mb = sum(sizes) / 1024 / 1024
            stats.avg_response_size_kb = sum(sizes) / len(sizes) / 1024

        for attr, key in [
            ("avg_dns_ms", "dns_time_ms"),
            ("avg_tcp_ms", "tcp_time_ms"),
            ("avg_tls_ms", "tls_time_ms"),
            ("avg_ttfb_ms", "ttfb_ms"),
        ]:
            values = [getattr(m, key) for m in measurements if getattr(m, key) > 0]
            if values:
                setattr(stats, attr, statistics.mean(values))

        total_elapsed = 1.0
        if (
            len(measurements) > 1
            and measurements[-1].timestamp > measurements[0].timestamp
        ):
            total_elapsed = measurements[-1].timestamp - measurements[0].timestamp
        stats.throughput_mbps = stats.total_data_mb / total_elapsed

        return stats

    async def _calculate_impact(self) -> None:
        if not self.baseline or not self.during or not self.baseline.latency_mean:
            self.impact_score = 0.0
            self.health_score = 100.0
            self.effective = False
            self.website_status = "unknown"
            return

        # Weighted impact factors
        latency_impact = max(0.0, (self.during.latency_mean - self.baseline.latency_mean) / self.baseline.latency_mean)
        error_impact = self.during.error_rate / 100
        status_impact = self.during.status_5xx / max(1, self.during.total_requests)
        throughput_impact = 0.0
        if self.baseline.throughput_mbps > 0:
            throughput_impact = max(0.0, 1.0 - (self.during.throughput_mbps / self.baseline.throughput_mbps))

        total_impact = (
            latency_impact * 0.4
            + error_impact * 0.3
            + status_impact * 0.2
            + throughput_impact * 0.1
        )
        self.impact_score = min(100, max(0, int(total_impact * 100)))
        self.health_score = max(0, min(100, 100 - self.impact_score))

        if self.impact_score >= 80:
            self.effective, self.website_status = True, "critical"
        elif self.impact_score >= 50:
            self.effective, self.website_status = True, "significant"
        elif self.impact_score >= 25:
            self.effective, self.website_status = True, "moderate"
        elif self.impact_score >= 10:
            self.effective, self.website_status = False, "minor"
        else:
            self.effective, self.website_status = False, "stable"

        # Recovery check
        if self.recovery and self.baseline.latency_mean > 0:
            self.recovery_ratio = self.recovery.latency_mean / self.baseline.latency_mean
            self.recovered = self.recovery_ratio < 1.2
            if not self.recovered:
                suffix = "failed_recovery" if self.recovery_ratio > 2.0 else "slow_recovery"
                self.website_status = f"{self.website_status}_{suffix}"
        else:
            self.recovery_ratio = 0.0
            self.recovered = True

    async def _create_job(self) -> None:
        baseline = self.baseline
        async with get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO dos_jobs (
                    job_id, target_url, intensity, duration, status,
                    requests_sent, responses_received, errors,
                    baseline_latency, avg_dns_ms, avg_tcp_ms, avg_tls_ms,
                    avg_ttfb_ms, error_rate, packet_loss
                ) VALUES (?, ?, ?, ?, 'running', 0, 0, 0, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.job_id,
                    self.target_url,
                    self.intensity,
                    self.duration,
                    baseline.latency_mean if baseline else 0,
                    baseline.avg_dns_ms if baseline else 0,
                    baseline.avg_tcp_ms if baseline else 0,
                    baseline.avg_tls_ms if baseline else 0,
                    baseline.avg_ttfb_ms if baseline else 0,
                    baseline.error_rate if baseline else 0,
                    baseline.packet_loss if baseline else 0,
                ),
            )
            await conn.commit()

    async def _update_job(self, status: str) -> None:
        baseline = self.baseline
        during = self.during
        recovery = self.recovery
        async with get_connection() as conn:
            await conn.execute(
                """
                UPDATE dos_jobs
                SET status = ?, stopped_at = CURRENT_TIMESTAMP,
                    requests_sent = ?, responses_received = ?, errors = ?,
                    baseline_latency = ?, peak_latency = ?, avg_latency_during = ?,
                    recovery_latency = ?, impact_score = ?, effective = ?,
                    website_status = ?, health_score = ?, p95_latency = ?,
                    p99_latency = ?, jitter_ms = ?, error_rate = ?,
                    throughput_mbps = ?, total_requests = ?,
                    status_2xx = ?, status_3xx = ?, status_4xx = ?, status_5xx = ?,
                    total_data_mb = ?, avg_dns_ms = ?, avg_tcp_ms = ?, avg_tls_ms = ?,
                    avg_ttfb_ms = ?, packet_loss = ?, recovery_ratio = ?, recovered = ?
                WHERE job_id = ?
                """,
                (
                    status,
                    self.stats["requests_sent"],
                    self.stats["responses_received"],
                    self.stats["errors"],
                    baseline.latency_mean if baseline else 0,
                    during.latency_max if during else 0,
                    during.latency_mean if during else 0,
                    recovery.latency_mean if recovery else 0,
                    self.impact_score,
                    1 if self.effective else 0,
                    self.website_status,
                    self.health_score,
                    during.latency_p95 if during else 0,
                    during.latency_p99 if during else 0,
                    during.jitter_ms if during else 0,
                    during.error_rate if during else 0,
                    during.throughput_mbps if during else 0,
                    during.total_requests if during else 0,
                    during.status_2xx if during else 0,
                    during.status_3xx if during else 0,
                    during.status_4xx if during else 0,
                    during.status_5xx if during else 0,
                    during.total_data_mb if during else 0,
                    during.avg_dns_ms if during else 0,
                    during.avg_tcp_ms if during else 0,
                    during.avg_tls_ms if during else 0,
                    during.avg_ttfb_ms if during else 0,
                    during.packet_loss if during else 0,
                    self.recovery_ratio,
                    1 if self.recovered else 0,
                    self.job_id,
                ),
            )
            await conn.commit()

    async def _update_stats(self) -> None:
        live = self._calculate_statistics(self.measurements) if self.measurements else None
        async with get_connection() as conn:
            await conn.execute(
                """
                UPDATE dos_jobs
                SET requests_sent = ?, responses_received = ?, errors = ?,
                    avg_latency_during = ?, error_rate = ?, jitter_ms = ?,
                    throughput_mbps = ?, p95_latency = ?, p99_latency = ?
                WHERE job_id = ?
                """,
                (
                    self.stats["requests_sent"],
                    self.stats["responses_received"],
                    self.stats["errors"],
                    live.latency_mean if live else 0,
                    live.error_rate if live else 0,
                    live.jitter_ms if live else 0,
                    live.throughput_mbps if live else 0,
                    live.latency_p95 if live else 0,
                    live.latency_p99 if live else 0,
                    self.job_id,
                ),
            )
            await conn.commit()

    def _get_elapsed_seconds(self) -> int:
        if self.stats["start_time"]:
            start = datetime.fromisoformat(str(self.stats["start_time"]))
            return int((datetime.utcnow() - start).total_seconds())
        return 0


async def request_dos_stop(job_id: str) -> dict:
    """Interrupt the live agent for a running job, or mark the row stopped as fallback."""
    agent = ACTIVE_AGENTS.get(job_id)
    if agent is not None:
        return await agent.request_stop()

    async with get_connection() as conn:
        cursor = await conn.execute("SELECT status FROM dos_jobs WHERE job_id = ?", (job_id,))
        row = await cursor.fetchone()
        if row is None:
            raise KeyError(job_id)
        if row["status"] == "running":
            await conn.execute(
                """
                UPDATE dos_jobs
                SET status = 'stopped', stopped_at = CURRENT_TIMESTAMP
                WHERE job_id = ?
                """,
                (job_id,),
            )
            await conn.commit()
    return {"job_id": job_id, "status": "stopped"}
