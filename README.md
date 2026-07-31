# 🛡️ PhantomScan

**PhantomScan** is an enterprise-grade, AI-powered security scanning and controlled penetration testing platform. It orchestrates autonomous reconnaissance, deep vulnerability analysis, real-time threat intelligence matching, controlled exploit verification, and AI-driven remediation reporting from a unified operations console.

---

## 🚀 Key Features

* 🤖 **Autonomous Multi-Agent Architecture**: 10+ core specialized security agents working in tandem with 9 targeted assessment sub-agents.
* ⚡ **Real-Time WebSocket Ops Console**: Live scan telemetry, real-time progress streaming, findings timeline, and interactive terminal event logs.
* 🔍 **Passive & Active Reconnaissance**: DNS resolution, port scanning, service banner grabbing, technology fingerprinting, subdomains, WHOIS, `robots.txt`, and `sitemap.xml` parsing.
* 🛡️ **Deep Vulnerability & CVE Intelligence**: Live correlation of detected technologies and library versions with the National Vulnerability Database (NVD API).
* 🧠 **AI Explainer & Localization**: Leverages Claude / OpenRouter LLM to explain exploitation vectors, produce exact code remediation snippets, and generate regional Hindi security reports.
* 🔐 **Target Authorization & Scope Gate**: Strict ownership verification system (via DNS TXT record or file verification token) ensuring scans run only on authorized targets.
* 🧪 **Built-in Vulnerable Security Lab**: Integrated safe sandbox environments to test and validate SQLi, XSS, Header misconfigurations, and BOLA vulnerability detection.
* 💥 **Controlled DoS & Load Stress Testing**: Isolated, rate-bounded simulation panel to measure server resilience under heavy traffic. Supports five intensity levels (Low, Medium, High, Critical, **Nuclear — 10,000 req/s, lab-only**) with auto-downgrade guard for external targets, per-worker connection isolation, and real-time telemetry (RPS, latency percentiles, error rates, impact scoring).
* 🌙 **Automated Nightly Self-Audit**: Scheduled cron job (runs daily at 02:00 UTC) that scans PhantomScan's own deployment and alerts on misconfigurations or vulnerabilities.

---

## 🧩 Autonomous Agent Matrix

| Agent | Responsibility & Functions |
| :--- | :--- |
| **Orchestrator** | Coordinates scan lifecycles, phase progression, progress updates, parallel agent execution, and artifact storage. |
| **Scanner** | Active host discovery, port scanning, HTTP stack fingerprinting, and subdomain enumeration. |
| **Shadow Recon** | Passive OSINT: WHOIS domain metadata, search query footprints, `robots.txt`, and `sitemap.xml` analysis. |
| **Analyzer** | Security header validation (CSP, HSTS, CORS), cookie security flags (`HttpOnly`, `Secure`, `SameSite`), and open redirects. |
| **CVE Matcher** | Correlates discovered tech stacks and versions against the NVD API database to surface known CVE vulnerabilities. |
| **Browser Security** | Client-side security verification using browser-emulated HTTP probes and headful security checks. |
| **Security Assessment Suite** | Modular sub-agents targeting specific vulnerability classes: <br> • **AccessControl**: BOLA / IDOR detection <br> • **ApiSecurity**: REST / GraphQL endpoint fuzzing & spec leaks <br> • **AuthSecurity**: Auth bypass & session handling <br> • **Dependency**: Vulnerable third-party JS/Python libraries <br> • **Infrastructure**: SSL/TLS & server misconfigurations <br> • **InjectionAnalysis**: SQLi, XSS & Command Injection <br> • **SessionSecurity**: Session token entropy & cookie flags <br> • **ThreatIntelligence**: IP reputation & threat feed correlation <br> • **WebSocketSecurity**: WS handshake & frame security |
| **Pentest Engine** | Controlled, authorized proof-of-concept payload execution for SQLi, XSS, CSRF, and access control probes. |
| **AI Explainer** | Generates detailed threat descriptions, impact analysis, and ready-to-apply code patch snippets using LLMs. |
| **Hindi Explainer** | Produces Hindi-language vulnerability summaries and remediation steps for localized security reporting. |
| **Fixer** | Aggregates findings, ranks risk levels (Critical, High, Medium, Low), and compiles prioritized Markdown action plans. |
| **Notifier** | Dispatches instant alerts and scan summaries via webhooks (Slack/Discord/Custom endpoints). |
| **Sandbox Manager** | Enforces process timeouts, memory limits, and subprocess execution safety boundaries. |
| **Self Audit** | Automated cron agent performing internal security regression audits every night at 02:00 UTC. |
| **DoS Agent** | Controlled load generator with five intensity tiers (Low 2 rps, Medium 10 rps, High 50 rps, Critical 100 rps, **Nuclear 10,000 rps**). Uses a per-worker single-connection pool (httpx AsyncClient, `max_connections=1`) to bypass httpcore 1.0.9's connection pool pile-up bug, achieving ~800–1200 rps sustained on lab targets. Includes auto-downgrade guard (nuclear → high for non-lab targets), baseline/recovery measurements, statistical impact scoring, and zero FD leak on stop. |

---

## 📈 DoS Agent — Technical Deep Dive

### Intensity Tiers

| Intensity | Requests/s | Max Duration | Use Case |
| :--- | :--- | :--- | :--- |
| Low | 2 | 300 s | Baseline health checks |
| Medium | 10 | 120 s | Light load profiling |
| High | 50 | 30 s | Stress validation |
| Critical | 100 | 10 s | Spike testing |
| **Nuclear** | **10,000** | **5 s** | **Lab-only saturation test** |

### Architecture

The DoS agent (`backend/app/agents/dos.py`) replaces the shared `httpx.AsyncClient` connection pool (limits: 20 conns / 10 keepalive) with a **worker-per-connection** model:

- Each worker owns one `httpx.AsyncClient(limits=Limits(max_connections=1, max_keepalive_connections=1))`
- A round-robin scheduler assigns each outgoing request to the next available worker's `asyncio.Semaphore(1)`
- This guarantees at most **one request in flight per worker**, eliminating:
  - httpcore 1.0.9's `_assign_requests_to_connections` pile-up (all queued requests assigned to one idle connection)
  - The resulting serialization bottleneck that capped throughput at ~60 rps
- Worker count scales with intensity: `min(max(4, rps // 10), 128)` → Nuclear = 128 workers

### The `sniffio` Discovery

During Nuclear development, throughput plateaued at ~340 rps despite the worker model. Root cause: the optional `sniffio` package was not installed. Both `anyio` and `httpcore` lazily import `sniffio` inside synchronization primitives (`AsyncEvent`, `AsyncLock`, `AsyncShieldCancellation`) on **every call**. Without it, each import triggered a full `sys.path` scan (~700 µs on Windows). Installing `sniffio` (a 10 KB pure-Python package) reduced per-request overhead by ~3.5×, lifting throughput to **1,100–1,200 rps** on a bare ASGI app and **~800 rps** against the real PhantomScan backend.

### Nuclear Guardrails

- **Lab-only enforcement**: `DoSAgent._is_lab_or_localhost(url)` checks for `localhost`, `127.0.0.1`, or `phantombank` substring
- External targets requesting Nuclear are auto-downgraded to **High (50 rps, max 30 s)** with a warning in the API response
- Frontend (`DoSPanel.tsx`) shows a red warning banner, yellow notice, and clamps duration to 5 s

### Metrics & Telemetry

Per-request measurements (DNS, TCP, TLS, TTFB, TTLB, status, body size) are stored in a `deque(maxlen=20_000)` with statistical rollups (mean, median, p95, p99, jitter, throughput). Live stats persist to SQLite every `max(10, rps // 10)` requests. Impact scoring compares attack-phase latency/error rate against baseline (weighted: latency 40%, errors 30%, 5xx 20%, throughput 10%).

---

## 🛠️ Technology Stack

* **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Framer Motion, Lucide Icons, WebSockets.
* **Backend**: FastAPI (Python 3.11+), SQLite Database, AsyncIOScheduler (APScheduler), WebSockets, Pydantic v2.
* **AI Provider**: OpenRouter / Anthropic Claude API.
* **Infrastructure**: Docker, Docker Compose.

---

## ⚙️ Quick Start & Setup

### Prerequisites
* **Docker & Docker Compose** (or Node.js v18+ and Python 3.11+)
* **NVD API Key** (optional, for live CVE lookup rate-limit increases)
* **Anthropic / OpenRouter API Key** (for AI explanations and automated code fixing)

### 1. Backend Environment Setup
```bash
cd backend
cp .env.example .env
```
Edit `backend/.env` with your API keys and configuration:
```dotenv
OPENROUTER_API_KEY= your openrouter api key
GROQ_API_KEY=your_groq_api_key
NVD_API_KEY=your_nvd_api_key
DATABASE_URL=sqlite:///./phantomscan.db
SELF_AUDIT_WEBHOOK=http://localhost:8000/api/logs/alert
FRONTEND_URL=http://localhost:5173
```

### 2. Running with Docker Compose (Recommended)
From the root directory:
```bash
docker-compose -f docker/docker-compose.yml up --build
```

### 3. Running Locally (Without Docker)
From the project root:
```bash
npm run dev
```

---

## 🌐 Ports & Services

| Service | URL | Description |
| :--- | :--- | :--- |
| **Frontend Operations Console** | `http://localhost:5173` | React TypeScript Dashboard & Ops Console |
| **FastAPI Backend Service** | `http://localhost:8000` | REST API, Agent Worker, WebSockets |
| **API Documentation (Swagger UI)** | `http://localhost:8000/docs` | Interactive OpenAPI documentation |

### Key WebSockets
* `ws://localhost:8000/ws/status`: Global health and scheduler heartbeat updates.
* `ws://localhost:8000/ws/scan/{scan_id}`: Real-time scan telemetry, log streaming, and finding alerts.

---

## 📁 Project Structure

```text
phantomscan/
├── backend/
│   ├── app/
│   │   ├── agents/            # Orchestrator & Autonomous Security Agents
│   │   │   └── exploitation/  # PoC exploitation modules (SQLi, XSS, etc.)
│   │   ├── routers/           # REST endpoints (scan, active, lab, dos, findings, auth)
│   │   ├── services/          # Active Gate, Target Authorization, OpenRouter AI Client
│   │   ├── config.py          # App configuration & settings
│   │   ├── database.py        # SQLite storage engine & audit logger
│   │   ├── lab.py             # Built-in vulnerable test lab endpoints
│   │   ├── models.py          # Pydantic schema models
│   │   └── websockets.py      # Real-time WebSocket broker
│   ├── main.py                # FastAPI lifecycle, route inclusions, and scheduler
│   └── requirements.txt       # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/        # UI components & AppShell layout
│   │   ├── features/          # Dashboard, Scans, Findings, CVE, Remediation, Lab, DoS
│   │   ├── hooks/             # Data providers & WebSocket hooks
│   │   ├── App.tsx            # Main App router
│   │   └── types.ts           # Global TypeScript definitions
│   └── package.json           # Frontend scripts & dependencies
├── docker/
│   └── docker-compose.yml     # Container orchestration stack
├── package.json               # Root monorepo dev scripts
└── README.md                  # Project documentation
```

---

## ⚖️ Legal & Ethical Disclaimer

**PhantomScan is intended strictly for security testing on authorized assets.** Scanning, probing, or testing targets without prior explicit written authorization from the system owner is illegal and unethical. The authors assume no liability for misuse or damage caused by this software.
