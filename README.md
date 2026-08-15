# 🛡️ PhantomScan

**PhantomScan** is an AI-powered, full-stack web application security testing platform. It orchestrates autonomous reconnaissance, deep vulnerability analysis, real-time threat intelligence correlation, controlled exploit verification, and AI-driven remediation reporting from a unified operations console.

Built for **authorized security testing** on targets you own, the PhantomBank Lab, or localhost.

---

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

```bash
git clone <repo-url>
cd phantomscan
cp backend/.env.example backend/.env
# Edit backend/.env with your API keys (see Configuration below)
docker-compose -f docker/docker-compose.yml up --build
```

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **Swagger UI**: http://localhost:8000/docs

### Option 2: Local Development

```bash
# Terminal 1 — Backend
cd backend
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API keys
python -m uvicorn main:app --host 127.0.0.1 --port 8000

# Terminal 2 — Frontend
cd frontend
npm install
npm run dev
# Vite will be available at http://localhost:5173
```

> **Port note**: The backend runs on port `8000` (matching Docker). If port
> `8000` is occupied, start the backend on `8001` and set
> `VITE_API_BASE_URL=http://127.0.0.1:8001` in `frontend/.env` so the frontend
> connects to it.

---

## 🏗️ Project Structure

```
phantomscan/
├── backend/
│   ├── app/
│   │   ├── agents/            # Security agents (orchestrator, scanner, recon, analyzer...)
│   │   │   └── exploitation/    # PoC exploitation modules (SQLi, XSS, etc.)
│   │   ├── routers/           # REST API endpoints (scan, active, dos, findings, auth...)
│   │   ├── services/          # Active gate, target authorization, AI client, browser obs
│   │   ├── workers/           # Background worker for authorized tests
│   │   ├── config.py          # App configuration & settings
│   │   ├── database.py        # SQLite storage engine, schema, migrations
│   │   ├── lab.py             # Built-in vulnerable test lab endpoints
│   │   ├── models.py          # Pydantic v2 data models
│   │   ├── security.py        # JWT authentication & password hashing
│   │   ├── main.py            # FastAPI entry: CORS, WebSockets, scheduler, routes
│   │   └── websockets.py      # Real-time WebSocket event broker
│   ├── tests/                 # Integration & smoke tests
│   ├── .env.example           # Backend environment template
│   ├── requirements.txt       # Python dependencies
│   └── Dockerfile             # Production container image
│
├── frontend/
│   ├── src/
│   │   ├── components/        # UI components (AppShell, ErrorBoundary, LoginModal, UI primitives)
│   │   ├── context/           # React context providers (AuthContext)
│   │   ├── features/          # Page-level components (dashboard, scans, findings, dos...)
│   │   ├── hooks/             # Custom hooks (usePhantomData, useScanTelemetry)
│   │   ├── services/          # API client (axios), auth service
│   │   ├── utils/             # Data transformation utilities (derived.ts)
│   │   ├── types.ts           # TypeScript type definitions
│   │   ├── App.tsx            # Main app with route definitions
│   │   ├── main.tsx           # React entry point (HashRouter + ErrorBoundary)
│   │   └── index.css          # Tailwind CSS entry
│   ├── .env                   # Vite environment variables
│   ├── vite.config.ts         # Vite configuration (base path, proxy, dev server)
│   ├── package.json           # Frontend scripts & dependencies
│   └── Dockerfile             # Development container image
│
├── docker/
│   └── docker-compose.yml     # Multi-container orchestration
├── .env.example               # Root environment template
└── README.md                  # This file
```

---

## ⚙️ Configuration

### Backend Environment Variables (`backend/.env`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `OPENROUTER_API_KEY` | _none_ | OpenRouter API key for AI features (explainer, analyst, fixer) |
| `OPENROUTER_MODEL` | `openrouter/free` | LLM model identifier |
| `GROQ_API_KEY` | _none_ | Optional Groq API key |
| `NVD_API_KEY` | _none_ | NVD API key for CVE lookup (increases rate limits) |
| `DATABASE_URL` | `sqlite:///./phantomscan.db` | SQLite database path |
| `SELF_AUDIT_WEBHOOK` | `http://localhost:8000/api/logs/alert` | Self-audit alert endpoint |
| `FRONTEND_URL` | `http://localhost:5173` | Frontend origin (for CORS) |
| `ACTIVE_TARGET_ALLOWLIST` | _none_ | Comma-separated allowed origins for active testing |
| `ADMIN_USERNAME` | `admin` | Admin login username |
| `ADMIN_PASSWORD` | `admin123` | Admin login password |
| `SECRET_KEY` | `your-secret-key-change-this` | JWT signing secret |
| `LOCAL_USER_ID` | `local-user` | Local user identifier |
| `LOCAL_USER_ROLE` | `user` | Local user role (`admin` grants admin access) |
| `MAX_SCAN_DURATION` | `300` | Maximum scan duration in seconds |
| `MAX_REQUESTS_PER_SECOND` | `2.0` | Rate limit for scan HTTP requests |
| `MAX_TOTAL_REQUESTS` | `300` | Maximum total HTTP requests per scan |
| `MAX_CONCURRENT_SCANS` | `2` | Maximum concurrent scans |
| `MAX_REDIRECT_DEPTH` | `0` | Maximum redirect chain depth |
| `MAX_RESPONSE_SIZE` | `1048576` | Maximum response body size (bytes) |
| `BROWSER_PAGE_LIMIT` | `8` | Maximum browser pages for browser security agent |
| `DEEP_PORT_SCAN` | `1` | Enable deep port scanning (full 1-65535 range) |
| `PORT_SCAN_CONCURRENCY` | `64` | Port scan concurrency |
| `PORT_SCAN_MAX_PORTS` | `1024` | Maximum ports to scan |
| `PORT_SCAN_SWEEP_TIMEOUT` | `75.0` | Port sweep timeout in seconds |
| `SUPABASE_URL` | _none_ | Supabase project URL (Google / GitHub login) |
| `SUPABASE_JWT_SECRET` | _none_ | Supabase project JWT secret (Project Settings → API) |
| `SUPABASE_ADMIN_EMAILS` | _none_ | Comma-separated emails that receive the `admin` role |
| `BRUTAL_MODE_ENABLED` | `0` | Master kill switch for Brutal Mode (active exploitation, shells, post-exploitation, lateral movement, exfiltration). **Off by default.** |
| `BRUTAL_EXFIL_DIR` | `backend/brutal_exfil` | Directory where exfiltration loot archives are stored |
| `BRUTAL_MAX_COMMANDS_PER_SHELL` | `100` | Per-shell interactive command budget |
| `BRUTAL_COMMAND_TIMEOUT` | `12.0` | Per-command timeout (seconds) in the interactive shell |
| `EXPLOITATION_ENABLED` | `0` | Global kill-switch for the scan exploitation engine (SQLi, XSS, path traversal, command injection). **Off by default.** A scan only exploits when this is on **and** the user ticks "Enable Exploitation" on the Authorized Testing page. |
| `AI_EXPLOITATION_ENABLED` | `0` | Global kill-switch for AI-driven PoC generation (OpenRouter). Falls back to deterministic templates when `OPENROUTER_API_KEY` is not set. |
| `EXPLOIT_ATTEMPT_TIMEOUT` | `30.0` | Per-finding timeout (seconds) for each exploitation attempt |
| `EXPLOIT_MAX_FINDINGS` | `10` | Maximum findings exploited per scan |

### Frontend Environment Variables (`frontend/.env`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `VITE_API_BASE_URL` | `http://127.0.0.1:8000` | Backend API base URL |
| `VITE_WS_BASE_URL` | `ws://127.0.0.1:8000` | WebSocket base URL |
| `VITE_API_URL` | _none_ | Legacy variable (unused, kept for compatibility) |
| `VITE_SUPABASE_URL` | _none_ | Supabase project URL (Google / GitHub login) |
| `VITE_SUPABASE_ANON_KEY` | _none_ | Supabase anon public key (Project Settings → API) |

---

## 🔑 Supabase Login Setup (Google & GitHub)

The login modal offers **Continue with Google** and **Continue with GitHub**
buttons powered by [Supabase Auth](https://supabase.com/docs/guides/auth).

### 1. Create a Supabase project

1. Sign up at [supabase.com](https://supabase.com) and create a new project.
2. Open **Authentication → Providers**.

### 2. Enable the Google provider

1. Create OAuth credentials at
   [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   (OAuth Client ID, type *Web application*).
2. Add the authorized redirect URI:
   `https://<your-project-ref>.supabase.co/auth/v1/callback`
3. In Supabase → **Authentication → Providers → Google**, paste the Client ID
   and Client Secret and enable the provider.

### 3. Enable the GitHub provider

1. Create an OAuth App at
   [GitHub Developer Settings](https://github.com/settings/developers) →
   *New OAuth App*.
2. Set the authorization callback URL to:
   `https://<your-project-ref>.supabase.co/auth/v1/callback`
3. In Supabase → **Authentication → Providers → GitHub**, paste the Client ID
   and Client Secret and enable the provider.

### 4. Configure PhantomScan

**Backend (`backend/.env`):**

```env
SUPABASE_URL=https://<your-project-ref>.supabase.co
SUPABASE_JWT_SECRET=<Project Settings → API → JWT Secret>
SUPABASE_ADMIN_EMAILS=you@example.com
```

**Frontend (`frontend/.env`):**

```env
VITE_SUPABASE_URL=https://<your-project-ref>.supabase.co
VITE_SUPABASE_ANON_KEY=<Project Settings → API → anon public key>
```

### 5. Allow the local callback URL

In Supabase → **Authentication → URL Configuration**:

1. Set **Site URL** to `http://localhost:5173`.
2. Add `http://localhost:5173/auth/callback` to **Redirect URLs**.
   (The default allowlist only covers `http://localhost:3000/**`; without this
   entry the login buttons fail with *"untrusted redirect"*.)

After completing the OAuth round-trip, Supabase redirects the browser to
`/auth/callback` and PhantomScan exchanges the session, then lands you back on
the dashboard.

> **Note**: the existing GitHub OAuth integration (`/api/github`) is separate —
> it scans repositories. GitHub *login* via Supabase only authenticates users.
> The admin username/password login always remains available.

---

## 🛡️ Key Features

### 1. Autonomous Multi-Agent Security Scanning

PhantomScan orchestrates 20+ specialized agents to perform comprehensive security assessments:

| Agent | Responsibility |
| :--- | :--- |
| **Orchestrator** | Coordinates scan lifecycles, phase progression, parallel agent execution |
| **Scanner** | DNS enumeration, port scanning, service fingerprinting, TLS analysis, subdomain discovery |
| **Shadow Recon** | Passive OSINT: WHOIS, Google dorks, robots.txt, sitemap.xml, source maps, wayback URLs |
| **Analyzer** | Security header validation (CSP, HSTS, CORS), cookie security flags, open redirects |
| **CVE Matcher** | Correlates detected technologies against NVD API for known vulnerabilities |
| **Browser Security** | Client-side security verification via Playwright browser automation |
| **Security Assessment Suite** | 9 targeted sub-agents: Auth, AccessControl, API, Session, Injection, Infrastructure, WebSocket, Dependency, ThreatIntelligence |
| **AI Security Analyst** | AI-powered vulnerability prioritization and root-cause analysis |
| **AI Explainer** | Threat descriptions and code remediation snippets via LLM |
| **Hindi Explainer** | Hindi-language security reports |
| **Fixer** | Prioritized Markdown remediation action plans |
| **Notifier** | Webhook alerts (Slack/Discord/Custom) |
| **DoS Agent** | Controlled load testing with 5 intensity tiers |
| **Self Audit** | Automated nightly security regression audit |

### 2. Real-Time WebSocket Console

- **Global health**: `ws://localhost:8001/ws/status` — server health, scheduler status, agent availability
- **Scan telemetry**: `ws://localhost:8001/ws/scan/{scan_id}` — live progress, log streaming, finding alerts

### 3. Controlled DoS & Load Stress Testing

The DoS agent provides five intensity tiers for controlled load testing:

| Intensity | Requests/s | Max Duration | Outside Lab? |
| :--- | :--- | :--- | :--- |
| **Low** | 2 | 300s | ✅ |
| **Medium** | 10 | 120s | ✅ |
| **High** | 50 | 30s | ✅ |
| **Critical** | 100 | 10s | ❌ (auto-downgraded to High) |
| **Nuclear** | 10,000 | 5s | ❌ (auto-downgraded to High) |

**Nuclear guardrails**: Nuclear and Critical intensities are restricted to lab/localhost targets. External targets are auto-downgraded to High intensity.

#### DoS Agent Architecture

The DoS agent uses a **worker-per-connection** model to achieve high throughput:
- Each worker owns one `httpx.AsyncClient` with `max_connections=1`
- A round-robin scheduler distributes requests across workers
- This bypasses httpcore's connection pool pile-up bottleneck
- Worker count scales with intensity: `min(max(4, rps // 10), 128)`

### 4. Target Authorization & Scope Gate

PhantomScan enforces strict target authorization:

| Authorization Level | How It Works |
| :--- | :--- |
| **Built-in Lab** | PhantomBank lab targets (`localhost/lab/phantombank`) — always allowed |
| **Loopback** | `localhost` and `127.0.0.1` — always allowed for lab/development |
| **Allowlist** | Configured in `ACTIVE_TARGET_ALLOWLIST` env var |
| **Verified** | Requires DNS TXT record or file verification token |
| **Admin Override** | Targets in Private Scope (requires `LOCAL_USER_ROLE=admin`) |

Admin endpoints require the `LOCAL_USER_ROLE` environment variable to be set to `admin`.

### 5. AI-Powered Analysis

- OpenRouter/Anthropic Claude API integration for:
  - Vulnerability explanation and risk assessment
  - Code remediation snippets
  - Findings prioritization and root-cause grouping
  - Hindi-language reporting

### 6. Brutal Mode (Black Ops)

A fully gated offensive-security module that walks the complete kill chain
against authorized targets (PhantomBank Lab or Private Scope hosts):

- **Auto-Exploitation** — one-click flows for SQLi, RCE, command injection,
  LFI, SSRF, file upload and XSS, mapped from detected findings, with an
  evasion layer (rotating user agents, request jitter, payload obfuscation)
  and a slow-scan mode.
- **Interactive Shells** — REST or WebSocket consoles with reverse/bind shell
  one-liners. Commands are filtered (destructive operations are blocked),
  budgeted per shell, and every single command is written to the `brutal_ops`
  audit table.
- **Post-Exploitation** — system enumeration and privilege-escalation checks.
- **Lateral Movement** — SSH key harvesting, internal network mapping and
  pivoting (lab-simulated only; never touches real hosts).
- **Persistence** — lab-simulated cron/registry templates.
- **Exfiltration** — loot (DB dumps, configs, keys, command output) packed
  into a checksummed ZIP archive with a manifest; admin-only, traversal-safe
  download.
- **AI Payloads** — LLM-generated target-specific payloads with a
  deterministic offline fallback and per-engagement caching.

**Safety gates (server-enforced, non-negotiable):** `BRUTAL_MODE_ENABLED=1`
kill switch (off by default) → admin role → target must be the lab or in
Private Scope → explicit ownership acknowledgment on mutating calls. Denials
and approvals are written to the audit log, and every operation lands in the
`brutal_ops` table. The lab simulation never touches real files, processes or
network hosts.

### 7. Exploitation Engine (Scan-Integrated)

The pentest scan pipeline can actively exploit confirmed findings after the
analysis phase. It is **off by default** and requires three independent gates:

1. **Global kill-switch** — `EXPLOITATION_ENABLED=true` in `backend/.env`
   (rejected with HTTP 403 by the scan policy when disabled).
2. **Conscious per-scan opt-in** — the user ticks **"Enable Exploitation"** on
   the Authorized Testing page (only reachable in pentest mode against
   verified / Private Scope / PhantomBank Lab targets).
3. **Mode + severity gates** — exploitation only ever runs in pentest mode and
   only against **CRITICAL/HIGH** findings.

What it does per vulnerability class:

- **SQL injection** — probe payloads plus a sqlmap-style async extraction
  wrapper that fingerprints the database (`SQLite 3.x`, MySQL, PostgreSQL,
  MSSQL, Oracle), enumerates tables, and pulls rows from the first tables.
- **XSS** — generates a cookie-stealing proof-of-concept URL (delivery-only;
  the payload is not executed by PhantomScan).
- **Path traversal / LFI** — attempts to read common sensitive files
  (`/etc/passwd`, `win.ini`, `.env`, …) with output redaction applied.
- **Command injection / RCE** — executes only harmless identity commands
  (`whoami`, `id`); output is redacted.
- **XXE** — entity-injection probes reading local files through the parser.

Safety behaviour: endpoints that return `403/404` or are unreachable are
skipped and marked `not_exploitable`; every attempt is time-boxed
(`EXPLOIT_ATTEMPT_TIMEOUT`, default 30 s) and capped per scan
(`EXPLOIT_MAX_FINDINGS`); every attempt is written to the `audit_logs` table
with `action='exploitation'` and to the `exploitation_results` table.

**AI exploitation** (`AI_EXPLOITATION_ENABLED=true` + the per-scan toggle) uses
OpenRouter to generate context-aware payloads with a one-hour cache. Without
`OPENROUTER_API_KEY` it falls back to deterministic templates, so validated
PoCs still work offline.

To try it end-to-end against the lab:

```bash
# backend/.env
EXPLOITATION_ENABLED=true
AI_EXPLOITATION_ENABLED=true
OPENROUTER_API_KEY=            # optional; templates used when empty
```

Then: **Authorized Testing** → **PhantomBank Lab** → **All Vulnerable** →
Map Surface → tick **Enable Exploitation** (and optionally **AI
Exploitation**) → **Run Authorized Test**. Backend logs will show
`phantomscan.exploitation:Exploiting SQL injection on ...` and the Results
panel shows the exploitation outcomes with a **Download Exploitation Report**
button.

---

## 📂 API Endpoints

### Scan Operations
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scan/start` | Start a new security scan |
| `GET` | `/api/scan/{scan_id}` | Get scan status and progress |
| `POST` | `/api/scan/{scan_id}/stop` | Stop a running scan |
| `GET` | `/api/scan/{scan_id}/artifacts` | Get scan artifacts |
| `GET` | `/api/scan/history` | Get scan history |

### Findings
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/findings` | List all findings |
| `POST` | `/api/findings/{id}/verify` | Verify finding fix |
| `PATCH` | `/api/findings/{id}/remediation` | Update remediation status |
| `PATCH` | `/api/findings/{id}/risk` | Update risk status |

### Authorized Testing
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/active/map` | Generate attack surface map |
| `POST` | `/api/active/score` | Calculate attack surface score |
| `POST` | `/api/active/run` | Start authorized test run |
| `GET` | `/api/active/jobs/{jobId}` | Get job status |
| `GET` | `/api/active/jobs/{jobId}/results` | Get job results |
| `GET` | `/api/active/jobs/{jobId}/events` | Get job event stream |
| `GET` | `/api/execution/status` | Get execution lifecycle status |

### Code Analysis (SAST, Admin Only)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/sast/scan-repo?repo_url=...&branch=main` | Clone a public GitHub repo and scan it (Semgrep, TruffleHog, Gitleaks, SCA, IaC) |
| `GET` | `/api/sast/{scan_id}` | Scan status, source phases, and findings |

### DoS Testing (Admin Only)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/admin/dos/start` | Start DoS test |
| `POST` | `/api/admin/dos/stop/{job_id}` | Stop running DoS test |
| `GET` | `/api/admin/dos/status/{job_id}` | Get DoS job status |
| `GET` | `/api/admin/dos/history` | Get DoS job history |

### Brutal Mode (Black Ops, Admin Only — gated)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/brutal/status` | Gate status (env flag, admin, requirements, supported categories) |
| `POST` | `/api/brutal/ack` | Record ownership/permission acknowledgment (audited) |
| `POST` | `/api/brutal/sessions` | Establish a session against an in-scope target (requires `ownership_ack: true`) |
| `GET` | `/api/brutal/sessions` | List sessions |
| `GET` | `/api/brutal/sessions/{id}` | Session detail (timeline + loot) |
| `POST` | `/api/brutal/sessions/{id}/exploit` | Run an exploitation flow (`category`: sqli, rce, lfi, ssrf, xss, file_upload, injection) |
| `POST` | `/api/brutal/sessions/{id}/shell` | Open an interactive shell session |
| `POST` | `/api/brutal/shell/{shell_id}/exec` | Run a command in the shell (filtered + budgeted + audited) |
| `GET` | `/api/brutal/shell/{shell_id}/payloads` | Reverse shell / bind shell one-liners |
| `DELETE` | `/api/brutal/shell/{shell_id}` | Close a shell |
| `POST` | `/api/brutal/sessions/{id}/post-exploit` | Enumeration + privilege-escalation checks (lab-simulated) |
| `POST` | `/api/brutal/sessions/{id}/lateral` | SSH key harvest + internal network map + pivot (lab-simulated) |
| `POST` | `/api/brutal/sessions/{id}/persist` | Install persistence (lab-simulated templates only) |
| `POST` | `/api/brutal/sessions/{id}/exfil` | Pack loot into a ZIP archive (SHA256 + MANIFEST) |
| `GET` | `/api/brutal/exfil/{file_id}` | Download the loot archive (admin only, traversal-safe) |
| `POST` | `/api/brutal/sessions/{id}/payload` | AI payload generation (OpenRouter, offline fallback) |
| `GET` | `/api/brutal/ops` | `brutal_ops` audit trail |
| `WS` | `/ws/brutal/shell/{shell_id}?token=...` | Interactive WebSocket shell console (admin token required) |

### System & Admin
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/lab/status` | Lab status |
| `GET` | `/api/lab/manifest` | Lab manifest |
| `POST` | `/api/lab/scenario` | Set lab scenario |
| `POST` | `/api/lab/reset` | Reset lab |
| `GET` | `/api/admin/scope/list` | List private scope targets |
| `POST` | `/api/admin/scope/add` | Add target to private scope |
| `DELETE` | `/api/admin/scope/remove` | Remove target from scope |
| `GET` | `/api/admin/scope/role` | Get user role |
| `GET` | `/api/agents/status` | Get agent statuses |
| `GET` | `/api/logs` | Get audit logs |
| `POST` | `/api/auth/login` | Login |
| `GET` | `/api/authorization/status` | Check target authorization |

### Authorization System
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/authorization/challenge` | Create authorization challenge |
| `POST` | `/api/authorization/{id}/verify` | Verify authorization |
| `POST` | `/api/authorization/{id}/revoke` | Revoke authorization |

---

## 🧪 Running Tests

```bash
cp .env.example .env
# Edit backend/.env with your API keys and configuration
python -m pytest tests/ -v
```

---

## 🐳 Docker

### Build & Run
```bash
docker-compose -f docker/docker-compose.yml up --build
```

### Environment Configuration in Docker
The docker-compose file sets the frontend environment variables:
- `VITE_API_BASE_URL: http://localhost:8000`
- `VITE_WS_BASE_URL: ws://localhost:8000`

For local development (without Docker), create a `frontend/.env` file:
```dotenv
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_WS_BASE_URL=ws://127.0.0.1:8000
```

---

> **Windows note**: use `127.0.0.1` (not `localhost`) in the frontend env — on
> Windows `localhost` resolves to IPv6 `::1` while uvicorn binds IPv4
> `127.0.0.1`, which leaves WebSocket connections stuck in "pending" and
> produces `ERR_NETWORK_CHANGED` errors.

---

## 🧪 PhantomBank Lab Demo

PhantomScan ships with a built-in, intentionally vulnerable banking application
at `http://localhost:8000/lab/phantombank` — the safe target for every demo.

### Using the lab

1. Start the backend and frontend (see Quick Start).
2. Log in to PhantomScan (admin login or Supabase).
3. Go to **Defend Scan**, enter `http://localhost:8000/lab/phantombank`, pick
   **Medium** intensity and start the scan.
4. Watch the real-time agent log stream on the right; findings appear live as
   the Analyzer/Security Assessment agents report them (security headers, CORS,
   SQL injection, session cookies, etc.).
5. Open the report (`/report/{scan_id}`) for severity breakdown, remediation
   plan, and AI analysis.

### Lab scenarios

| Endpoint | Effect |
| :--- | :--- |
| `GET /api/lab/scenario?name=patched` | Patch most vulnerabilities (CSP, HSTS, secure cookies, parameterized SQL) |
| `GET /api/lab/scenario?name=vulnerable` | Restore the vulnerable state |
| `POST /api/lab/reset` | Reset the lab |

**Demo flow**: scan the lab (vulnerable) → findings appear → toggle scenario to
`patched` → rescan the same target → 0 findings → shows remediation in action.

### Multi-Agent / Multi-Source scans

- **Multi-Source** (sidebar → Multi-Source): run SAST + DAST + SCA + IaC +
  secrets against a live target and/or a GitHub repository in one coordinated
  scan, with cross-source correlation.
- **Code Analysis** (sidebar → Operations → Code Analysis, admin only): paste a
  public GitHub repo URL (e.g. `https://github.com/expressjs/express`) and scan
  it with Semgrep, TruffleHog, Gitleaks, pip-audit/npm-audit, and IaC rules.

---

## 🎤 5-Minute Hackathon Demo Script

> Recommended order — each step has a natural "wow" moment.

| Time | Step | What the judges see |
| :--- | :--- | :--- |
| 0:00 | **Intro (30s)** | "PhantomScan is an AI-powered autonomous security testing platform with 20+ agents." Show the dashboard. |
| 0:30 | **Login** | Click **Continue with GitHub** (Supabase OAuth). Header shows your avatar + name. |
| 1:00 | **Add target & scan** | Defend Scan → `http://localhost:8000/lab/phantombank` → Medium → **Start Scan**. Live telemetry sidebar streams agent activity in real time. |
| 2:30 | **Findings** | After ~60–90s the scan completes; show the findings list with severity badges, then open the **Report** page (severity breakdown, CVSS, remediation checklist, AI analysis). |
| 3:30 | **Attack Intelligence** | Sidebar → **Attack Intelligence** → enter `localhost/lab/phantombank` → **Analyze**. Full dossier: DNS, ports, technologies, headers, exposed assets, entry points, risk score. |
| 4:00 | **Code Analysis** | Sidebar → **Code Analysis** → paste `https://github.com/expressjs/express` → **Scan Repository**. Show SAST findings (secrets, vulnerable deps). |
| 4:30 | **Brutal Mode (optional wow)** | Sidebar → **Brutal Mode** → pick the lab target → tick ownership → **Establish Session** → **SQLi** auto-exploit (DB dump in Loot), **Open Shell** → `whoami`, `netstat`, and a blocked `rm -rf /` command — then **Exfiltrate** → **Download** the loot ZIP. Show the `brutal_ops` audit trail. |
| 5:00 | **Remediation proof** | `GET /api/lab/scenario?name=patched` → **Rescan** the lab → report shows **0 findings** (or dramatically fewer). |
| 5:15 | **Close** | "Everything is logged in an append-only audit trail; WebSocket events stream every action." |

**Backup plan**: if the live demo fails, play the recorded video (see below).

---

## 🎥 Backup Demo Video

Record a 3-minute screen capture (OBS Studio or Windows Game Bar) of:

1. Supabase login (GitHub OAuth) → avatar in header
2. Defend Scan on `http://localhost:8000/lab/phantombank` (VULNERABLE) → findings appear
3. Report page with severity breakdown + remediation checklist
4. Toggle lab to `patched` → rescan → 0 findings
5. Attack Intelligence dossier for the lab
6. Code Analysis on a public repo
7. Brutal Mode: establish session → SQLi exploit (loot) → shell `whoami` + blocked destructive command → exfil download

Save as `demo.mp4` and keep it next to your laptop. Rehearse the script above
once with the video playing so the timing matches.

---

## ✅ Verification Commands

```bash
# Backend — targeted fix regression tests (expect 14 passing)
cd backend
python -m pytest tests/test_fix_verification.py -v
python -m pytest tests/test_learning_engine.py -q
python -m pytest tests/test_brutal_mode.py -q   # Brutal Mode gate + shell + exfil safety (expect 20 passing)

# Frontend
cd frontend
npm run typecheck
npm run build

# Start the stack
cd backend && python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
cd frontend && npm run dev
```

---

## ⚖️ Legal & Ethical Disclaimer

**PhantomScan is intended strictly for security testing on authorized assets.**

- Only scan targets you own or have **explicit written permission** to test
- The PhantomBank Lab (`/lab/phantombank`) is provided as a safe, controlled environment for testing
- DoS testing is restricted to lab/localhost targets by default
- Unauthorized scanning of third-party systems is illegal and unethical
- The authors assume no liability for misuse or damage caused by this software

---

## 🔧 Development Notes

### Error Handling
PhantomScan includes a React `ErrorBoundary` component that catches render-time JavaScript errors and displays a diagnostic page instead of a blank screen. The backend includes a global exception handler that logs full stack traces.

### Database Migrations
PhantomScan uses an incremental migration system in `database.py`. New columns and tables are added via migration functions called during `initialize_database()`. The database is automatically created and migrated on startup.

### Technology Stack
| Layer | Technology |
| :--- | :--- |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Framer Motion, Lucide Icons |
| **Backend** | FastAPI, Python 3.11+, aiosqlite, Pydantic v2, APScheduler |
| **AI Provider** | OpenRouter API (configurable) |
| **Browser Automation** | Playwright |
| **Infrastructure** | Docker, Docker Compose |

---

## 📜 License

This project is provided for educational and authorized security testing purposes. See the LICENSE file for details.