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
python -m uvicorn main:app --host 127.0.0.1 --port 8001

# Terminal 2 — Frontend
cd frontend
npm install
npm run dev
# Vite will be available at http://localhost:5173
```

> **Port note**: The backend runs on port `8001` for local dev (port `8000` is often occupied).
> The frontend `.env` is configured to connect to `http://127.0.0.1:8001`.

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

### Frontend Environment Variables (`frontend/.env`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `VITE_API_BASE_URL` | `http://127.0.0.1:8001` | Backend API base URL |
| `VITE_WS_BASE_URL` | `ws://127.0.0.1:8001` | WebSocket base URL |
| `VITE_API_URL` | _none_ | Legacy variable (unused, kept for compatibility) |

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

### DoS Testing (Admin Only)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/admin/dos/start` | Start DoS test |
| `POST` | `/api/admin/dos/stop/{job_id}` | Stop running DoS test |
| `GET` | `/api/admin/dos/status/{job_id}` | Get DoS job status |
| `GET` | `/api/admin/dos/history` | Get DoS job history |

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
cd backend
<<<<<<< HEAD
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
=======
python -m pytest tests/ -v
>>>>>>> 65acbad (finilised version)
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
VITE_API_BASE_URL=http://127.0.0.1:8001
VITE_WS_BASE_URL=ws://127.0.0.1:8001
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