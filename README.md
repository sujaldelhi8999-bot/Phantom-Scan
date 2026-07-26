# PhantomScan

PhantomScan is an AI-powered security scanning platform that coordinates autonomous reconnaissance, analysis, vulnerability intelligence, controlled pentesting, and remediation reporting from a single operations console.

## Setup

Requirements: Docker, Docker Compose, Node.js, and npm.

From the project root:

```bash
cd backend
cp .env.example .env
```

Add the required API keys to `backend/.env`:

```dotenv
ANTHROPIC_API_KEY=
GROQ_API_KEY=
NVD_API_KEY=
DATABASE_URL=sqlite:///./phantomscan.db
SELF_AUDIT_WEBHOOK=http://localhost:8000/api/logs/alert
FRONTEND_URL=http://localhost:5173
```

Return to the project root and start the complete stack:

```bash
cd ..
npm run dev
```

To rebuild both images before starting:

```bash
npm run build
```

## Ports

| Service | URL | Port |
| --- | --- | --- |
| Frontend operations console | http://localhost:5173 | 5173 |
| FastAPI backend and WebSocket | http://localhost:8000 | 8000 |

FastAPI documentation is available at `http://localhost:8000/docs`.

## Agents

1. **Scanner** - Resolves DNS, enumerates common subdomains, checks exposed ports, and fingerprints the HTTP technology stack.
2. **Analyzer** - Reviews response headers and application configuration for security weaknesses and unsafe CORS behavior.
3. **CVE Matcher** - Correlates detected technologies with live vulnerability records from the NVD API.
4. **AI Explainer** - Uses Claude to explain exploitation paths and provide exact remediation commands or code.
5. **Hindi Explainer** - Produces Hindi vulnerability explanations for regional security reports.
6. **Fixer** - Groups findings by severity and generates a prioritized Markdown remediation checklist.
7. **Notifier** - Delivers scan summaries and alerts to a configured webhook endpoint.
8. **Shadow Recon** - Performs passive WHOIS, search-query, robots.txt, and sitemap.xml reconnaissance.
9. **Pentest** - Runs authorized SQLi, XSS, redirect, and access-control probes with full payload auditing.
10. **Self Audit** - Scans PhantomScan itself nightly at 02:00 UTC and raises alerts for critical findings.

The **Orchestrator** coordinates agent execution and WebSocket events, while the **Sandbox Manager** enforces subprocess timeout and memory limits.

## Project Structure

```text
phantomscan/
|-- backend/       FastAPI, SQLite, agents, and backend Dockerfile
|-- frontend/      React, TypeScript, Vite, Tailwind, and frontend Dockerfile
|-- docker/        Docker Compose configuration
|-- package.json   One-command development scripts
`-- README.md
```

Only scan systems you own or have explicit authorization to test.
