# PhantomScan Report: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
**Scan ID:** 39
**Time:** 20260729_142603

## Summary
- Total findings: 7
- HIGH: 1
- MEDIUM: 2
- LOW: 4
- Subdomains: 41
- Open ports: 3
- WAF: none

## Findings
### [HIGH] CSP allows unsafe-inline scripts
- Category: Security Headers
- Endpoint: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
- Evidence: script-src includes 'unsafe-inline'
- Impact: Bypasses CSP protection against XSS
- Fix: Remove 'unsafe-inline' from script-src; use nonces or hashes

### [LOW] Missing Permissions-Policy
- Category: Security Headers
- Endpoint: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
- Evidence: No Permissions-Policy header
- Impact: Browser features (camera, mic, etc.) unrestricted
- Fix: Add: Permissions-Policy: geolocation=(), microphone=(), camera=()

### [MEDIUM] Could not establish TLS connection
- Category: TLS
- Endpoint: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
- Evidence: Failed to connect to nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app:443
- Impact: TLS may not be available
- Fix: Ensure HTTPS is properly configured

### [LOW] Server version disclosure
- Category: Information Disclosure
- Endpoint: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
- Evidence: Header 'server: Vercel'
- Impact: Attackers fingerprint stack for targeted exploits
- Fix: Remove or obfuscate the 'server' header in server config

### [LOW] API response permits reads from any origin
- Category: API Security
- Endpoint: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
- Evidence: Captured response sets Access-Control-Allow-Origin: *.
- Impact: The policy may expose browser-readable API data to untrusted sites; conforming browsers reject the wildcard/credentials combination but it signals unsafe policy intent.
- Fix: Allow only required trusted origins and enable credentials only for endpoints that need them.

### [MEDIUM] Content Security Policy permits unsafe script execution
- Category: Infrastructure Security
- Endpoint: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
- Evidence: The captured CSP script policy includes unsafe-inline or unsafe-eval; nonce and hash values are omitted from evidence.
- Impact: The policy provides reduced protection if attacker-controlled script or markup reaches the page.
- Fix: Remove unsafe-eval and migrate inline scripts to nonces or hashes with narrowly scoped sources.

### [LOW] Non-production or administrative hostnames discovered
- Category: Threat Intelligence
- Endpoint: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
- Evidence: Supplied reconnaissance includes sensitive-looking hostname(s): admin.nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app, beta.nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app, dev.nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app, internal.nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app, old.nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app, staging.nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app, test.nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app.
- Impact: Forgotten or less-hardened environments can expand the externally reachable attack surface.
- Fix: Inventory each hostname, retire unused systems, and apply production-equivalent access controls and patching.

## Remediation Checklist
# PhantomScan Remediation Checklist

## HIGH

- [ ] **[HIGH]** CSP allows unsafe-inline scripts
  - Affected: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
  - Fix: `Remove 'unsafe-inline' from script-src; use nonces or hashes`
  - Owner: frontend
  - ETA: 4h

## MEDIUM

- [ ] **[MEDIUM]** Could not establish TLS connection
  - Affected: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
  - Fix: `Ensure HTTPS is properly configured`
  - Owner: devops
  - ETA: 1d

- [ ] **[MEDIUM]** Content Security Policy permits unsafe script execution
  - Affected: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
  - Fix: `Remove unsafe-eval and migrate inline scripts to nonces or hashes with narrowly scoped sources.`
  - Owner: backend
  - ETA: 1d

## LOW

- [ ] **[LOW]** Missing Permissions-Policy
  - Affected: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
  - Fix: `Add: Permissions-Policy: geolocation=(), microphone=(), camera=()`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Server version disclosure
  - Affected: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
  - Fix: `Remove or obfuscate the 'server' header in server config`
  - Owner: devops
  - ETA: 1w

- [ ] **[LOW]** API response permits reads from any origin
  - Affected: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
  - Fix: `Allow only required trusted origins and enable credentials only for endpoints that need them.`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Non-production or administrative hostnames discovered
  - Affected: https://nyay-mitra-rjwmzrjrv-sujaldelhi8999-8617s-projects.vercel.app/
  - Fix: `Inventory each hostname, retire unused systems, and apply production-equivalent access controls and patching.`
  - Owner: backend
  - ETA: 1w


# Browser Observation Report
Engine: http_fallback
Pages visited: 1
Network events: 1
APIs discovered: 0
Console events: 0
WebSockets: 0
Safety pause: Unexpected redirect outside scope: https://vercel.com/sso-api?url=http_%2A%2A%2A%2A%2A%2A%2A%2A%2A%2A%2A%2Aapp%2F&nonce=3e5d_%2A%2A%2A%2A%2A%2A%2A%2A%2A%2A%2A%2Af00e
- [LOW/HIGH] CSP missing or weak with browser-observed script surfaces
