# PhantomScan Report: https://insights-ai.info/Home
**Scan ID:** 59
**Time:** 20260730_080229

## Summary
- Total findings: 7
- MEDIUM: 4
- LOW: 3
- Subdomains: 2
- Open ports: 4
- WAF: cloudflare

## Findings
### [MEDIUM] Missing Content Security Policy
- Category: Security Headers
- Endpoint: https://insights-ai.info/Home
- Evidence: No CSP header found
- Impact: XSS and data injection attacks are easier without CSP
- Fix: Add: Content-Security-Policy: default-src 'self'

### [LOW] HSTS missing preload directive
- Category: Security Headers
- Endpoint: https://insights-ai.info/Home
- Evidence: No preload flag in HSTS
- Impact: Browser won't preload HSTS
- Fix: Add 'preload' to HSTS header and submit to hstspreload.org

### [LOW] Missing Permissions-Policy
- Category: Security Headers
- Endpoint: https://insights-ai.info/Home
- Evidence: No Permissions-Policy header
- Impact: Browser features (camera, mic, etc.) unrestricted
- Fix: Add: Permissions-Policy: geolocation=(), microphone=(), camera=()

### [MEDIUM] Wildcard CORS allowed
- Category: CORS
- Endpoint: https://insights-ai.info/Home
- Evidence: Access-Control-Allow-Origin: *
- Impact: Any origin can read responses
- Fix: Restrict to specific trusted origins

### [MEDIUM] Could not establish TLS connection
- Category: TLS
- Endpoint: https://insights-ai.info/Home
- Evidence: Failed to connect to insights-ai.info:443
- Impact: TLS may not be available
- Fix: Ensure HTTPS is properly configured

### [LOW] Server version disclosure
- Category: Information Disclosure
- Endpoint: https://insights-ai.info/Home
- Evidence: Header 'server: cloudflare'
- Impact: Attackers fingerprint stack for targeted exploits
- Fix: Remove or obfuscate the 'server' header in server config

### [MEDIUM] Missing Content Security Policy
- Category: Infrastructure Security
- Endpoint: https://insights-ai.info/Home
- Evidence: No Content-Security-Policy header was captured.
- Impact: Missing browser defense-in-depth controls can increase the impact of a separate content injection or UI-redress weakness.
- Fix: Deploy a restrictive, application-specific Content-Security-Policy.


## Remediation Checklist
# PhantomScan Remediation Checklist

## MEDIUM

- [ ] **[MEDIUM]** Missing Content Security Policy
  - Affected: https://insights-ai.info/Home
  - Fix: `Add: Content-Security-Policy: default-src 'self'`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Wildcard CORS allowed
  - Affected: https://insights-ai.info/Home
  - Fix: `Restrict to specific trusted origins`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Could not establish TLS connection
  - Affected: https://insights-ai.info/Home
  - Fix: `Ensure HTTPS is properly configured`
  - Owner: devops
  - ETA: 1d

- [ ] **[MEDIUM]** Missing Content Security Policy
  - Affected: https://insights-ai.info/Home
  - Fix: `Deploy a restrictive, application-specific Content-Security-Policy.`
  - Owner: backend
  - ETA: 1d

## LOW

- [ ] **[LOW]** HSTS missing preload directive
  - Affected: https://insights-ai.info/Home
  - Fix: `Add 'preload' to HSTS header and submit to hstspreload.org`
  - Owner: devops
  - ETA: 1w

- [ ] **[LOW]** Missing Permissions-Policy
  - Affected: https://insights-ai.info/Home
  - Fix: `Add: Permissions-Policy: geolocation=(), microphone=(), camera=()`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Server version disclosure
  - Affected: https://insights-ai.info/Home
  - Fix: `Remove or obfuscate the 'server' header in server config`
  - Owner: devops
  - ETA: 1w


# Browser Observation Report
Engine: http_fallback
Pages visited: 8
Network events: 16
APIs discovered: 0
Console events: 0
WebSockets: 0
Safety pause: none
- [LOW/HIGH] CSP missing or weak with browser-observed script surfaces
- [INFO/POTENTIAL] Potential Client Security Surface
