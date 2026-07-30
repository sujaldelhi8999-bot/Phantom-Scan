# PhantomScan Report: https://nyay-mitra-two.vercel.app/
**Scan ID:** 38
**Time:** 20260729_141352

## Summary
- Total findings: 12
- MEDIUM: 5
- LOW: 7
- Subdomains: 41
- Open ports: 3
- WAF: none

## Findings
### [MEDIUM] Missing Content Security Policy
- Category: Security Headers
- Endpoint: https://nyay-mitra-two.vercel.app/
- Evidence: No CSP header found
- Impact: XSS and data injection attacks are easier without CSP
- Fix: Add: Content-Security-Policy: default-src 'self'

### [MEDIUM] Missing Clickjacking Protection
- Category: Security Headers
- Endpoint: https://nyay-mitra-two.vercel.app/
- Evidence: No X-Frame-Options or CSP frame-ancestors
- Impact: Page can be embedded in malicious iframes
- Fix: Add: X-Frame-Options: DENY or frame-ancestors 'none'

### [LOW] Missing X-Content-Type-Options
- Category: Security Headers
- Endpoint: https://nyay-mitra-two.vercel.app/
- Evidence: No X-Content-Type-Options: nosniff
- Impact: Browser may MIME-sniff responses, enabling drive-download attacks
- Fix: Add: X-Content-Type-Options: nosniff

### [LOW] Missing Referrer-Policy
- Category: Security Headers
- Endpoint: https://nyay-mitra-two.vercel.app/
- Evidence: No Referrer-Policy header
- Impact: Referrer URL may leak in cross-origin requests
- Fix: Add: Referrer-Policy: strict-origin-when-cross-origin

### [LOW] Missing Permissions-Policy
- Category: Security Headers
- Endpoint: https://nyay-mitra-two.vercel.app/
- Evidence: No Permissions-Policy header
- Impact: Browser features (camera, mic, etc.) unrestricted
- Fix: Add: Permissions-Policy: geolocation=(), microphone=(), camera=()

### [MEDIUM] Could not establish TLS connection
- Category: TLS
- Endpoint: https://nyay-mitra-two.vercel.app/
- Evidence: Failed to connect to nyay-mitra-two.vercel.app:443
- Impact: TLS may not be available
- Fix: Ensure HTTPS is properly configured

### [LOW] Server version disclosure
- Category: Information Disclosure
- Endpoint: https://nyay-mitra-two.vercel.app/
- Evidence: Header 'server: Vercel'
- Impact: Attackers fingerprint stack for targeted exploits
- Fix: Remove or obfuscate the 'server' header in server config

### [LOW] X-Powered-By disclosure
- Category: Information Disclosure
- Endpoint: https://nyay-mitra-two.vercel.app/
- Evidence: Header 'x-powered-by: Next.js'
- Impact: Attackers fingerprint stack for targeted exploits
- Fix: Remove or obfuscate the 'x-powered-by' header in server config

### [MEDIUM] Missing Content Security Policy
- Category: Infrastructure Security
- Endpoint: https://nyay-mitra-two.vercel.app/
- Evidence: No Content-Security-Policy header was captured.
- Impact: Missing browser defense-in-depth controls can increase the impact of a separate content injection or UI-redress weakness.
- Fix: Deploy a restrictive, application-specific Content-Security-Policy.

### [MEDIUM] Missing frame embedding protection
- Category: Infrastructure Security
- Endpoint: https://nyay-mitra-two.vercel.app/
- Evidence: Neither X-Frame-Options nor CSP frame-ancestors was captured.
- Impact: Missing browser defense-in-depth controls can increase the impact of a separate content injection or UI-redress weakness.
- Fix: Set CSP frame-ancestors or X-Frame-Options to the intended embedding policy.

### [LOW] Missing MIME sniffing protection
- Category: Infrastructure Security
- Endpoint: https://nyay-mitra-two.vercel.app/
- Evidence: X-Content-Type-Options: nosniff was not captured.
- Impact: Missing browser defense-in-depth controls can increase the impact of a separate content injection or UI-redress weakness.
- Fix: Send X-Content-Type-Options: nosniff on application responses.

### [LOW] Non-production or administrative hostnames discovered
- Category: Threat Intelligence
- Endpoint: https://nyay-mitra-two.vercel.app/
- Evidence: Supplied reconnaissance includes sensitive-looking hostname(s): admin.nyay-mitra-two.vercel.app, beta.nyay-mitra-two.vercel.app, dev.nyay-mitra-two.vercel.app, internal.nyay-mitra-two.vercel.app, old.nyay-mitra-two.vercel.app, staging.nyay-mitra-two.vercel.app, test.nyay-mitra-two.vercel.app.
- Impact: Forgotten or less-hardened environments can expand the externally reachable attack surface.
- Fix: Inventory each hostname, retire unused systems, and apply production-equivalent access controls and patching.

## Remediation Checklist
# PhantomScan Remediation Checklist

## MEDIUM

- [ ] **[MEDIUM]** Missing Content Security Policy
  - Affected: https://nyay-mitra-two.vercel.app/
  - Fix: `Add: Content-Security-Policy: default-src 'self'`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Missing Clickjacking Protection
  - Affected: https://nyay-mitra-two.vercel.app/
  - Fix: `Add: X-Frame-Options: DENY or frame-ancestors 'none'`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Could not establish TLS connection
  - Affected: https://nyay-mitra-two.vercel.app/
  - Fix: `Ensure HTTPS is properly configured`
  - Owner: devops
  - ETA: 1d

- [ ] **[MEDIUM]** Missing Content Security Policy
  - Affected: https://nyay-mitra-two.vercel.app/
  - Fix: `Deploy a restrictive, application-specific Content-Security-Policy.`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Missing frame embedding protection
  - Affected: https://nyay-mitra-two.vercel.app/
  - Fix: `Set CSP frame-ancestors or X-Frame-Options to the intended embedding policy.`
  - Owner: backend
  - ETA: 1d

## LOW

- [ ] **[LOW]** Missing X-Content-Type-Options
  - Affected: https://nyay-mitra-two.vercel.app/
  - Fix: `Add: X-Content-Type-Options: nosniff`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Missing Referrer-Policy
  - Affected: https://nyay-mitra-two.vercel.app/
  - Fix: `Add: Referrer-Policy: strict-origin-when-cross-origin`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Missing Permissions-Policy
  - Affected: https://nyay-mitra-two.vercel.app/
  - Fix: `Add: Permissions-Policy: geolocation=(), microphone=(), camera=()`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Server version disclosure
  - Affected: https://nyay-mitra-two.vercel.app/
  - Fix: `Remove or obfuscate the 'server' header in server config`
  - Owner: devops
  - ETA: 1w

- [ ] **[LOW]** X-Powered-By disclosure
  - Affected: https://nyay-mitra-two.vercel.app/
  - Fix: `Remove or obfuscate the 'x-powered-by' header in server config`
  - Owner: devops
  - ETA: 1w

- [ ] **[LOW]** Missing MIME sniffing protection
  - Affected: https://nyay-mitra-two.vercel.app/
  - Fix: `Send X-Content-Type-Options: nosniff on application responses.`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Non-production or administrative hostnames discovered
  - Affected: https://nyay-mitra-two.vercel.app/
  - Fix: `Inventory each hostname, retire unused systems, and apply production-equivalent access controls and patching.`
  - Owner: backend
  - ETA: 1w


# Browser Observation Report
Engine: http_fallback
Pages visited: 4
Network events: 65
APIs discovered: 0
Console events: 0
WebSockets: 0
Safety pause: none
- [LOW/HIGH] CSP missing or weak with browser-observed script surfaces
- [INFO/MEDIUM] Potential Client Security Surface
