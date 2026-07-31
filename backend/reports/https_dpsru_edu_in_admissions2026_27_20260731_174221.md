# PhantomScan Report: https://dpsru.edu.in/admissions2026_27
**Scan ID:** 103
**Time:** 20260731_174221

## Summary
- Total findings: 7
- HIGH: 1
- MEDIUM: 3
- LOW: 3
- Subdomains: 3
- Open ports: 6
- WAF: cloudflare

## Findings
### [HIGH] CSP allows unsafe-inline scripts
- Category: Security Headers
- Endpoint: https://dpsru.edu.in/admissions2026_27
- Evidence: script-src includes 'unsafe-inline'
- Impact: Bypasses CSP protection against XSS
- Fix: Remove 'unsafe-inline' from script-src; use nonces or hashes

### [LOW] HSTS missing preload directive
- Category: Security Headers
- Endpoint: https://dpsru.edu.in/admissions2026_27
- Evidence: No preload flag in HSTS
- Impact: Browser won't preload HSTS
- Fix: Add 'preload' to HSTS header and submit to hstspreload.org

### [MEDIUM] Could not establish TLS connection
- Category: TLS
- Endpoint: https://dpsru.edu.in/admissions2026_27
- Evidence: Failed to connect to dpsru.edu.in:443
- Impact: TLS may not be available
- Fix: Ensure HTTPS is properly configured

### [LOW] Server version disclosure
- Category: Information Disclosure
- Endpoint: https://dpsru.edu.in/admissions2026_27
- Evidence: Header 'server: cloudflare'
- Impact: Attackers fingerprint stack for targeted exploits
- Fix: Remove or obfuscate the 'server' header in server config

### [MEDIUM] Content Security Policy permits unsafe script execution
- Category: Infrastructure Security
- Endpoint: https://dpsru.edu.in/admissions2026_27
- Evidence: The captured CSP script policy includes unsafe-inline or unsafe-eval; nonce and hash values are omitted from evidence.
- Impact: The policy provides reduced protection if attacker-controlled script or markup reaches the page.
- Fix: Remove unsafe-eval and migrate inline scripts to nonces or hashes with narrowly scoped sources.

### [MEDIUM] Legacy TLS protocol support reported
- Category: Infrastructure Security
- Endpoint: https://dpsru.edu.in/admissions2026_27
- Evidence: Supplied TLS data lists legacy protocol(s): tlsv1.0, tlsv1.1.
- Impact: Legacy protocols expose clients to obsolete cryptography and downgrade risks.
- Fix: Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1; prefer TLS 1.2 and 1.3.

### [LOW] Non-production or administrative hostnames discovered
- Category: Threat Intelligence
- Endpoint: https://dpsru.edu.in/admissions2026_27
- Evidence: Supplied reconnaissance includes sensitive-looking hostname(s): admin.dpsru.edu.in.
- Impact: Forgotten or less-hardened environments can expand the externally reachable attack surface.
- Fix: Inventory each hostname, retire unused systems, and apply production-equivalent access controls and patching.


## Remediation Checklist
# PhantomScan Remediation Checklist

## HIGH

- [ ] **[HIGH]** CSP allows unsafe-inline scripts
  - Affected: https://dpsru.edu.in/admissions2026_27
  - Fix: `Remove 'unsafe-inline' from script-src; use nonces or hashes`
  - Owner: frontend
  - ETA: 4h

## MEDIUM

- [ ] **[MEDIUM]** Could not establish TLS connection
  - Affected: https://dpsru.edu.in/admissions2026_27
  - Fix: `Ensure HTTPS is properly configured`
  - Owner: devops
  - ETA: 1d

- [ ] **[MEDIUM]** Content Security Policy permits unsafe script execution
  - Affected: https://dpsru.edu.in/admissions2026_27
  - Fix: `Remove unsafe-eval and migrate inline scripts to nonces or hashes with narrowly scoped sources.`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Legacy TLS protocol support reported
  - Affected: https://dpsru.edu.in/admissions2026_27
  - Fix: `Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1; prefer TLS 1.2 and 1.3.`
  - Owner: devops
  - ETA: 1d

## LOW

- [ ] **[LOW]** HSTS missing preload directive
  - Affected: https://dpsru.edu.in/admissions2026_27
  - Fix: `Add 'preload' to HSTS header and submit to hstspreload.org`
  - Owner: devops
  - ETA: 1w

- [ ] **[LOW]** Server version disclosure
  - Affected: https://dpsru.edu.in/admissions2026_27
  - Fix: `Remove or obfuscate the 'server' header in server config`
  - Owner: devops
  - ETA: 1w

- [ ] **[LOW]** Non-production or administrative hostnames discovered
  - Affected: https://dpsru.edu.in/admissions2026_27
  - Fix: `Inventory each hostname, retire unused systems, and apply production-equivalent access controls and patching.`
  - Owner: backend
  - ETA: 1w


# Browser Observation Report
Engine: http_fallback
Pages visited: 1
Network events: 2
APIs discovered: 0
Console events: 0
WebSockets: 0
Safety pause: none
- [LOW/HIGH] CSP missing or weak with browser-observed script surfaces
- [INFO/MEDIUM] Potential Client Security Surface
