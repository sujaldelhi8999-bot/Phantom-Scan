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