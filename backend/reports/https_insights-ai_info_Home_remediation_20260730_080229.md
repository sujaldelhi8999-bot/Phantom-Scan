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