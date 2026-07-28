# PhantomScan Remediation Checklist

## HIGH

- [ ] **[HIGH]** Target uses cleartext HTTP
  - Affected: http://httpbin.org/
  - Fix: `Serve the application exclusively over HTTPS and redirect cleartext requests.`
  - Owner: backend
  - ETA: 4h

## MEDIUM

- [ ] **[MEDIUM]** Missing Content Security Policy
  - Affected: http://httpbin.org/
  - Fix: `Add: Content-Security-Policy: default-src 'self'`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Missing HTTP Strict Transport Security
  - Affected: http://httpbin.org/
  - Fix: `Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Missing Clickjacking Protection
  - Affected: http://httpbin.org/
  - Fix: `Add: X-Frame-Options: DENY or frame-ancestors 'none'`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Could not establish TLS connection
  - Affected: http://httpbin.org/
  - Fix: `Ensure HTTPS is properly configured`
  - Owner: devops
  - ETA: 1d

- [ ] **[MEDIUM]** Missing Content Security Policy
  - Affected: http://httpbin.org/
  - Fix: `Deploy a restrictive, application-specific Content-Security-Policy.`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Missing frame embedding protection
  - Affected: http://httpbin.org/
  - Fix: `Set CSP frame-ancestors or X-Frame-Options to the intended embedding policy.`
  - Owner: backend
  - ETA: 1d

## LOW

- [ ] **[LOW]** Missing X-Content-Type-Options
  - Affected: http://httpbin.org/
  - Fix: `Add: X-Content-Type-Options: nosniff`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Missing Referrer-Policy
  - Affected: http://httpbin.org/
  - Fix: `Add: Referrer-Policy: strict-origin-when-cross-origin`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Missing Permissions-Policy
  - Affected: http://httpbin.org/
  - Fix: `Add: Permissions-Policy: geolocation=(), microphone=(), camera=()`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Server version disclosure
  - Affected: http://httpbin.org/
  - Fix: `Remove or obfuscate the 'server' header in server config`
  - Owner: devops
  - ETA: 1w

- [ ] **[LOW]** Missing MIME sniffing protection
  - Affected: http://httpbin.org/
  - Fix: `Send X-Content-Type-Options: nosniff on application responses.`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Detailed technology versions disclosed in headers
  - Affected: http://httpbin.org/
  - Fix: `Remove unnecessary product/version headers without relying on obscurity as a primary control.`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Non-production or administrative hostnames discovered
  - Affected: http://httpbin.org/
  - Fix: `Inventory each hostname, retire unused systems, and apply production-equivalent access controls and patching.`
  - Owner: backend
  - ETA: 1w


# Browser Observation Report
Engine: playwright_chromium
Pages visited: 1
Network events: 1
APIs discovered: 0
Console events: 1
WebSockets: 0
Safety pause: none
- [LOW/HIGH] CSP missing or weak with browser-observed script surfaces