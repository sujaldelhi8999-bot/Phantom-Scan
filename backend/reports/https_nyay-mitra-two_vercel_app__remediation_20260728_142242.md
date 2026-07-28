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
Engine: playwright_chromium
Pages visited: 1
Network events: 35
APIs discovered: 0
Console events: 0
WebSockets: 0
Safety pause: none
- [LOW/HIGH] CSP missing or weak with browser-observed script surfaces
- [MEDIUM/HIGH] Browser-observed cookie lacks hardened attributes
- [INFO/POTENTIAL] Potential Client Security Surface