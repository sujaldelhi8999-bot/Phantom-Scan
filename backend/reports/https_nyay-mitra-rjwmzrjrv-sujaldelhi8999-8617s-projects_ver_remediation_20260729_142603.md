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