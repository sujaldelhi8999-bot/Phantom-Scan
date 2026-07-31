# PhantomScan Report: https://vulturex.in/
**Scan ID:** 69
**Time:** 20260731_162404

## Summary
- Total findings: 13
- MEDIUM: 6
- LOW: 7
- Subdomains: 2
- Open ports: 3
- WAF: None

## Findings
### [MEDIUM] Missing Content Security Policy
- Category: Security Headers
- Endpoint: https://vulturex.in/
- Evidence: No CSP header found
- Impact: XSS and data injection attacks are easier without CSP
- Fix: Add: Content-Security-Policy: default-src 'self'

### [LOW] HSTS missing preload directive
- Category: Security Headers
- Endpoint: https://vulturex.in/
- Evidence: No preload flag in HSTS
- Impact: Browser won't preload HSTS
- Fix: Add 'preload' to HSTS header and submit to hstspreload.org

### [MEDIUM] Missing Clickjacking Protection
- Category: Security Headers
- Endpoint: https://vulturex.in/
- Evidence: No X-Frame-Options or CSP frame-ancestors
- Impact: Page can be embedded in malicious iframes
- Fix: Add: X-Frame-Options: DENY or frame-ancestors 'none'

### [LOW] Missing X-Content-Type-Options
- Category: Security Headers
- Endpoint: https://vulturex.in/
- Evidence: No X-Content-Type-Options: nosniff
- Impact: Browser may MIME-sniff responses, enabling drive-download attacks
- Fix: Add: X-Content-Type-Options: nosniff

### [LOW] Missing Referrer-Policy
- Category: Security Headers
- Endpoint: https://vulturex.in/
- Evidence: No Referrer-Policy header
- Impact: Referrer URL may leak in cross-origin requests
- Fix: Add: Referrer-Policy: strict-origin-when-cross-origin

### [LOW] Missing Permissions-Policy
- Category: Security Headers
- Endpoint: https://vulturex.in/
- Evidence: No Permissions-Policy header
- Impact: Browser features (camera, mic, etc.) unrestricted
- Fix: Add: Permissions-Policy: geolocation=(), microphone=(), camera=()

### [MEDIUM] Could not establish TLS connection
- Category: TLS
- Endpoint: https://vulturex.in/
- Evidence: Failed to connect to vulturex.in:443
- Impact: TLS may not be available
- Fix: Ensure HTTPS is properly configured

### [LOW] Server version disclosure
- Category: Information Disclosure
- Endpoint: https://vulturex.in/
- Evidence: Header 'server: Vercel'
- Impact: Attackers fingerprint stack for targeted exploits
- Fix: Remove or obfuscate the 'server' header in server config

### [LOW] API response permits reads from any origin
- Category: API Security
- Endpoint: https://vulturex.in/
- Evidence: Captured response sets Access-Control-Allow-Origin: *.
- Impact: The policy may expose browser-readable API data to untrusted sites; conforming browsers reject the wildcard/credentials combination but it signals unsafe policy intent.
- Fix: Allow only required trusted origins and enable credentials only for endpoints that need them.

### [MEDIUM] Missing Content Security Policy
- Category: Infrastructure Security
- Endpoint: https://vulturex.in/
- Evidence: No Content-Security-Policy header was captured.
- Impact: Missing browser defense-in-depth controls can increase the impact of a separate content injection or UI-redress weakness.
- Fix: Deploy a restrictive, application-specific Content-Security-Policy.

### [MEDIUM] Missing frame embedding protection
- Category: Infrastructure Security
- Endpoint: https://vulturex.in/
- Evidence: Neither X-Frame-Options nor CSP frame-ancestors was captured.
- Impact: Missing browser defense-in-depth controls can increase the impact of a separate content injection or UI-redress weakness.
- Fix: Set CSP frame-ancestors or X-Frame-Options to the intended embedding policy.

### [LOW] Missing MIME sniffing protection
- Category: Infrastructure Security
- Endpoint: https://vulturex.in/
- Evidence: X-Content-Type-Options: nosniff was not captured.
- Impact: Missing browser defense-in-depth controls can increase the impact of a separate content injection or UI-redress weakness.
- Fix: Send X-Content-Type-Options: nosniff on application responses.

### [MEDIUM] Legacy TLS protocol support reported
- Category: Infrastructure Security
- Endpoint: https://vulturex.in/
- Evidence: Supplied TLS data lists legacy protocol(s): tlsv1.0, tlsv1.1.
- Impact: Legacy protocols expose clients to obsolete cryptography and downgrade risks.
- Fix: Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1; prefer TLS 1.2 and 1.3.


## Remediation Checklist
# PhantomScan Remediation Checklist

## MEDIUM

- [ ] **[MEDIUM]** Missing Content Security Policy
  - Affected: https://vulturex.in/
  - Fix: `Add: Content-Security-Policy: default-src 'self'`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Missing Clickjacking Protection
  - Affected: https://vulturex.in/
  - Fix: `Add: X-Frame-Options: DENY or frame-ancestors 'none'`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Could not establish TLS connection
  - Affected: https://vulturex.in/
  - Fix: `Ensure HTTPS is properly configured`
  - Owner: devops
  - ETA: 1d

- [ ] **[MEDIUM]** Missing Content Security Policy
  - Affected: https://vulturex.in/
  - Fix: `Deploy a restrictive, application-specific Content-Security-Policy.`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Missing frame embedding protection
  - Affected: https://vulturex.in/
  - Fix: `Set CSP frame-ancestors or X-Frame-Options to the intended embedding policy.`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Legacy TLS protocol support reported
  - Affected: https://vulturex.in/
  - Fix: `Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1; prefer TLS 1.2 and 1.3.`
  - Owner: devops
  - ETA: 1d

## LOW

- [ ] **[LOW]** HSTS missing preload directive
  - Affected: https://vulturex.in/
  - Fix: `Add 'preload' to HSTS header and submit to hstspreload.org`
  - Owner: devops
  - ETA: 1w

- [ ] **[LOW]** Missing X-Content-Type-Options
  - Affected: https://vulturex.in/
  - Fix: `Add: X-Content-Type-Options: nosniff`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Missing Referrer-Policy
  - Affected: https://vulturex.in/
  - Fix: `Add: Referrer-Policy: strict-origin-when-cross-origin`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Missing Permissions-Policy
  - Affected: https://vulturex.in/
  - Fix: `Add: Permissions-Policy: geolocation=(), microphone=(), camera=()`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Server version disclosure
  - Affected: https://vulturex.in/
  - Fix: `Remove or obfuscate the 'server' header in server config`
  - Owner: devops
  - ETA: 1w

- [ ] **[LOW]** API response permits reads from any origin
  - Affected: https://vulturex.in/
  - Fix: `Allow only required trusted origins and enable credentials only for endpoints that need them.`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Missing MIME sniffing protection
  - Affected: https://vulturex.in/
  - Fix: `Send X-Content-Type-Options: nosniff on application responses.`
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
- [INFO/POTENTIAL] Potential Client Security Surface
