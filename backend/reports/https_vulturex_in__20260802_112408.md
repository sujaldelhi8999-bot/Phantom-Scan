# PhantomScan Report: https://vulturex.in/
**Scan ID:** 124
**Time:** 20260802_112408

## Summary
- Total findings: 15
- MEDIUM: 6
- LOW: 8
- INFO: 1
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

### [MEDIUM] Missing Cross-Origin-Embedder-Policy
- Category: Security Headers
- Endpoint: https://vulturex.in/
- Evidence: No COEP header
- Impact: Page is not isolated from cross-origin embeddings; Spectre/Meltdown mitigations are weakened
- Fix: Add: Cross-Origin-Embedder-Policy: require-corp

### [MEDIUM] Missing Cross-Origin-Opener-Policy
- Category: Security Headers
- Endpoint: https://vulturex.in/
- Evidence: No COOP header
- Impact: Top-level navigations can open the page in a pop-up window and access it via window.opener
- Fix: Add: Cross-Origin-Opener-Policy: same-origin

### [LOW] Missing Cross-Origin-Resource-Policy
- Category: Security Headers
- Endpoint: https://vulturex.in/
- Evidence: No CORP header
- Impact: Cross-origin requests can load the resource, enabling data exfiltration
- Fix: Add: Cross-Origin-Resource-Policy: same-origin

### [LOW] Missing Origin-Agent-Cluster
- Category: Security Headers
- Endpoint: https://vulturex.in/
- Evidence: No OAC header
- Impact: The page is not isolated in its own agent cluster; cross-origin attacks may affect it
- Fix: Add: Origin-Agent-Cluster: ?1

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

### [LOW] CSP missing or weak with browser-observed script surfaces
- Category: CSP
- Endpoint: https://vulturex.in/
- Evidence: CSP status: missing. Weaknesses: CSP header missing. Related observations: {"external_script_origins": ["www.googletagmanager.com"], "inline_script_blocks": 0, "user_controlled_inputs": 0, "api_calls": 0, "console_errors": 1, "javascript_sinks": ["DOM insertion", "HTML rendering", "URL assignment", "navigation", "storage usage"], "previous_related_findings": 0}
- Impact: Weak CSP increases the impact of client-side injection and third-party script compromise.
- Fix: Deploy a restrictive CSP including script-src, object-src 'none', base-uri, frame-ancestors, and form-action.

### [MEDIUM] Browser-observed cookie lacks hardened attributes
- Category: Cookie Security
- Endpoint: https://vulturex.in/
- Evidence: Cookie _ga_8W44EEGKPF flags: Secure=False, HttpOnly=False, SameSite=Lax. Related observations: {"external_script_origins": ["www.googletagmanager.com"], "inline_script_blocks": 0, "user_controlled_inputs": 0, "api_calls": 0, "console_errors": 1, "javascript_sinks": ["DOM insertion", "HTML rendering", "URL assignment", "navigation", "storage usage"], "previous_related_findings": 0}
- Impact: Weak cookie flags can expose sessions to script access, cross-site requests, or cleartext transport.
- Fix: Set Secure, HttpOnly, and SameSite on session cookies and scope Domain/Path narrowly.

### [INFO] Potential Client Security Surface
- Category: Client-Side Dataflow
- Endpoint: https://vulturex.in/
- Evidence: Statically observed JavaScript sink categories: DOM insertion, HTML rendering, URL assignment, navigation, storage usage. Related observations: {"external_script_origins": ["www.googletagmanager.com"], "inline_script_blocks": 0, "user_controlled_inputs": 0, "api_calls": 0, "console_errors": 1, "javascript_sinks": ["DOM insertion", "HTML rendering", "URL assignment", "navigation", "storage usage"], "previous_related_findings": 0}
- Impact: These patterns are not vulnerabilities by themselves but should be prioritized for output encoding and navigation review.
- Fix: Review the identified client-side sinks and ensure user-controlled data is encoded or validated before use.


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

- [ ] **[MEDIUM]** Missing Cross-Origin-Embedder-Policy
  - Affected: https://vulturex.in/
  - Fix: `Add: Cross-Origin-Embedder-Policy: require-corp`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Missing Cross-Origin-Opener-Policy
  - Affected: https://vulturex.in/
  - Fix: `Add: Cross-Origin-Opener-Policy: same-origin`
  - Owner: backend
  - ETA: 1d

- [ ] **[MEDIUM]** Could not establish TLS connection
  - Affected: https://vulturex.in/
  - Fix: `Ensure HTTPS is properly configured`
  - Owner: devops
  - ETA: 1d

- [ ] **[MEDIUM]** Browser-observed cookie lacks hardened attributes
  - Affected: https://vulturex.in/
  - Fix: `Set Secure, HttpOnly, and SameSite on session cookies and scope Domain/Path narrowly.`
  - Owner: backend
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

- [ ] **[LOW]** Missing Cross-Origin-Resource-Policy
  - Affected: https://vulturex.in/
  - Fix: `Add: Cross-Origin-Resource-Policy: same-origin`
  - Owner: devops
  - ETA: 1w

- [ ] **[LOW]** Missing Origin-Agent-Cluster
  - Affected: https://vulturex.in/
  - Fix: `Add: Origin-Agent-Cluster: ?1`
  - Owner: backend
  - ETA: 1w

- [ ] **[LOW]** Server version disclosure
  - Affected: https://vulturex.in/
  - Fix: `Remove or obfuscate the 'server' header in server config`
  - Owner: devops
  - ETA: 1w

- [ ] **[LOW]** CSP missing or weak with browser-observed script surfaces
  - Affected: https://vulturex.in/
  - Fix: `Deploy a restrictive CSP including script-src, object-src 'none', base-uri, frame-ancestors, and form-action.`
  - Owner: frontend
  - ETA: 1w

## INFO

- [ ] **[INFO]** Potential Client Security Surface
  - Affected: https://vulturex.in/
  - Fix: `Review the identified client-side sinks and ensure user-controlled data is encoded or validated before use.`
  - Owner: backend
  - ETA: 1w


# Browser Observation Report
Engine: playwright_chromium
Pages visited: 1
Network events: 12
APIs discovered: 0
Console events: 1
WebSockets: 0
Safety pause: none
- [LOW/HIGH] CSP missing or weak with browser-observed script surfaces
- [MEDIUM/HIGH] Browser-observed cookie lacks hardened attributes
- [INFO/MEDIUM] Potential Client Security Surface
