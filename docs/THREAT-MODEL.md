# Threat model

**Assets:** private per-tab results, connection address, optional provider queries, trusted ingress metadata, operator configuration and service availability.

**Trust boundaries:** browser -> application; optional browser -> diagnostic ingress -> application; application -> resolver/registry/optional InternetDB. Source data is untrusted even when it comes from an approved provider.

| Risk | Implemented control | Remaining validation |
| --- | --- | --- |
| Arbitrary-target proxy / SSRF | Server derives the subject; request targets rejected; public-IP gate; fixed registry host allowlist; redirects rejected | Review updated registry endpoints and DNS transport in deployment |
| Forwarded-header spoofing | Exact trusted peers; rightmost address only for a single approved ingress; fingerprints ignored otherwise | Verify real Fingerproxy overwrites client-supplied fingerprint headers |
| XSS through PTR/registry strings | UI uses textContent/createTextNode, no dynamic HTML; CSP and no remote scripts; the page checks and trims server answers before showing them | Hostile fixture values were tested in headless Chromium. Other browsers are untested |
| Unexpected external disclosure | Operator flag plus visitor approval; default disabled; configured resolver named; receipts | Audit actual hosting/proxy/provider recipients and logs |
| Cross-visitor data leakage | No results database; personalized responses no-store; per-request state | Deployment cache and ingress tests |
| Resource exhaustion | Body cap (4 KB), response cap, lookup timeouts, low query count, ephemeral HMAC quota per visitor (IPv6 counted per /64, at most 2,000 visitors tracked), requests still unfinished after 10 seconds are closed | Distributed abuse, connection counts and bandwidth need ingress controls. A full visitor table refuses new visitors until entries expire, which is a deliberate trade-off |
| DNS rebinding against a local copy | The server does not check the Host header, so reverse proxies that rewrite it keep working. The API serves public files and reports only on the caller's own connection | A rebinding page could call the local API but learns nothing private. Add a Host allow-list before this app serves anything private |
| Sensitive exports | Preview and default identifier redaction | Redaction does not guarantee anonymity; manual preview remains important |
| Overconfident attribution | Source/subject/limits visible; unknowns remain missing | No measured accuracy or uniqueness claim |

An operator deliberately deploying malicious modifications is outside the protections of this code. Source availability does not establish safety. Do not advertise absolute security, anonymous IP data, zero infrastructure logging or a complete view of all browser traffic.
