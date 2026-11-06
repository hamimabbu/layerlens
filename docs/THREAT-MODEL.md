# Threat model

**Assets:** private per-tab results, connection address, optional provider queries, trusted ingress metadata, operator configuration and service availability.

**Trust boundaries:** browser -> application; optional browser -> diagnostic ingress -> application; application -> resolver/registry/optional InternetDB. Source data is untrusted even when it comes from an approved provider.

| Risk | Implemented control | Remaining validation |
| --- | --- | --- |
| Arbitrary-target proxy / SSRF | Server derives the subject; request targets rejected; public-IP gate; fixed registry host allowlist; redirects rejected | Review updated registry endpoints and DNS transport in deployment |
| Forwarded-header spoofing | Exact trusted peers; rightmost address only for a single approved ingress; fingerprints ignored otherwise | Verify real Fingerproxy overwrites client-supplied fingerprint headers |
| XSS through PTR/registry strings | UI uses textContent/createTextNode, no dynamic HTML; CSP and no remote scripts | Browser tests with hostile fixture values |
| Unexpected external disclosure | Operator flag plus visitor approval; default disabled; configured resolver named; receipts | Audit actual hosting/proxy/provider recipients and logs |
| Cross-visitor data leakage | No results database; personalized responses no-store; per-request state | Deployment cache and ingress tests |
| Resource exhaustion | Body cap, response cap, timeouts, low query count, ephemeral per-IP HMAC quota | Distributed abuse and slow connection limits require ingress controls |
| Sensitive exports | Preview and default identifier redaction | Redaction does not guarantee anonymity; manual preview remains important |
| Overconfident attribution | Source/subject/limits visible; unknowns remain missing | No measured accuracy or uniqueness claim |

An operator deliberately deploying malicious modifications is outside the protections of this code. Source availability does not establish safety. Do not advertise absolute security, anonymous IP data, zero infrastructure logging or a complete view of all browser traffic.
