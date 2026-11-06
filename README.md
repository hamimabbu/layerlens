# LayerLens

**Your connection, explained.** A standalone visitor-controlled browser and network evidence lab.

> You haven't introduced yourself. What can an ordinary connection still reveal?

LayerLens is a working research prototype with an original interface, collection workflow, evidence model and privacy receipt. It uses selected native browser APIs and a small dependency-free Node service. An optional Linux Fingerproxy ingress adds real JA3, JA4 and HTTP/2 evidence. Public DNS, registry and historical-IP checks require both operator configuration and a visitor's explicit choice.

![LayerLens sample dashboard](docs/preview-desktop.png)

## Run locally

Requires Node.js 22 or newer. No package installation or API key is needed for the core app.

```sh
npm start
```

Open **http://127.0.0.1:8787**.

```sh
npm run check
npm test
```

The default server binds to loopback. The sample works without any external lookup. Browser checks remain in the tab; the configuration request contains deployment policy, not a request to enrich the visitor.

## What works

| Feature | Status / source |
| --- | --- |
| Labelled sample exploration | Implemented; synthetic fixtures and reserved example addresses |
| Selected browser settings | Implemented; native APIs, computed locally after a click |
| Optional coarse hardware hints | Implemented; browser-reported, unsupported values remain unavailable |
| Optional local attribute pattern | Implemented; SHA-256 over selected values, never presented as a unique person |
| Connection report | Implemented; socket address or explicitly trusted ingress |
| Privacy receipt and reset | Implemented; tab results, actual selected checks and recipient notes |
| Previewable redacted JSON export | Implemented; remaining combinations can still be identifying |
| PTR / RDAP / InternetDB adapters | Implemented, disabled by default; live third-party queries have not been benchmarked or accuracy-tested |
| Separate Fingerproxy diagnostic endpoint | Adapter and consent flow implemented; real TLS deployment requires the setup below |
| p0f sensor / packet capture | Research extension only; not installed, run or advertised as working |

Unavailable TLS evidence is **not fabricated**. In direct local HTTP mode, the app shows its application-side connection and explicitly says that transport fingerprints need a configured ingress.

## Linux deployment

```sh
docker compose up --build
```

The container runs as a non-root user with a read-only filesystem and dropped capabilities. The published port is loopback-only. Add a correctly configured HTTPS ingress for a public deployment. Docker has not been available in the development environment, so this deployment needs verification on your Linux host before publication.

To enable chosen public-record sources, copy `.env.example` to `.env` and configure the relevant settings. Docker Compose reads `.env`; for direct Node use:

```sh
node --env-file=.env server/index.mjs
```

`ENABLE_EXTERNAL_LOOKUPS=true` enables the operator side of the gate. PTR additionally needs explicit `DNS_RESOLVERS`. InternetDB additionally needs `ENABLE_INTERNETDB=true`; it is documented as free for noncommercial use. The visitor must then choose a configured source and approve its recipient in the interface. Nothing scans their services.

Local/private/reserved addresses are rejected **before** any external lookup. An empty provider result is not proof of safety.

## Real transport evidence with Fingerproxy

See [the integration guide](docs/TRANSPORT.md). We selected [wi1dcard/fingerproxy](https://github.com/wi1dcard/fingerproxy), Apache-2.0, because it provides a Go TLS ingress and structured fingerprint headers. The inspected release was v1.2.3; review dependencies and current upstream advisories before deployment.

Use a **dedicated first-party diagnostic hostname** with valid HTTPS. Do not route ordinary visitors through a capture experiment before they choose it. The main app requests the diagnostic endpoint only after its separate button is pressed, with browser cookies omitted.

Only explicitly trusted proxy peer addresses can supply fingerprints. A terminating CDN in front of the diagnostic host changes the observed client; a forwarded IP cannot reconstruct the original TCP/TLS handshake.

## What makes the project ours

- A consistent evidence record with source, subject, assertion type, limitations and timestamps.
- A clear sample/local/connection/public-record separation.
- An explicit preflight choice and a receipt for each selected check.
- A separate, opt-in transport observation path with trusted-source validation.
- Careful handling of shared IPs, missing data, private addresses, malformed sources and redacted exports.
- An original accessible interface and a reproducible security test suite.

Research references and integrated components are credited in [SOURCES.md](docs/SOURCES.md). This repository is not a claim to have invented fingerprinting, DNS or the integrated upstream tools.

## Repository

```text
public/                 Interface and native browser collectors
server/index.mjs        API, consent gates, trusted ingress and short-lived quotas
server/evidence.mjs     IP classification, evidence records, redaction helpers
server/collectors.mjs   Constrained PTR, RDAP and InternetDB adapters
tests/                  Security and integration tests using local fixtures
docs/                   Architecture, threat model, sources and transport setup
compose.yaml            Linux container deployment
```

## Verification and limits

Automated checks cover IP parsing, mapped IPv6, reserved ranges, trusted forwarding, fingerprint validation, RDAP destination selection, HTTP response limits, redaction, consent, same-origin policy, disabled collectors, local-address rejection and API quotas. Browser verification is recorded in `docs/VALIDATION.md`.

No results database, analytics SDK, cookies or persistent browser identifiers are included. Ordinary hosting still sees request IPs/headers; configure proxy, hosting and security logs separately. Hashed rate counters live for at most 61 seconds. Reset clears the tab's results, not records already held by another provider. This is a prototype, not a security audit or a promise of absolute privacy.

The app cannot infer a person's real name, email, employer or private computer name from an ordinary visit. A PTR record is not a PC name. An OS guess is not a verified inventory. A CVE association indexed for a shared exit IP is not a diagnosis of the visitor's laptop.

## GitHub

The source is ready to put in a new repository. Keep `.env`, certificates, private keys, packet captures and logs out of Git. This project has **not** been published to a GitHub account automatically.

## Licence

Original LayerLens code: MIT. Optional tools and datasets retain their separate upstream licences and terms. Preserve their licences/notices if you distribute their binaries or adapted code.
