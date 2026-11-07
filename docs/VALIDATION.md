# Test record

This file records two passes, both on 7 November 2026. The second pass describes the current code.

## First pass

### Automated tests

All 20 tests and the JavaScript syntax checks passed locally on Windows with Node.js 26.13.0. The same suite passed on GitHub's Linux runner with Node.js 22 and 24: [test run](https://github.com/hamimabbu/layerlens/actions/runs/42325275966).

The tests covered address parsing, trusted forwarding and fingerprint headers, RDAP destinations, HTTP response limits, lookup selection, consent, content types, quotas and export redaction. IPv4 and IPv6 DNS resolver cases use fixtures. InternetDB parsing uses a mocked response.

Test requests stay on local servers. The suite does not query public lookup providers or scan real visitors.

The earlier 15-test version also passed on Linux: [initial run](https://github.com/hamimabbu/layerlens/actions/runs/42315502843).

### Browser checks

A headless Chromium check used the real local API and covered:

- Sample mode with four browser findings and three connection findings.
- Reset, followed by a six-field browser check and a local receipt.
- The connection check and redacted export preview.
- Disabled public-record controls under the default configuration.
- A delayed configuration response arriving after the connection view was selected.
- A 390px viewport, with no horizontal overflow.

No requests left the local origin, and no browser console errors were reported.

## Second pass

A second review added tests, fixed the problems it found and checked the page again in a browser. It ran on Linux with Node.js 22.23.4. It has not been run on Windows.

### Automated tests

`npm test` now runs 62 tests: the first 20, 33 in `tests/behaviour.test.mjs` and 9 in `tests/page-modules.test.mjs`. They cover:

- Every route and method, HEAD requests, and the security headers on every kind of response.
- Request size and content type rules, and requests that try to name their own target.
- The per-visitor allowance (IPv6 counted per /64, checked with a mocked clock), the visitor table limit, and a connection that never finishes its request.
- Address classification, using boundary addresses from the IANA special-purpose registries.
- PTR lookups against a local fake DNS server, including a resolver that is down.
- Failing and slow lookup sources, redirects, and the media type sent to RDAP servers.
- The environment settings, the start-up messages, and the `.env.example` and `compose.yaml` files.
- The page modules: unreadable server answers, finding rows and the sample data.

Eighteen deliberate breakages (for example reading the file after sending the header, dropping the /64 grouping, or removing a reserved range) were put into temporary copies of the code one at a time. The tests failed for every one. That script is not in the repository.

### Checks run outside the repository

These scripts are not committed, so the results below are a record and not something the repository can reproduce. The browser script uses Playwright, which the zero-dependency repository does not include.

- Attack script: 180 checks against local servers, covering odd paths and methods, oversized and malformed bodies, wrong content types, spoofed forwarding and fingerprint headers, cross-origin requests, local and reserved addresses, 300 parallel requests against the allowance, and a deployment with a missing file. All passed. Fifteen notes record behaviour that is intended or a known trade-off, such as a full visitor table refusing new visitors until entries expire.
- Browser script: 96 checks in headless Chromium, all passed. They cover first load, sample mode, the browser check, the connection check, the default (disabled) public-record controls, enabled sources with mocked answers, failures and request races, hostile values in server answers, malformed answers, the transport diagnostic with a mocked endpoint, layout, text size, keyboard use and an axe-core accessibility scan. Axe reported no violations. Contrast items it could not decide on its own, such as text over gradients and over the blurred dialog backdrop, were measured from rendered pixels instead.
- Contrast: 1,101 text items were measured from the rendered pixels behind them, in seven states (including open details, the privacy dialog and the export preview) at 390 and 1440 px. None was below WCAG AA (4.5:1, or 3:1 for large text).
- Layout: 320, 360, 390, 768, 1024 and 1440 px, in the start, sample, records and privacy states. No horizontal scrolling and no clipped text. The only elements reaching past the screen edge were two decorative rings that are meant to be cut off.

The sample screenshots are [desktop](preview-desktop.png) and [mobile](preview-mobile.png).

### Container

The Compose setup was built and run with Docker Engine 29.9.2 on Linux.

- `docker compose build` and `docker compose up -d` worked, and the port was published on 127.0.0.1 only.
- The process ran as user `node` with no capabilities and `no-new-privileges` set. The root filesystem was read-only, and writes to `/app` and `/tmp` failed.
- Every page and module was served with the right content type, and the healthcheck turned healthy.
- Settings passed through Compose reached the app: `TRANSPORT_ORIGIN` and `APP_ORIGIN` (visible in `/api/config` and the CSP), `TRUSTED_PROXY_IPS` (a forwarded address was accepted from the trusted bridge address), `ENABLE_EXTERNAL_LOOKUPS` and `DNS_RESOLVERS`.
- `docker stop` finished in under a second with exit code 0. A wrong `TRANSPORT_ORIGIN` printed one clear line in the logs.

This was one run on one host.

### Live lookups

RDAP and InternetDB were run once against the live services from the test host, using well-known public addresses: Cloudflare and Google DNS, the RIPE NCC k-root, an AFRINIC address and three LACNIC addresses. Registry answers parsed correctly for ARIN, RIPE NCC, APNIC, AFRINIC and LACNIC, over IPv4 and IPv6. InternetDB returned parsed records for addresses it knows and a "no record" answer for addresses it does not.

This found the LACNIC problem listed below. Ranges that LACNIC hands to a national registry, such as NIC.br in Brazil, are redirected there. The app does not follow redirects and now says so.

Reverse DNS could not be checked live. The test host's DNS answered "not found" for the reverse records of well-known addresses, so PTR is covered only by the local fake DNS server tests.

This was a handful of requests. It is not a measurement of accuracy or availability.

### What changed

Server:

- A missing public file now returns a 500 error. It used to send an empty 200 response.
- HEAD requests are served, and a known path with the wrong method returns 405 with an `Allow` header. Both returned 404 before.
- Requests that stay unfinished are closed after about 10 seconds. The timeouts were already set, but Node only checks them every 30 seconds by default, so the check interval is now 1 second.
- IPv6 visitors share one allowance per /64 range. Before, a visitor could get a fresh allowance by changing the end of the address. The visitor table holds at most 2,000 entries.
- Address classification follows the IANA special-purpose registries. The old list treated some ranges as public, including Teredo, benchmarking, the 3fff documentation prefix and the 6to4 relay range.
- A resolver that is down is reported as unavailable. Node's `reverse()` reports an unreachable server as "not found", so the lookup now uses `resolvePtr`.
- RDAP requests ask for `application/rdap+json`. LACNIC answers plain `application/json` with a 406, so every lookup for Latin American addresses failed.
- A wrong `PORT` or `TRANSPORT_ORIGIN` stops the program with one clear line, not a stack trace.

Page:

- An answer with the wrong shape, an odd value or hostile text ends in a short message or an "unavailable" card. Raw parser messages are no longer shown.
- Smooth scrolling respects the reduced-motion setting in script as well as in CSS.
- Text is no smaller than 11px. Many styles were 6 to 10px before. Low-contrast colours were raised, and the sidebar and small-screen layout were adjusted so nothing overflows or is cut off.

Configuration:

- `.env.example` no longer lists a setting the server never reads. A test keeps the file and the code in line.
- `compose.yaml` passes every documented setting to the container. Before, `TRUSTED_PROXY_IPS`, `TRUSTED_PROXY_HOST`, `APP_ORIGIN` and `TRANSPORT_ORIGIN` were silently ignored under Compose.

## Still to test

- Docker Desktop on Windows and macOS, and the container behind HTTPS and a real reverse proxy.
- Real Fingerproxy TLS handshakes, header replacement and dependency compatibility.
- Live reverse DNS, and the accuracy, speed and availability of DNS, RDAP and InternetDB over time.
- Firefox, Safari, physical mobile devices and production hosting logs.
- Use with a real screen reader. Only automated accessibility checks were run.

p0f capture is not implemented. Private keys, raw visitor logs, captures and API credentials should stay out of this repository.
