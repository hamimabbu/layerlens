# Validation record

## Verified locally

- Node.js syntax checks pass.
- Automated unit/integration tests pass on the development Windows host with local-network permission.
- The expanded 20-test suite passes locally on Node.js 26.13.0. It adds lookup-name validation, JSON media type validation, InternetDB fixture parsing, shared browser/server redaction and the browser module route. CI also targets Node.js 22 and 24; consult the latest run for those results.
- The same 15 tests and syntax checks passed on GitHub Actions' Ubuntu runner: [initial source verification](https://github.com/hamimabbu/layerlens/actions/runs/42315502843).
- Test requests use local servers and synthetic fixtures; the suite does not call public lookup providers or scan real visitors.

## Browser verification

Checked with the available Chromium automation browser on 7 November 2026:

- Initial resources came only from the local first-party origin.
- Sample mode produced four labelled browser findings and three sample connection findings without a lookup.
- A live local browser check produced six findings and one local-only receipt.
- The export dialog opened with selected values redacted before download.
- External controls were disabled by the default server policy.
- No horizontal overflow at a 390px mobile viewport.
- No browser console errors or warnings during this pass.
- Desktop and mobile sample screenshots: `preview-desktop.png`, `preview-mobile.png`.

These are limited prototype checks, not a guarantee about all browsers or production infrastructure.

The fixes were checked again on 7 November 2026 using a temporary headless Chromium browser and the real local API:

- Sample mode, reset, the six-field browser check and the connection check completed.
- Export previews redacted the browser and connection address values.
- Optional lookup controls remained disabled under the default configuration. No requests left the local origin.
- A connection view selected before a delayed configuration response showed the transport choice after the configuration arrived.
- The 390px viewport had no horizontal overflow, and no browser console errors were reported.

The DNS resolver export cases use local IPv4/IPv6 fixtures in the automated suite; no resolver query was needed for those checks.

## Not verified here

- Docker image/Compose execution: Docker is not installed locally; WSL access was unavailable. The Node core was separately verified on the GitHub Actions Linux runner.
- Real Fingerproxy TLS handshakes and upstream dependency compatibility.
- p0f packet capture (not implemented).
- Live DNS/RDAP/InternetDB accuracy, speed or availability. Defaults remain disabled.
- Real Safari/mobile browsers and production hosting log retention.

No private keys, packet captures, raw visitor logs or third-party API credentials belong in the repository.
