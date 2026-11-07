# Test record

Checked on 7 November 2026.

## Automated tests

All 20 tests and the JavaScript syntax checks pass locally on Windows with Node.js 26.13.0. The same suite passed on GitHub's Linux runner with Node.js 22 and 24: [test run](https://github.com/hamimabbu/layerlens/actions/runs/42325275966).

The tests cover address parsing, trusted forwarding and fingerprint headers, RDAP destinations, HTTP response limits, lookup selection, consent, content types, quotas and export redaction. IPv4 and IPv6 DNS resolver cases use fixtures. InternetDB parsing uses a mocked response.

Test requests stay on local servers. The suite does not query public lookup providers or scan real visitors.

The earlier 15-test version also passed on Linux: [initial run](https://github.com/hamimabbu/layerlens/actions/runs/42315502843).

## Browser checks

A headless Chromium check used the real local API and covered:

- Sample mode with four browser findings and three connection findings.
- Reset, followed by a six-field browser check and a local receipt.
- The connection check and redacted export preview.
- Disabled public-record controls under the default configuration.
- A delayed configuration response arriving after the connection view was selected.
- A 390px viewport, with no horizontal overflow.

No requests left the local origin, and no browser console errors were reported. The sample screenshots are [desktop](preview-desktop.png) and [mobile](preview-mobile.png).

These checks cover the local prototype, not every browser or deployment.

## Still to test

- Docker and Compose execution. Docker was not installed on the test host, and WSL was unavailable.
- Real Fingerproxy TLS handshakes, header replacement and dependency compatibility.
- Live DNS, RDAP and InternetDB accuracy, speed and availability.
- Safari, physical mobile devices and production hosting logs.

p0f capture is not implemented. Private keys, raw visitor logs, captures and API credentials should stay out of this repository.
