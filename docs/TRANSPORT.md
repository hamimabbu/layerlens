# Optional transport diagnostic

The core app works without TLS fingerprinting. This guide describes the optional Linux integration; real Fingerproxy operation was not tested on the development host.

## Components

- Main app: Node 22+, bound to `127.0.0.1:8787` in a same-host setup.
- Dedicated diagnostic ingress: [Fingerproxy](https://github.com/wi1dcard/fingerproxy), inspected release **v1.2.3**, Apache-2.0.
- A distinct first-party diagnostic hostname with a valid certificate. Do not use a public self-signed certificate or ask visitors to bypass warnings.

Review the upstream release, checksums, dependencies, LICENSE and NOTICE before installation. No binary is bundled or downloaded automatically by LayerLens.

## Configuration

```text
APP_ORIGIN=https://lab.your-domain.example
TRANSPORT_ORIGIN=https://transport.your-domain.example
TRUSTED_PROXY_IPS=127.0.0.1
```

Use the proxy's exact peer address, not its client address. A separate container may need a carefully controlled internal peer; `TRUSTED_PROXY_HOST` can resolve a dedicated internal service. Never trust the whole internet or accept a visitor-supplied proxy list.

The upstream documented invocation is:

```sh
./fingerproxy -listen-addr :8443 -forward-url http://127.0.0.1:8787
```

Configure its certificate and deployment using the matching upstream release documentation. Publish only the intended HTTPS diagnostic endpoint; protect direct access to the application. Use a browser-trusted certificate and appropriate production port. No commands from the supplied PDF were executed.

The interface requests `TRANSPORT_ORIGIN/api/transport` only after the transport button. It uses JSON POST, CORS restricted to `APP_ORIGIN`, and `credentials: omit`. There is no preconnect or automatic hidden probe. The application accepts JA3/JA4/HTTP2 headers only when the immediate peer is trusted. The single ingress is expected to append the actual client address at the right of `X-Forwarded-For`; verify this and header overwrite behaviour with the pinned upstream version before exposing it.

The diagnostic endpoint is a separate listener path, not an upstream proxy to a public echo service. Forward only to our local application. Do not use the PDF's external httpbin target for visitor traffic: that would forward their request to another recipient.

## Verification before public use

1. Confirm real browser-to-ingress TLS reaches Fingerproxy directly. A TLS-terminating CDN or proxy changes the observed subject.
2. Send forged fingerprint/forwarding headers in a controlled test and verify that ingress replaces them; block direct-origin bypass.
3. Check that ordinary sample/local use never contacts the diagnostic hostname.
4. Confirm only its explicit button initiates the request and browser cookies are omitted.
5. Confirm the UI labels missing fingerprints unavailable. Cached/resumed handshakes and HTTP/2 connection coalescing can affect evidence.
6. Review request, metrics, access and error logs. Do not retain full raw headers, tokens or packet payloads.
7. Audit dependencies in the selected Fingerproxy release. Upstream throughput claims are not our benchmark.

HTTP/3, exact OS identification and reliable host uptime are not claimed. p0f/JA4T are not running in this build. JA4 TLS and all JA4+ implementations do not share one universal licence; in particular, do not substitute FoxIO's separate NGINX module without reviewing its hosting terms.
