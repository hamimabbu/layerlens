# LayerLens

LayerLens shows what a browser and an ordinary network connection can reveal. Browser checks run in the tab. A small Node.js server handles connection checks and optional public-record lookups.

Each result lists its source, when it was retrieved and what it can tell you. A shared IP address or a network registration record describes a connection, not the person using it.

![LayerLens sample dashboard](docs/preview-desktop.png)

## Run locally

Requires Node.js 22 or newer. The core app has no package dependencies and needs no API key.

```sh
npm start
```

Open http://127.0.0.1:8787. The server binds to loopback by default.

```sh
npm run check
npm test
```

## What you can try

| Check | How it works |
| --- | --- |
| Sample mode | Shows made-up data without running a lookup. |
| Browser settings | Reads selected settings in the tab after a click. Optional hardware hints can be unavailable in some browsers. |
| Local attribute pattern | Computes a SHA-256 hash of selected browser values. It does not establish a unique identity. |
| Connection check | Returns the socket address or the address supplied by a configured, trusted ingress. |
| Public records | Looks up PTR, RDAP or InternetDB records after the operator enables a source and the visitor selects it. These checks are off by default. |
| Export and reset | Previews a redacted JSON export. Reset clears the tab's results. |
| Transport diagnostic | Supports a separate Fingerproxy endpoint for JA3, JA4 and HTTP/2 metadata. A real TLS deployment still needs testing. |

Browser results stay in the tab. The initial configuration request reads deployment settings; it does not run an address lookup. Missing transport data stays unavailable. In local HTTP mode, the connection report describes the application-side connection.

## Optional public-record lookups

Copy `.env.example` to `.env` and configure the sources you want to enable. For direct Node use:

```sh
node --env-file=.env server/index.mjs
```

- `ENABLE_EXTERNAL_LOOKUPS=true` enables the public-record adapters.
- PTR also needs `DNS_RESOLVERS`.
- InternetDB also needs `ENABLE_INTERNETDB=true`. Its publisher documents free noncommercial use; check the terms before deployment.

The visitor must select a configured source and approve its recipient before the lookup runs. Local, private and reserved addresses are rejected before an external request. InternetDB returns existing indexed records; this app does not scan visitors' services. An empty result does not establish that a connection is safe.

## Optional deployment

```sh
docker compose up --build
```

Compose reads `.env`. The container configuration uses a non-root user, a read-only filesystem and dropped capabilities, with a loopback-only published port. Docker execution has not been verified. Test it on the intended host and configure HTTPS before public use.

For transport fingerprints, see the [Fingerproxy setup guide](docs/TRANSPORT.md). The integration uses [wi1dcard/fingerproxy](https://github.com/wi1dcard/fingerproxy), licensed under Apache-2.0. The version reviewed for the guide was v1.2.3.

Use a separate diagnostic hostname with valid HTTPS. The app contacts it only after the transport button is pressed and omits browser cookies. Only trusted proxy peers can supply fingerprint headers. A TLS-terminating CDN changes the connection being measured, so it needs separate consideration during setup.

## Tests and limits

The 20 automated tests cover address parsing, trusted headers, lookup selection, consent, response limits, redaction and API behaviour. GitHub Actions runs them on Node.js 22 and 24. The [validation record](docs/VALIDATION.md) includes the browser checks and remaining gaps.

Live DNS, RDAP and InternetDB accuracy and availability have not been measured. Real Fingerproxy TLS and Docker execution remain unverified. p0f packet capture is a possible extension and is not implemented.

The app has no results database, analytics SDK, cookies or persistent browser identifiers. Server results last for the request; browser results stay in memory. Hashed rate counters are removed within 61 seconds. Hosting and proxy logs need their own configuration, and reset cannot remove records held by a provider.

Export redaction reduces the information shared, but remaining values can still be identifying. A PTR name is not a private computer name, and a CVE linked to a shared exit IP does not confirm a vulnerability on the visitor's laptop.

## Code

```text
public/                 Interface and browser collectors
public/report.mjs       Export redaction shared with the server
server/index.mjs        API, consent checks, trusted ingress and quotas
server/evidence.mjs     Address parsing and evidence records
server/collectors.mjs   PTR, RDAP and InternetDB adapters
tests/                  Unit and local integration tests
docs/                   Architecture, setup, sources and test notes
compose.yaml            Container configuration
```

See the [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT-MODEL.md) and [sources](docs/SOURCES.md) for more detail. Keep `.env`, certificates, private keys, captures and logs out of Git. Publishing the repository does not deploy the app.

## Licence

LayerLens code is licensed under MIT. Optional tools and datasets keep their own licences and terms. Preserve their notices when distributing their code or binaries.
