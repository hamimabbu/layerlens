# Sources and attribution

Reviewed 7 November 2026. Repository code and terms can change; pin/review the actual version used in a deployment.

## Integrated optional component

- [wi1dcard/fingerproxy](https://github.com/wi1dcard/fingerproxy): Go reverse proxy, JA3/JA4/HTTP2 fingerprint headers; [Apache-2.0](https://github.com/wi1dcard/fingerproxy/blob/master/LICENSE). Inspected v1.2.3 release and current README. LayerLens does not vendor its code or binary.

## Public record sources

- [IANA RDAP bootstrap](https://data.iana.org/rdap/) and [RFC 9224](https://www.rfc-editor.org/rfc/rfc9224.html): approved regional registry selection. We expose selected network fields, not personal contact entities.
- [Shodan InternetDB](https://book.shodan.io/developer-apis/internetdb/): optional existing public-IP records. [Publisher terms](https://blog.shodan.io/introducing-the-internetdb-api/) document weekly updates and noncommercial free use; associations can be unverified.
- PTR: operator-selected DNS resolver; no unlisted vendor is hardcoded.

## Research references, no copied application code

- [MyIP](https://github.com/jason5ng32/MyIP), AGPL-3.0: complete network-toolbox reference.
- [CreepJS](https://github.com/abrahamjuliot/creepjs), MIT code with public-fork renaming requirements: browser research reference.
- [phuslu/nginx-ssl-fingerprint](https://github.com/phuslu/nginx-ssl-fingerprint), BSD-2-Clause: alternative transport architecture, not stacked into this build.
- [FoxIO JA4](https://github.com/FoxIO-LLC/ja4): TLS specification/reference. Review separate terms for JA4+ components.
- The user-supplied **Linux Telemetry & Recon Project.pdf** informed the advanced research direction. It is reference content, not permission to install, capture or scan. Several version-specific p0f options and strong OS/uptime/privacy assertions need correction before implementation.

## Standards and implementation references

- [User-Agent reduction](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/User-agent_reduction)
- [Hardware concurrency](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/hardwareConcurrency) and [device memory](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/deviceMemory)
- [Shared IP implications, RFC 6269](https://www.rfc-editor.org/rfc/rfc6269.html)
- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

The original app is licensed MIT. Integrating a separately licensed tool does not erase its attribution, redistribution or service-use conditions.
