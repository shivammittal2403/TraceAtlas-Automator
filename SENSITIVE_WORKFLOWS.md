# Controlled Sensitive Workflows

TraceAtlas 1.7 automates five sensitive research categories inside a deliberately
narrow safety envelope. The commands are defensive monitoring aids, not a way
to obtain private records, identify anonymous people, test credentials or track
third-party devices.

## Shared gate

Every command requires all of the following:

1. an existing case with a documented purpose;
2. `--authorized` and `--allow-sensitive` together;
3. `--lawful-purpose` containing a specific reason;
4. the workflow-specific ownership, consent or data-authority flag.

A successful run records an audit row containing the workflow, target SHA-256
fingerprint, purpose, attestations, timestamps, status and result count. It also
creates typed Spider events, redacted evidence and a change snapshot. The
command returns `changed: false` when the normalized result set is identical to
the previous run for the same workflow and target.

## Workflow matrix

| Category | Command(s) | Source | Retained | Intentionally excluded |
|---|---|---|---|---|
| Dark-web research | `darkweb-monitor`, `darkweb-feed`, `darkweb-misp` | Approved export, permitted Ahmia clear-web search, or operator-controlled MISP | Source/service fingerprints, counts and target-mention flags | Raw title/content, Tor connection, onion fetch, attachments, marketplace interaction |
| Data-breach analysis | `breach-catalog`, `breach-domain`, `breach-artifact` | HIBP metadata or authorized local JSON/CSV/TSV | Breach names/metadata, hashed aliases, file/schema statistics | Passwords, raw accounts, local rows, artifact copy |
| Person profiling | `person-profile` | ORCID and Crossref public APIs | Low-confidence professional/publication candidates | Home, family, contact, live location, social-graph enrichment |
| Leaked-credential monitoring | `breach-account`, `password-hash` | HIBP k-anonymity endpoints | Target fingerprints, breach names, exposure count | Plaintext passwords, recovered credentials, credential testing |
| Wi-Fi geolocation | `wifi-locate` | WiGLE API | Hashed BSSID and coordinates rounded to two decimals | SSID, raw BSSID in storage, precise coordinates, bulk/radius search |

All candidate person matches are tagged `candidate-not-identity`; analyst review
is mandatory. Wi-Fi lookup accepts one exact unicast BSSID and requires an
owned-asset attestation. Breach artifact processing is limited to 32 MiB and
hashes column names rather than saving them.

Dark-web monitoring requires exactly one source mode. `--index-file` plus
`--authorized-feed` parses a locally supplied, approved HTML export and performs
no network request. `--live-ahmia` plus `--source-permission` performs one
clear-web query and must be used only when the operator has documented permission
consistent with Ahmia's current terms. Neither mode requests an `.onion` URL.

`darkweb-misp` performs one exact owned-domain search against an approved MISP
instance. The service hostname must be loopback or explicitly allowlisted for
HTTPS. Results are immediately reduced to fingerprints and counts; raw event
content and attachments are not copied into the case.

## Connector configuration

Set credentials in the process environment or your approved secret manager;
never put real keys in command history, source files or case notes.

| Variable | Used by | Required |
|---|---|---|
| `HIBP_API_KEY` | `breach-account`, `breach-domain` | Yes; 32 hexadecimal characters |
| `ORCID_ACCESS_TOKEN` | ORCID part of `person-profile` | Optional; Crossref still runs without it |
| `WIGLE_API_NAME` | `wifi-locate` | Yes |
| `WIGLE_API_TOKEN` | `wifi-locate` | Yes |
| `MISP_URL`, `MISP_API_KEY` | `darkweb-misp` | Yes |

`breach-domain` also requires that the domain is already verified for the API
account and both `--owned-domain` and `--hibp-domain-verified` are supplied.
Public `breach-catalog` metadata and Pwned Passwords hash-range checks do not use
the HIBP API key.

## Scheduling

TraceAtlas does not install a daemon or modify the host scheduler. Run the same
command periodically through your organization's cron, systemd, CI or workflow
runner. Use the JSON `changed` value to decide whether to create an alert, and
retain the full generated case report for review rather than forwarding raw
console output to a public channel.

## Failure behavior

- A missing consent/ownership flag fails before network access or audit creation.
- Missing connector credentials fail before a request is made.
- HTTP/source failures produce a `partial` run with zero or partial results.
- Third-party responses are size-bounded and malformed JSON is treated as empty.
- API responses remain leads; absence is not proof that no exposure exists.
