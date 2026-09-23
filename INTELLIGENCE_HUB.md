# Governed Intelligence Hub

## Purpose

The version 0.5 intelligence hub normalizes authorised public-source and
operator-supplied evidence into the existing TraceAtlas event graph. It is
designed for defensive investigations, owned-asset exposure reviews, consented
professional-profile reviews and documented public-record due diligence.

It does not bypass authentication, use stolen sessions, scrape private
profiles, enumerate private community members, retrieve private messages,
download malware, infer protected traits or label a person as a criminal.

## Source matrix

| Source | Mode | Required basis | Normalized event |
|---|---|---|---|
| LinkedIn | Official/approved export | Subject consent or owned organisation | `PROFESSIONAL_PROFILE` |
| Instagram | Official/approved export | Subject consent or owned organisation | `SOCIAL_PROFILE` |
| Facebook | Official/approved export | Subject consent or owned organisation | `SOCIAL_PROFILE` |
| TikTok | Official/approved export | Subject consent or owned organisation | `SOCIAL_PROFILE` |
| Snapchat | Official/approved export | Subject consent or owned organisation | `SOCIAL_PROFILE` |
| YouTube | Data API or export | Subject consent or owned organisation | `PUBLIC_MEDIA_PROFILE` |
| GitHub | Public API or export | Subject consent or owned organisation | `CODE_PROFILE` |
| Discord | Public invite API or export | Subject consent or owned organisation | `COMMUNITY_METADATA` |
| Shodan | API or export | Owned public asset | `INTERNET_EXPOSURE` |
| Censys | API or export | Owned public asset | `INTERNET_EXPOSURE` |
| VirusTotal | API or export | Owned indicator/asset | `THREAT_INTELLIGENCE` |
| MalwareBazaar | Approved export | Owned asset | `THREAT_INTELLIGENCE` |
| Business registry | Authoritative export | Public-record basis or owned organisation | `BUSINESS_RECORD` |
| Employee directory | Owned directory export | Subject consent or owned organisation | `PROFESSIONAL_RECORD` |
| Sanctions | Authoritative export | Public-record basis or owned organisation | `SANCTIONS_RECORD` |
| Court records | Authoritative export | Public-record basis or owned organisation | `COURT_RECORD` |

## Live connector credentials

| Connector | Environment variables |
|---|---|
| GitHub | `GITHUB_TOKEN` is optional for a higher official API rate limit |
| YouTube | `YOUTUBE_API_KEY` |
| Discord invite | None |
| Shodan | `SHODAN_API_KEY` |
| Censys | `CENSYS_API_ID`, `CENSYS_API_SECRET` |
| VirusTotal | `VIRUSTOTAL_API_KEY` |

Tokens remain in environment variables and are never written to events,
reports or evidence. The connectors call fixed HTTPS hosts and do not accept a
user-controlled API base URL.

## Export ingestion

JSON, JSONL, CSV and TSV are accepted up to 10 MiB. Processing is capped at
5,000 records per run. TraceAtlas stores a normalized evidence copy rather than
the original sensitive export.

During normalization:

- passwords, tokens, cookies and secrets become SHA-256 representations;
- email addresses and phone numbers become non-reversible fingerprints;
- government identifiers, payment-card fields, home addresses and exact
  locations are removed;
- long strings, lists and objects are bounded;
- every record is marked as an observed fact with a source-specific limitation.

## Media analysis

The media command accepts one authorised image, audio or video file up to
100 MiB.

| Capability | Optional local tool | Behaviour |
|---|---|---|
| Image metadata | ExifTool | Sanitized EXIF and coarse GPS only |
| Audio/video metadata | FFprobe | Container, stream, duration and codec metadata |
| Image text | Tesseract | Redacted OCR text marked untrusted |
| Audio/video transcript | Whisper | Machine transcript marked unverified |
| AI analysis | Ollama | Advisory analysis; endpoint restricted to loopback HTTP |

AI output receives a low confidence value, is tagged `not-a-fact` and requires
analyst review. OCR and transcripts are treated as untrusted data so embedded
instructions cannot control the analysis prompt.

## Analysis model

`traceatlas intel analyze` first produces a deterministic report containing:

- observed facts with event type, source, confidence and risk;
- coverage and source counts;
- an empty inference section unless a separate analytical step adds hypotheses;
- unanswered corroboration questions;
- explicit limitations.

Optional Ollama output is stored separately as advisory analysis. Every
hypothesis must reference source/event context and must be verified before use.

## Examples

```bash
traceatlas intel collect --case demo-001 --source virustotal \
  --target-type domain --target example.org \
  --owned-asset --authorized

traceatlas intel collect --case demo-001 --source shodan \
  --target-type ip --target 203.0.113.10 \
  --owned-asset --authorized

traceatlas intel ingest --case demo-001 --source court_records \
  --file ./official-court-export.json \
  --public-record-basis --authorized

traceatlas intel media --case demo-001 --file ./interview.mp4 \
  --subject-consent --authorized --transcribe --whisper-model tiny
```

The Shodan/Censys examples require a real organisation-owned global IP;
documentation addresses are intentionally rejected by the live connector.
