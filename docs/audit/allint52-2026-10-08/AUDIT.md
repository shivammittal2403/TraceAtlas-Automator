# allint52 uploaded-source audit — 2026-10-08

## Delivery and preservation contract

User request: extract `allint52(1).zip`, push all code and audit it while preserving the exact source and core behavior. Destination is the user's established canonical repository, `shivammittal2403/TraceAtlas-Automator`, main baseline `184c0f6a7cb31f587cf56cea31402b9f7faa58b4`.

This is an additive source import at the archive's original `allint52/` path. All 53 Python files retain their exact bytes, CRLF line endings, names and empty-file status. None of the existing repository files, canonical workforce, evidence store, policies, UI, dependencies, entrypoints or workflows is replaced. Audit artifacts are separate under this directory. No fixes, renames, new employee implementations, procurement prompt additions or runtime wiring are included.

Archive SHA-256: `6741c330f33f464be54bd322f2795b64b7567b1b82f5e417b8afa0c4fdecd3ea`.

Main advanced during preparation to `5bda9a009017e5621322f6491836af2640e1f530`. The refreshed tree and comparison were inspected: intervening changes concern the TypeScript workflow/lockfile and current-state/gap/verification documentation. There are no collisions with these 57 additions. The final commit builds on that latest parent and retains all its pre-existing blobs unchanged; the earlier SHA remains the audit's initial read baseline.

`manifest.json` records size, SHA-256 and exact Git blob SHA-1 for every source file. Git blob identities provide a remote tree check without decoding large file responses. Git does not preserve ZIP timestamps; byte preservation does not imply preservation of archive metadata.

## What the archive actually contains

53 files, 837,417 source bytes: seven nonempty Tkinter desktop panels and 46 zero-byte placeholders. The seven panels total 21,392 physical lines. Importing the files does not start their Tk applications because their launchers are guarded by `if __name__ == '__main__'`.

| Source | Lines | Actual implemented scope | Qualification |
| --- | ---: | --- | --- |
| `allint52/osint.py` | 1,475 | Form, search-query planning, evidence/observation schemas and JSON export | Standalone planning prototype |
| `allint52/socmint.py` | 1,940 | Social-source query planning, policy screening, matching guidance, JSON export | Standalone planning prototype; no live social collector |
| `allint52/geomint.py` | 3,425 | Coordinate parsing, distance/bearing helpers, geospatial planning and export | Local helpers plus planning |
| `allint52/imgmint.py` | 3,352 | Local image hashing, dimensions, EXIF summary, perceptual hashes and planning | Optional Pillow; no OCR, vision model or reverse-image service |
| `allint52/audint.py` | 3,946 | Local audio hash/container/ffprobe metadata, volume analysis, sample extraction and planning | Requires FFmpeg/ffprobe for relevant operations |
| `allint52/vedmint.py` | 3,763 | Local video hash/container/ffprobe metadata, sample-frame extraction and planning | Requires FFmpeg/ffprobe; original filename preserved |
| `allint52/webint.py` | 3,491 | Single-page HTTP fetch, basic HTML/metadata/link parsing, hashes and WEBINT planning | Bounded desktop fetch; concerns below |

`procurementint.py` is empty. The procurement system prompt supplied in conversation is not executable code in this archive and was not inserted into it. Other domain names are placeholders, not implemented AI employees. No model API or canonical workforce registration is present in the seven source files. Schemas and suggested handoffs do not themselves execute integrations.

Existing root planning panels have separate recent fixes documented in `docs/CURRENT_STATE.md`; these uploaded originals do not inherit those fixes. They coexist as a preserved snapshot and must not be used to overwrite the repaired root versions.

## Findings

Severity reflects this standalone desktop context. A hosted, untrusted-input service would increase several risks. Confirmed helper defects are distinguished from architectural risks; no real system was probed.

| ID | Severity / confidence | Source and evidence | Preconditions and impact | Recommended separate follow-up / verification |
| --- | --- | --- | --- | --- |
| A01 | Medium / high | `osint.py:390–506`, `socmint.py:487–522`: default forms assert a customer-authorized engagement; reproduced by invoking actual default methods with a fake widget sink | Analyst leaves defaults unchanged; exported planning payload can imply authorization that was never supplied. These strings cannot establish canonical authority | Blank defaults, bind actual authority server-side if later integrated. Test no supplied authority remains unverified. Do not alter the preserved originals |
| A02 | Medium / high | `socmint.py:1894–1910`: export only regenerates when `last_result` is empty; reproduced with old cached target and changed current payload. Similar cached-export pattern exists in `geomint.py:3373–3395` | Form changes after planning; SOCMINT exports the old target/result without refreshed checks, creating a case attribution or disclosure error | Regenerate from current form or bind cached result to an input digest. Test edits to target, scope and policy inputs invalidate old exports |
| A03 | Low / high | `webint.py:497`: `parsed.port` is accessed outside a catch; `https://example.com:bad/` raises ValueError. Fetch worker at `1443–1457` lacks a surrounding catch | Malformed operator or imported URL; worker can end without a structured report | Validate malformed ports within catch; test invalid port and invalid IPv6 return a structured error |
| A04 | Low / high | `webint.py:523–534`: normalization uses naked hostname; a public IPv6 URL becomes `https://2606:4700:4700::1111/` | Legitimate IPv6 literal; accepted URL is rewritten into invalid URL syntax | Preserve brackets and scheme/port meaning. Add IPv6 round-trip tests |
| A05 | Medium / high for redaction gap; leakage impact conditional | `webint.py:252–269`: quoted JSON password fields are not redacted; synthetic fixture reproduced. Parsed content and previews are report/export data | Public or authorized source contains incidental sensitive content; incomplete redaction can retain it in local output/export. This is explicitly light redaction, not proven DLP | Structured redaction plus review before export. Test nested JSON, HTML attributes and token formats with synthetic values |
| A06 | Medium / medium, architectural risk | `webint.py:434–480`, `627–638`: DNS answers are validated, then standard HTTP transport resolves/connects separately; resolved addresses are not pinned | Attacker controls an allowed hostname and changes answers between validation and connection; potential internal-address request. Not exploited or proven live | Reuse canonical fixed-host transport or validate and bind every socket to approved addresses. Test DNS answer changes with a fake transport; retain redirect scope checks |
| A07 | Medium / high for missing bounds; hostile-media impact conditional | `imgmint.py:428–429` decodes with `img.load()` in caller context. Audio/video subprocesses use timeouts and `capture_output=True` (`audint.py:413,462,786`; `vedmint.py:430,692`) without app-level file/memory/output caps or an isolated decoder | Operator opens large or hostile media; resource exhaustion or decoder vulnerability exposure. Pillow has its own bomb safeguards, but no uniform application isolation/budget exists | Separate restricted decoder process, file/pixel/output/memory budgets, pinned maintained decoders. Verify oversized output and malicious-media fixtures in isolation |
| A08 | Low / high | `audint.py:736–783`, `vedmint.py:651–689`: deterministic output filenames plus FFmpeg `-y` | Repeated extraction into same directory, or different inputs with same stem; derived files can overwrite previous output | Unique case/evidence-derived names and no-clobber writing; test same-stem inputs and repeat runs |
| A09 | Capability gap / high | All 46 empty files, including `procurementint.py`; no registration/runner/dependency packaging supplied | User expects 53 functioning employees or procurement functionality | Keep placeholders visibly incomplete. Implement any future vertical as a separate governed change; never infer capability from filenames |

Positive controls observed: no `eval`, `exec`, pickle loading or shell-enabled subprocess calls found in these source files; FFmpeg invocations use argument lists and timeouts. WEBINT blocks basic private/loopback/link-local addresses, URL userinfo and nonstandard ports, revalidates redirects, limits response bytes and rejects unsupported content types. Image GPS coordinates are intentionally withheld in its summary. These controls do not close the findings or constitute full security certification.

## Verification performed

- Safe ZIP inventory/extraction: 53 entries, no traversal or symlink entries; extraction matched every archived file byte-for-byte.
- Source compilation: 53/53 pass, including empty placeholders; seven nonempty files import without launching Tk.
- Secret scan: repository `scripts/check_secrets.py` applied to the extracted snapshot passes. Additional common JWT/key-pattern scan found no matches. Pattern scanning is not proof that every possible secret is absent.
- Network-free audit harness: eleven checks complete; six positive checks and five checks reproducing existing defects. The authorization check covers both OSINT and SOCMINT. These are observed defects, not a claim that the software passes all acceptance gates.
- Missing local image/audio/video files yield structured failures; invalid geographic bounds are rejected.
- GUI export regression uses the real SOCMINT export method with mocked dialogs and synthetic records. URL domain validation uses mocked DNS. No external fetch, real target investigation, model call or media decoder execution was performed by the audit harness.

Reproduce the included checks from repository root:

```sh
python docs/audit/allint52-2026-10-08/audit_checks.py .
python scripts/check_secrets.py
```

`verification.json` records this session's scoped results. Python/Tkinter is needed for imports; native GUI rendering and user interaction require a desktop display. FFmpeg/ffprobe were present locally, but their processing paths were inspected rather than run on uploaded/hostile media.

## Limits and status

CODED: preserved source snapshot and audit artifacts. TESTED: compilation, imports, helper controls and reproduced defects only. DEPLOYED: not performed. Live VERIFIED: not established. The full canonical core suite and browser/database gates were not run locally because no canonical runtime, API, database, frontend or dependency file was changed. GitHub CI/CodeQL for the new commit is a separate gate and is pending at commit creation.

This audit is limited to the uploaded archive and preservation boundary. It is not a comprehensive repository, dependency/advisory, penetration, live-provider or enterprise-readiness audit. Publishing the snapshot does not fix it or integrate it. Original code defects are intentionally retained to satisfy exact-source preservation; fixes must be made separately without replacing this evidence snapshot.
