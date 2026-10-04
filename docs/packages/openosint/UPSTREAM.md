# Preserved OpenOSINT package

This directory preserves the executable source of
[OpenOSINT](https://github.com/OpenOSINT/OpenOSINT) version 2.29.0 at upstream
commit `871ccbe3d526241241b4126c8991100a2b20b52f`.

OpenOSINT is licensed under the MIT License. Its original `LICENSE`, README,
security policy, disclaimer, changelog, legal documents and dependency lock are
kept in this directory. Copyright and authorship remain with the upstream
project and contributors.

## Integration boundary

- The upstream Python package, cloud service, actor definitions, database
  schema and runtime tests are preserved without RedKross source modifications.
- Promotional documentation/site sources, sponsor-maintenance scripts/data and
  demo-recording assets are intentionally omitted. Their upstream tests remain
  for audit provenance but are excluded from the bundled runtime CI because the
  referenced artifacts are not shipped.
- Playbook tests that require separately installed `sherlock`, `holehe` and
  other optional command-line tools are excluded from the dependency-free
  runtime job. The adapter layer reports those tools unavailable until installed.
- TraceAtlas installs it into `.traceatlas/openosint-venv`, separately from the
  dependency-free core runtime.
- `traceatlas openosint` is an allowlisted compatibility bridge. It requires a
  known case, explicit authorisation, ownership or subject consent, and stores
  only redacted, normalized evidence.
- The upstream interactive shell, proxy controls, anti-bot scraping and web
  server are not exposed by the bridge or the Vercel deployment.
- Large promotional media, generated site assets and upstream CI metadata are
  omitted because they are not needed to run, test or audit the package.

The repository CI executes the remaining locked OpenOSINT runtime suite with
proxy inheritance disabled. Graph-dedup tests continue to skip unless the
optional native ICU/nomenklatura stack is installed.

Use the upstream package only for lawful, authorised research and follow both
projects' acceptable-use and privacy requirements.
