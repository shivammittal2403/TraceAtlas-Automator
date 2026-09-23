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
  schema and tests are preserved without RedKross source modifications.
- TraceAtlas installs it into `.traceatlas/openosint-venv`, separately from the
  dependency-free core runtime.
- `traceatlas openosint` is an allowlisted compatibility bridge. It requires a
  known case, explicit authorisation, ownership or subject consent, and stores
  only redacted, normalized evidence.
- The upstream interactive shell, proxy controls, anti-bot scraping and web
  server are not exposed by the bridge or the Vercel deployment.
- Large promotional media, generated site assets and upstream CI metadata are
  omitted because they are not needed to run, test or audit the package.

Use the upstream package only for lawful, authorised research and follow both
projects' acceptable-use and privacy requirements.
