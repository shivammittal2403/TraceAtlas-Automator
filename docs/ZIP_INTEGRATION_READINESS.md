# Root ZIP integration: evidence and restrictions

As observed on 17 October 2026, TraceAtlas main contains **23 root-level ZIP
archives**. The two Agent-Reach ZIP names have the same Git blob hash.

This integration provides a reproducible **audit and isolated staging pipeline**.
It does not claim that unreviewed third-party software is now a working
TraceAtlas source adapter.

## Run the complete archive audit

```bash
python -m pip install .
traceatlas-zips --repository . --output /tmp/traceatlas-zips.json
traceatlas-zips --repository . --stage-dir /tmp/traceatlas-vendor-staging \
  --syntax-check --output /tmp/traceatlas-zip-readiness.json
python -m unittest discover -s tests -p test_zip_workbench.py -v
```

The workbench SHA-256 hashes each archive and maps archive names to the existing
`traceatlas.capabilities.registry` contracts. It rejects path traversal,
symlinks, encrypted entries, colliding member paths, unsupported member types,
suspicious compression ratios, excessive decompressed totals, and files beyond
defined limits. Same-content copies stage only once.

Output includes `capability_id`, `contract_exists`,
`ready_for_live_execution`, `issues`, `duplicate_of`, `stage`,
`syntax`, and `next_gate` for every ZIP. Python AST checks parse code but
never execute it.

## What is executed?

Only the *auditing, extraction and syntax-check workflow* runs. ZIP-contained
install scripts, workers, scanners, browser agents and service code **do not
execute**. Staged source is isolated outside the checkout and not imported by
TraceAtlas, so upstream archives cannot overwrite the main runtime.

Any live integration requires a reviewed license, pinned dependencies, a
qualified adapter, actual runtime tests, explicit investigator authorization,
a bounded target scope, and separately configured provider access. Existing
TraceAtlas capabilities are not replaced.

GitHub Actions `ZIP Archive Readiness` performs the same offline verification
on pushes and pull requests, and uploads a machine-readable audit artifact.

This is the foundation for integrating all archives safely, not a false claim
that every archive is a working production tool.
