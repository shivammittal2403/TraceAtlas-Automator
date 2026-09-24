# Deployment ownership

`shivammittal2403/TraceAtlas-Automator` is the canonical source repository for
the complete project. It contains the TraceAtlas engine, bundled OpenOSINT
package, compatibility bridge, tests, setup launchers, RedKross console,
serverless APIs and the preserved legacy directory.

## Routes

| Route | Source | Purpose |
|---|---|---|
| `/` | `public/index.html` | RedKross Fusion console |
| `/legacy` | `public/legacy.html` | Original TraceAtlas directory |
| `/api/catalog` | `api/catalog.py` | Public feature catalog |
| `/api/health` | `api/health.py` | Deployment health |
| `/api/plan` | `api/plan.py` | Validated local command plans |

## Vercel

Deploy this repository directly after linking the Vercel project:

```bash
vercel link
vercel --prod
```

The currently published Vercel project may use a small deployment mirror while
its Git integration remains attached to an older repository. That mirror is not
the source of truth and must not receive independent feature development. Any
deployment mirror should be generated from this repository's `public/`, `api/`,
`vercel_app_data.py`, `vercel.json` and `.vercelignore` files.

The hosted UI is deliberately a stateless planner. Actual authorised
collection, credentials, case databases, evidence and reports stay on the
operator's machine and run through `./start.sh`.
