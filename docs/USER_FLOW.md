# Investigator user flows

| Investigation | Seed | Executable source mode | Boundary |
|---|---|---|---|
| Person | `person:synthetic-analyst` | Approved records | No private discovery; possible identity only |
| Company | `company:synthetic-company` | Approved records | Registry assertions require source review |
| Domain | `domain:example.org` | Approved records or fixed-host DNS/RDAP/archive | Exact scope; no discovered-domain pivots |
| IP | Authorized global IPv4/IPv6 | Approved records or RDAP/InternetDB | IPv6 excludes InternetDB; no scanning |
| IOC | Controlled domain/IP assertion | Shared backbone fixture | Native CTI engine exists separately |
| Threat actor | Controlled public-source assertions | Shared backbone fixture | No autonomous attribution |
| Malware | Inert static-analysis assertions | Shared backbone fixture | No specimen execution |
| Supply chain | Controlled company dependency assertions | Shared backbone fixture | No native BOM import in this slice |

Local happy path: create case → register authority → define objective/seed → plan
→ approve exact digest → run → inspect product evidence/graph/timeline/claims →
review verification/gaps → retain draft → replay. Login/tenant dashboard applies
to the existing hosted surface; local access depends on OS/workspace permissions.

Empty results are PARTIAL with `no-source-observations`. Source failures preserve
successful evidence and stable failure codes. Unavailable models do not affect
this deterministic runner. Expired/mismatched permission fails before dispatch.
Budget exhaustion skips further requests and preserves unknowns. Detected source
instructions have no action authority and prevent SUPPORTED promotion.

Pause/cancel/resume of this new workflow are not implemented. The kill switch
stops new dispatch; transport timeout bounds an in-flight request. Completed-task
retry returns its immutable product. A failed task needs a new approved task;
interrupted acquisition can leave captured but unreferenced bytes. Do not call
that distributed exactly-once execution. See RUNBOOK.md for concrete commands.
