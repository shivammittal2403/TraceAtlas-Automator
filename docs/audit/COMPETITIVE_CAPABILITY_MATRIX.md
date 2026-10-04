# Competitive capability matrix

Reviewed 2026-10-04. This matrix records vendor-published product positioning and repository evidence. Vendor descriptions are not independently verified; no competitor weakness or parity claim is inferred.

| Dimension | TraceAtlas baseline | Public competitor reference |
|---|---|---|
| Evidence integrity / replay | Bounded evidence store and offline replay TESTED; forensic maturity partial | Social Links describes collection/link-analysis workflows; Maltego describes evidence and graph workflow. Feature comparison requires hands-on evaluation |
| SOCMINT | Integrated social investigation NOT_IMPLEMENTED | Social Links markets broad OSINT/social capabilities; vendor claim, not independently measured |
| Graph investigation | Browser graph and temporal primitives PARTIAL | Maltego Graph positions graph visualization and transform integrations |
| Open-source automation | Governed adapters and controlled scenarios TESTED | SpiderFoot public repo describes modular automated OSINT scans/correlation |
| CTI graph/connectors | Partial CTI source path | OpenCTI documents STIX-based data model and connectors/imports |
| Enterprise intelligence | No hosted production qualification | Recorded Future describes intelligence graph and AI workflows; vendor description |
| Entity resolution / accuracy | Human-reviewed case-local candidates; population accuracy unmeasured | No cross-product precision benchmark gathered for this audit |
| IAM/on-prem/operations | Local bounded mode plus hosted components; live enterprise readiness unverified | Product/plan details require current procurement evaluation |

## Sources

- [Social Links product](https://sociallinks.io/)
- [Maltego Graph](https://www.maltego.com/graph/)
- [SpiderFoot repository](https://github.com/smicallef/spiderfoot)
- [OpenCTI data model](https://docs.opencti.io/5.7.X/usage/data-model/) and [automated imports](https://docs.opencti.io/6.8.X/usage/import/getting-started/)
- [Recorded Future Intelligence Graph](https://www.recordedfuture.com/platform/intelligence-graph) and [AI](https://www.recordedfuture.com/platform/ai)

## Gates

Social-Links-class parity is NOT ESTABLISHED: TraceAtlas has no measured multi-source SOCMINT, cross-platform correlation, accuracy, social case management or enterprise access-control benchmark. Maltego-class graph parity is NOT ESTABLISHED: useful expansion, transforms, persistent temporal paths, collaboration, scale and evidence navigation have not all been demonstrated together.
