# Supplied repository review — geo, media and documents

Eleven archives were supplied in this batch. CTI-to-MITRE and OSINTIQ are exact
directory-level duplicates of projects already integrated in TraceAtlas 0.9.
The nine unique projects below expand the registry from 31 to 40 engines.

| Project | Verified licence state | Useful capability | 1.0 integration |
|---|---|---|---|
| Data Commons Agent Toolkit | Apache 2.0 in package source | Public statistical variables and observations through MCP | Read-only MCP contract |
| Citra | MIT | Local PDF structure, page/bbox proof, compare, OCR and trust reports | Read-only MCP plus staged files |
| Docling MCP | MIT | Multi-format conversion, OCR/tables, document search and RAG | Read-only MCP plus staged files |
| SIDA | No licence file supplied | Deepfake classification, tamper masks and explanations | Design-only; no code/model/data copied |
| Alethia | No licence file supplied | Reverse-image, perceptual hash, media-bias and geo-signal fusion | Independent native concepts only |
| Geo Sleuth | MIT code; CC BY-SA tables | Evidence-driven image geolocation, terrain/OSM/camera geometry | Export contract; live tracking automation disabled |
| LocateAnything | COCL 1.0 custom/non-commercial | Local VLM geolocation, ranked candidates and GeoJSON | Approved exports only |
| GeoAI | MIT | Satellite/remote-sensing segmentation, classification and change detection | Restricted MCP; downloads excluded |
| GeoCLIP | MIT | Offline worldwide image geolocation and GPS embeddings | Optional external model-output adapter |

## Implemented missing features

- deterministic evidence Fusion Board with observed/inference/model separation;
- explicit contradictions, source diversity caps and review-required rankings;
- consent/ownership gates for identity, location and organisation scopes;
- coarse GeoJSON export;
- image signature validation and optional aHash/dHash;
- staged-file security boundary for document/geospatial MCP tools;
- MCP allowlists for Data Commons, Citra, Docling and GeoAI;
- licence-aware contracts for all nine projects.

Large model weights, datasets, satellite downloads, reverse-image browser
automation and upstream monoliths are deliberately not bundled.
