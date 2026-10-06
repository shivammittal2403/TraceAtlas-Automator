TraceAtlas-Automator/
│
│======================================================================
│ 00. REPOSITORY CONTROL / PROJECT ROOT
│======================================================================
│
├── README.md                         # Product overview, truthful capabilities, quickstart
├── LICENSE                           # Software license
├── SECURITY.md                       # Vulnerability disclosure + security policy
├── CONTRIBUTING.md                   # Contribution workflow
├── CODE_OF_CONDUCT.md                # Contributor conduct
├── CHANGELOG.md                      # Version changes
├── ROADMAP.md                        # Measured roadmap, never fake readiness
├── AGENTS.md                         # Coding-agent repository instructions
├── ARCHITECTURE.md                   # Top-level architecture map
├── pyproject.toml                    # Python project/dependencies/tooling
├── uv.lock                           # Reproducible Python dependency lock
├── package.json                      # Root JS workspace commands
├── pnpm-workspace.yaml               # JS/TS monorepo workspace
├── pnpm-lock.yaml                    # JS dependency lock
├── tsconfig.json                     # Shared TypeScript configuration
├── eslint.config.js                  # TS/React linting
├── prettier.config.js                # Formatting
├── pytest.ini                        # Python test configuration
├── alembic.ini                       # DB migration configuration
├── Dockerfile                        # Production backend container
├── Dockerfile.worker                 # Worker container
├── docker-compose.yml                # Local complete stack
├── Makefile                          # Common developer commands
├── .env.example                      # Environment-variable contract
├── .editorconfig
├── .gitignore
├── .dockerignore
├── .pre-commit-config.yaml
│
│
│======================================================================
│ 01. CANONICAL BACKEND PACKAGE
│======================================================================
│
├── traceatlas/
│   ├── __init__.py
│   ├── __main__.py
│   ├── bootstrap.py                  # Application composition root
│   ├── config.py                     # Typed settings
│   ├── version.py
│   ├── constants.py
│   ├── exceptions.py
│   ├── logging.py
│   │
│   │------------------------------------------------------------------
│   │ DOMAIN MODEL
│   │------------------------------------------------------------------
│   ├── core/
│   │   ├── __init__.py
│   │   ├── case.py
│   │   ├── objective.py
│   │   ├── objective_spec.py
│   │   ├── scope.py
│   │   ├── authorization.py
│   │   ├── target.py
│   │   ├── entity.py
│   │   ├── entity_type.py
│   │   ├── relationship.py
│   │   ├── relationship_type.py
│   │   ├── evidence.py
│   │   ├── observation.py
│   │   ├── fact.py
│   │   ├── claim.py
│   │   ├── hypothesis.py
│   │   ├── contradiction.py
│   │   ├── confidence.py
│   │   ├── verification.py
│   │   ├── knowledge_state.py
│   │   ├── information_gap.py
│   │   ├── next_action.py
│   │   ├── timeline.py
│   │   ├── event.py
│   │   ├── source.py
│   │   ├── source_lineage.py
│   │   ├── provenance.py
│   │   ├── citation.py
│   │   ├── task.py
│   │   ├── result.py
│   │   ├── artifact.py
│   │   ├── investigation.py
│   │   ├── budget.py
│   │   ├── cost.py
│   │   ├── jurisdiction.py
│   │   ├── language.py
│   │   ├── identifiers.py
│   │   ├── enums.py
│   │   ├── validation.py
│   │   └── serialization.py
│   │
│   │------------------------------------------------------------------
│   │ GOAL / OBJECTIVE UNDERSTANDING
│   │------------------------------------------------------------------
│   ├── objectives/
│   │   ├── parser.py                 # Natural-language objective -> ObjectiveSpec
│   │   ├── classifier.py             # Determine investigation type
│   │   ├── entity_extractor.py
│   │   ├── target_extractor.py
│   │   ├── question_generator.py
│   │   ├── requirement_extractor.py
│   │   ├── constraint_extractor.py
│   │   ├── jurisdiction_resolver.py
│   │   ├── temporal_scope.py
│   │   ├── authorization_resolver.py
│   │   ├── ambiguity_detector.py
│   │   ├── normalizer.py
│   │   └── validator.py
│   │
│   │------------------------------------------------------------------
│   │ INVESTIGATION PLANNER
│   │------------------------------------------------------------------
│   ├── planning/
│   │   ├── planner.py
│   │   ├── planner_output.py
│   │   ├── semantic_planner.py
│   │   ├── deterministic_validator.py
│   │   ├── question_decomposer.py
│   │   ├── subproblem_builder.py
│   │   ├── capability_planner.py
│   │   ├── intelligence_domain_planner.py
│   │   ├── evidence_planner.py
│   │   ├── source_planner.py
│   │   ├── connector_planner.py
│   │   ├── worker_planner.py
│   │   ├── verification_planner.py
│   │   ├── dependency_planner.py
│   │   ├── wave_planner.py
│   │   ├── cost_planner.py
│   │   ├── latency_planner.py
│   │   ├── risk_planner.py
│   │   ├── stop_condition_builder.py
│   │   └── plan_validator.py
│   │
│   │------------------------------------------------------------------
│   │ INVESTIGATION EXECUTION
│   │------------------------------------------------------------------
│   ├── investigation/
│   │   ├── manager.py
│   │   ├── engine.py
│   │   ├── lifecycle.py
│   │   ├── state.py
│   │   ├── session.py
│   │   ├── context.py
│   │   ├── executor.py
│   │   ├── scheduler.py
│   │   ├── task_queue.py
│   │   ├── task_graph.py
│   │   ├── dependencies.py
│   │   ├── wave_executor.py
│   │   ├── parallel_executor.py
│   │   ├── retry.py
│   │   ├── backoff.py
│   │   ├── timeout.py
│   │   ├── cancellation.py
│   │   ├── checkpoints.py
│   │   ├── recovery.py
│   │   ├── resumability.py
│   │   ├── kill_switch.py
│   │   ├── progress.py
│   │   └── audit.py
│   │
│   │------------------------------------------------------------------
│   │ REASONING / INVESTIGATION LOOP
│   │------------------------------------------------------------------
│   ├── reasoning/
│   │   ├── engine.py
│   │   ├── claim_engine.py
│   │   ├── hypothesis_engine.py
│   │   ├── alternative_hypothesis.py
│   │   ├── pattern_engine.py
│   │   ├── correlation_engine.py
│   │   ├── contradiction_engine.py
│   │   ├── knowledge_state.py
│   │   ├── gap_engine.py
│   │   ├── information_gain.py
│   │   ├── next_best_action.py
│   │   ├── action_ranker.py
│   │   ├── uncertainty.py
│   │   ├── stopping_engine.py
│   │   ├── completion.py
│   │   └── human_review.py
│   │
│   │
│   │==================================================================
│   │ 02. AI EMPLOYEE OPERATING SYSTEM
│   │==================================================================
│   │
│   ├── employees/
│   │   ├── base.py
│   │   ├── employee.py
│   │   ├── manifest.py
│   │   ├── registry.py
│   │   ├── capabilities.py
│   │   ├── permissions.py
│   │   ├── context.py
│   │   ├── memory.py
│   │   ├── working_memory.py
│   │   ├── case_memory.py
│   │   ├── state.py
│   │   ├── budget.py
│   │   ├── task_envelope.py
│   │   ├── result_envelope.py
│   │   ├── dispatcher.py
│   │   ├── orchestrator.py
│   │   ├── supervisor.py
│   │   ├── router.py
│   │   ├── handoff.py
│   │   ├── checkpoint.py
│   │   ├── heartbeat.py
│   │   ├── review.py
│   │   ├── telemetry.py
│   │   ├── failure.py
│   │   └── lifecycle.py
│   │
│   │   ├── workers/
│   │   │   ├── investigation_manager.py
│   │   │   ├── planner.py
│   │   │   ├── collection_coordinator.py
│   │   │   ├── source_router.py
│   │   │   ├── web_osint.py
│   │   │   ├── search_analyst.py
│   │   │   ├── person_analyst.py
│   │   │   ├── username_analyst.py
│   │   │   ├── socmint_analyst.py
│   │   │   ├── company_analyst.py
│   │   │   ├── registry_analyst.py
│   │   │   ├── procurement_analyst.py
│   │   │   ├── legal_analyst.py
│   │   │   ├── domain_analyst.py
│   │   │   ├── dns_analyst.py
│   │   │   ├── ip_analyst.py
│   │   │   ├── asn_analyst.py
│   │   │   ├── infrastructure_analyst.py
│   │   │   ├── cloud_analyst.py
│   │   │   ├── cti_analyst.py
│   │   │   ├── vulnerability_analyst.py
│   │   │   ├── malware_context_analyst.py
│   │   │   ├── supply_chain_analyst.py
│   │   │   ├── code_analyst.py
│   │   │   ├── package_analyst.py
│   │   │   ├── geo_analyst.py
│   │   │   ├── image_analyst.py
│   │   │   ├── video_analyst.py
│   │   │   ├── audio_analyst.py
│   │   │   ├── document_analyst.py
│   │   │   ├── archive_analyst.py
│   │   │   ├── news_analyst.py
│   │   │   ├── dataset_analyst.py
│   │   │   ├── exposure_analyst.py
│   │   │   ├── entity_resolution_analyst.py
│   │   │   ├── graph_analyst.py
│   │   │   ├── timeline_analyst.py
│   │   │   ├── contradiction_analyst.py
│   │   │   ├── verification_analyst.py
│   │   │   ├── gap_analyst.py
│   │   │   ├── report_analyst.py
│   │   │   ├── adversarial_supervisor.py
│   │   │   ├── quality_supervisor.py
│   │   │   └── compliance_supervisor.py
│   │
│   │   ├── skills/
│   │   │   ├── search.py
│   │   │   ├── fetch.py
│   │   │   ├── extract.py
│   │   │   ├── parse.py
│   │   │   ├── normalize.py
│   │   │   ├── correlate.py
│   │   │   ├── resolve.py
│   │   │   ├── verify.py
│   │   │   ├── contradict.py
│   │   │   ├── graph.py
│   │   │   ├── timeline.py
│   │   │   ├── geolocate.py
│   │   │   ├── analyze_image.py
│   │   │   ├── analyze_video.py
│   │   │   ├── analyze_audio.py
│   │   │   ├── analyze_document.py
│   │   │   └── report.py
│   │
│   │   └── prompts/
│   │       ├── planner.yaml
│   │       ├── extraction.yaml
│   │       ├── entity_resolution.yaml
│   │       ├── hypothesis.yaml
│   │       ├── contradiction.yaml
│   │       ├── verification.yaml
│   │       ├── adversarial_review.yaml
│   │       └── report.yaml
│   │
│   │
│   │==================================================================
│   │ 03. INTELLIGENCE DISCIPLINE ENGINES
│   │==================================================================
│   │
│   ├── intelligence/
│   │   ├── common/
│   │   │   ├── pipeline.py
│   │   │   ├── result.py
│   │   │   └── provenance.py
│   │   │
│   │   ├── webint/
│   │   │   ├── search.py
│   │   │   ├── crawler.py
│   │   │   ├── page_parser.py
│   │   │   ├── links.py
│   │   │   ├── metadata.py
│   │   │   └── historical.py
│   │   │
│   │   ├── searchint/
│   │   │   ├── query_builder.py
│   │   │   ├── query_expansion.py
│   │   │   ├── multilingual.py
│   │   │   ├── deduplication.py
│   │   │   └── ranking.py
│   │   │
│   │   ├── socmint/
│   │   │   ├── model.py
│   │   │   ├── public_profiles.py
│   │   │   ├── public_posts.py
│   │   │   ├── public_groups.py
│   │   │   ├── usernames.py
│   │   │   ├── hashtags.py
│   │   │   ├── public_relationships.py
│   │   │   ├── timeline.py
│   │   │   ├── media.py
│   │   │   └── provenance.py
│   │   │
│   │   ├── personint/
│   │   │   ├── identity.py
│   │   │   ├── aliases.py
│   │   │   ├── public_profiles.py
│   │   │   ├── affiliations.py
│   │   │   ├── locations.py
│   │   │   ├── timeline.py
│   │   │   └── confidence.py
│   │   │
│   │   ├── usernameint/
│   │   │   ├── normalization.py
│   │   │   ├── discovery.py
│   │   │   ├── correlation.py
│   │   │   └── confidence.py
│   │   │
│   │   ├── corpint/
│   │   │   ├── legal_identity.py
│   │   │   ├── registrations.py
│   │   │   ├── officers.py
│   │   │   ├── ownership.py
│   │   │   ├── subsidiaries.py
│   │   │   ├── filings.py
│   │   │   ├── procurement.py
│   │   │   └── timeline.py
│   │   │
│   │   ├── domainint/
│   │   │   ├── domain.py
│   │   │   ├── rdap.py
│   │   │   ├── dns.py
│   │   │   ├── certificates.py
│   │   │   ├── historical_dns.py
│   │   │   ├── urls.py
│   │   │   ├── technologies.py
│   │   │   └── relationships.py
│   │   │
│   │   ├── infraint/
│   │   │   ├── ip.py
│   │   │   ├── asn.py
│   │   │   ├── prefix.py
│   │   │   ├── routing.py
│   │   │   ├── hosting.py
│   │   │   ├── certificates.py
│   │   │   └── historical.py
│   │   │
│   │   ├── cti/
│   │   │   ├── ioc.py
│   │   │   ├── cve.py
│   │   │   ├── cwe.py
│   │   │   ├── capec.py
│   │   │   ├── attack.py
│   │   │   ├── actor.py
│   │   │   ├── campaign.py
│   │   │   ├── malware.py
│   │   │   ├── advisory.py
│   │   │   ├── stix.py
│   │   │   ├── taxii.py
│   │   │   └── relationships.py
│   │   │
│   │   ├── geoint/
│   │   │   ├── coordinates.py
│   │   │   ├── geocoding.py
│   │   │   ├── reverse_geocoding.py
│   │   │   ├── boundaries.py
│   │   │   ├── distance.py
│   │   │   ├── clustering.py
│   │   │   ├── terrain.py
│   │   │   ├── imagery.py
│   │   │   └── confidence.py
│   │   │
│   │   ├── imint/
│   │   │   ├── metadata.py
│   │   │   ├── exif.py
│   │   │   ├── hashing.py
│   │   │   ├── perceptual_hash.py
│   │   │   ├── ocr.py
│   │   │   ├── objects.py
│   │   │   ├── scenes.py
│   │   │   ├── duplicate.py
│   │   │   ├── crops.py
│   │   │   ├── landmarks.py
│   │   │   └── provenance.py
│   │   │
│   │   ├── vidint/
│   │   │   ├── metadata.py
│   │   │   ├── keyframes.py
│   │   │   ├── scenes.py
│   │   │   ├── ocr.py
│   │   │   ├── objects.py
│   │   │   ├── audio_track.py
│   │   │   ├── timeline.py
│   │   │   ├── duplicate.py
│   │   │   └── provenance.py
│   │   │
│   │   ├── audint/
│   │   │   ├── metadata.py
│   │   │   ├── transcription.py
│   │   │   ├── language.py
│   │   │   ├── diarization.py
│   │   │   ├── segmentation.py
│   │   │   ├── entities.py
│   │   │   ├── timeline.py
│   │   │   └── provenance.py
│   │   │
│   │   ├── docint/
│   │   │   ├── metadata.py
│   │   │   ├── text.py
│   │   │   ├── ocr.py
│   │   │   ├── layout.py
│   │   │   ├── tables.py
│   │   │   ├── citations.py
│   │   │   ├── urls.py
│   │   │   ├── embedded_files.py
│   │   │   ├── entities.py
│   │   │   ├── claims.py
│   │   │   └── provenance.py
│   │   │
│   │   ├── codeint/
│   │   │   ├── repository.py
│   │   │   ├── commits.py
│   │   │   ├── contributors.py
│   │   │   ├── dependencies.py
│   │   │   ├── packages.py
│   │   │   └── provenance.py
│   │   │
│   │   ├── archiveint/
│   │   │   ├── snapshots.py
│   │   │   ├── changes.py
│   │   │   └── historical_state.py
│   │   │
│   │   └── darkint/
│   │       ├── policy.py
│   │       ├── passive_collection.py
│   │       ├── isolation.py
│   │       ├── quarantine.py
│   │       ├── safe_parser.py
│   │       └── provenance.py
│   │
│   │
│   │==================================================================
│   │ 04. SOURCE / CONNECTOR FABRIC
│   │==================================================================
│   │
│   ├── sources/
│   │   ├── registry.py
│   │   ├── manifest.py
│   │   ├── capability.py
│   │   ├── router.py
│   │   ├── selector.py
│   │   ├── ranker.py
│   │   ├── scoring.py
│   │   ├── health.py
│   │   ├── qualification.py
│   │   ├── lifecycle.py
│   │   ├── lineage.py
│   │   ├── independence.py
│   │   ├── syndication.py
│   │   ├── authority.py
│   │   ├── freshness.py
│   │   ├── cost.py
│   │   ├── quota.py
│   │   ├── rate_limit.py
│   │   ├── credentials.py
│   │   ├── availability.py
│   │   └── errors.py
│   │
│   │   ├── connectors/
│   │   │   ├── base.py
│   │   │   ├── http.py
│   │   │   ├── rest.py
│   │   │   ├── graphql.py
│   │   │   ├── rss.py
│   │   │   ├── atom.py
│   │   │   ├── search.py
│   │   │   ├── archive.py
│   │   │   ├── dataset.py
│   │   │   ├── file_feed.py
│   │   │   ├── webhook.py
│   │   │   ├── dns.py
│   │   │   ├── rdap.py
│   │   │   ├── stix.py
│   │   │   ├── taxii.py
│   │   │   ├── misp.py
│   │   │   ├── stream.py
│   │   │   ├── pagination.py
│   │   │   ├── retries.py
│   │   │   ├── circuit_breaker.py
│   │   │   ├── normalization.py
│   │   │   └── evidence_capture.py
│   │
│   │   └── providers/
│   │       ├── dns/
│   │       ├── rdap/
│   │       ├── certificate_transparency/
│   │       ├── search/
│   │       ├── archives/
│   │       ├── social/
│   │       ├── communities/
│   │       ├── companies/
│   │       ├── registries/
│   │       ├── government/
│   │       ├── procurement/
│   │       ├── legal/
│   │       ├── sanctions/
│   │       ├── infrastructure/
│   │       ├── cti/
│   │       ├── vulnerabilities/
│   │       ├── malware/
│   │       ├── geo/
│   │       ├── maps/
│   │       ├── satellite/
│   │       ├── transport/
│   │       ├── images/
│   │       ├── video/
│   │       ├── audio/
│   │       ├── documents/
│   │       ├── news/
│   │       ├── academic/
│   │       ├── code/
│   │       ├── packages/
│   │       ├── exposure/
│   │       └── datasets/
│   │
│   │
│   │==================================================================
│   │ 05. EVIDENCE / PROVENANCE
│   │==================================================================
│   │
│   ├── evidence/
│   │   ├── object.py
│   │   ├── store.py
│   │   ├── capture.py
│   │   ├── raw_bytes.py
│   │   ├── hashing.py
│   │   ├── integrity.py
│   │   ├── provenance.py
│   │   ├── custody.py
│   │   ├── metadata.py
│   │   ├── artifact.py
│   │   ├── lineage.py
│   │   ├── source_snapshot.py
│   │   ├── versioning.py
│   │   ├── deduplication.py
│   │   ├── retention.py
│   │   ├── access.py
│   │   ├── replay.py
│   │   ├── replay_manifest.py
│   │   ├── citations.py
│   │   ├── export.py
│   │   └── validation.py
│   │
│   │
│   │==================================================================
│   │ 06. ENTITY RESOLUTION V3
│   │==================================================================
│   │
│   ├── entities/
│   │   ├── registry.py
│   │   ├── schema.py
│   │   ├── normalization.py
│   │   ├── blocking.py
│   │   ├── candidate_generation.py
│   │   ├── features.py
│   │   ├── exact_match.py
│   │   ├── fuzzy_match.py
│   │   ├── probabilistic.py
│   │   ├── temporal.py
│   │   ├── geographic.py
│   │   ├── contextual.py
│   │   ├── conflicts.py
│   │   ├── scorer.py
│   │   ├── thresholds.py
│   │   ├── calibration.py
│   │   ├── resolver.py
│   │   ├── merger.py
│   │   ├── splitter.py
│   │   ├── reversible_merge.py
│   │   ├── history.py
│   │   ├── explanation.py
│   │   └── evaluation.py
│   │
│   │
│   │==================================================================
│   │ 07. TEMPORAL KNOWLEDGE GRAPH
│   │==================================================================
│   │
│   ├── graph/
│   │   ├── model.py
│   │   ├── node.py
│   │   ├── edge.py
│   │   ├── builder.py
│   │   ├── repository.py
│   │   ├── query.py
│   │   ├── traversal.py
│   │   ├── expansion.py
│   │   ├── shortest_path.py
│   │   ├── khop.py
│   │   ├── connected_components.py
│   │   ├── community.py
│   │   ├── centrality.py
│   │   ├── bridges.py
│   │   ├── temporal.py
│   │   ├── snapshots.py
│   │   ├── diff.py
│   │   ├── evidence_links.py
│   │   ├── confidence.py
│   │   ├── rebuild.py
│   │   └── export.py
│   │
│   ├── timeline/
│   │   ├── model.py
│   │   ├── builder.py
│   │   ├── normalizer.py
│   │   ├── events.py
│   │   ├── event_time.py
│   │   ├── validity_time.py
│   │   ├── observation_time.py
│   │   ├── retrieval_time.py
│   │   ├── correlation.py
│   │   ├── conflicts.py
│   │   ├── snapshots.py
│   │   ├── query.py
│   │   └── export.py
│   │
│   │
│   │==================================================================
│   │ 08. SOURCE INDEPENDENCE
│   │==================================================================
│   │
│   ├── independence/
│   │   ├── graph.py
│   │   ├── fingerprints.py
│   │   ├── exact_duplicate.py
│   │   ├── shingles.py
│   │   ├── minhash.py
│   │   ├── simhash.py
│   │   ├── near_duplicate.py
│   │   ├── citation_extraction.py
│   │   ├── citation_graph.py
│   │   ├── syndication.py
│   │   ├── upstream_dataset.py
│   │   ├── publisher_ownership.py
│   │   ├── temporal_copying.py
│   │   ├── classifier.py
│   │   └── explanation.py
│   │
│   │
│   │==================================================================
│   │ 09. CONTRADICTION + VERIFICATION
│   │==================================================================
│   │
│   ├── verification/
│   │   ├── engine.py
│   │   ├── integrity.py
│   │   ├── corroboration.py
│   │   ├── adversarial.py
│   │   ├── claim_verifier.py
│   │   ├── identity_verifier.py
│   │   ├── relationship_verifier.py
│   │   ├── source_authority.py
│   │   ├── source_independence.py
│   │   ├── freshness.py
│   │   ├── temporal_consistency.py
│   │   ├── alternative_explanations.py
│   │   ├── association_vs_culpability.py
│   │   ├── confidence.py
│   │   ├── calibration.py
│   │   └── decision.py
│   │
│   ├── contradictions/
│   │   ├── engine.py
│   │   ├── candidate_pairs.py
│   │   ├── value_conflict.py
│   │   ├── temporal_conflict.py
│   │   ├── identity_conflict.py
│   │   ├── location_conflict.py
│   │   ├── ownership_conflict.py
│   │   ├── registration_conflict.py
│   │   ├── source_disagreement.py
│   │   ├── historical_current.py
│   │   ├── severity.py
│   │   └── resolution.py
│   │
│   │
│   │==================================================================
│   │ 10. AI MODEL GATEWAY
│   │==================================================================
│   │
│   ├── ai/
│   │   ├── gateway.py
│   │   ├── adapter.py
│   │   ├── router.py
│   │   ├── routing_policy.py
│   │   ├── capability.py
│   │   ├── budget.py
│   │   ├── cost.py
│   │   ├── fallback.py
│   │   ├── structured_output.py
│   │   ├── validation.py
│   │   ├── context.py
│   │   ├── context_window.py
│   │   ├── untrusted_content.py
│   │   ├── injection_detection.py
│   │   ├── output_sanitization.py
│   │   ├── telemetry.py
│   │   │
│   │   ├── providers/
│   │   │   ├── ollama.py
│   │   │   ├── openai.py
│   │   │   ├── anthropic.py
│   │   │   ├── gemini.py
│   │   │   ├── grok.py
│   │   │   ├── qwen.py
│   │   │   ├── deepseek.py
│   │   │   └── mistral.py
│   │   │
│   │   └── tasks/
│   │       ├── extraction.py
│   │       ├── classification.py
│   │       ├── planning.py
│   │       ├── reasoning.py
│   │       ├── summarization.py
│   │       ├── entity_resolution.py
│   │       ├── contradiction.py
│   │       └── verification.py
│   │
│   │
│   │==================================================================
│   │ 11. REPORT GENERATION
│   │==================================================================
│   │
│   ├── reporting/
│   │   ├── builder.py
│   │   ├── statement_validator.py
│   │   ├── executive_summary.py
│   │   ├── scope.py
│   │   ├── methodology.py
│   │   ├── findings.py
│   │   ├── entities.py
│   │   ├── relationships.py
│   │   ├── graph.py
│   │   ├── timeline.py
│   │   ├── claims.py
│   │   ├── contradictions.py
│   │   ├── unknowns.py
│   │   ├── limitations.py
│   │   ├── evidence_table.py
│   │   ├── recommendations.py
│   │   ├── citations.py
│   │   ├── replay_manifest.py
│   │   ├── export_html.py
│   │   ├── export_pdf.py
│   │   ├── export_json.py
│   │   ├── export_csv.py
│   │   ├── export_graph.py
│   │   └── export_stix.py
│   │
│   │
│   │==================================================================
│   │ 12. SECURITY / GOVERNANCE / PRIVACY
│   │==================================================================
│   │
│   ├── security/
│   │   ├── authentication.py
│   │   ├── authorization.py
│   │   ├── rbac.py
│   │   ├── abac.py
│   │   ├── tenant_isolation.py
│   │   ├── case_isolation.py
│   │   ├── service_identity.py
│   │   ├── connector_permissions.py
│   │   ├── secrets.py
│   │   ├── encryption.py
│   │   ├── redaction.py
│   │   ├── pii.py
│   │   ├── retention.py
│   │   ├── deletion.py
│   │   ├── ssrf.py
│   │   ├── url_policy.py
│   │   ├── egress.py
│   │   ├── prompt_injection.py
│   │   ├── tool_injection.py
│   │   ├── agent_policy.py
│   │   ├── malicious_document.py
│   │   ├── media_sandbox.py
│   │   ├── rate_limit.py
│   │   ├── quota.py
│   │   ├── approval.py
│   │   ├── audit.py
│   │   └── kill_switch.py
│   │
│   ├── policy/
│   │   ├── engine.py
│   │   ├── authorization.py
│   │   ├── scope.py
│   │   ├── source_policy.py
│   │   ├── action_policy.py
│   │   ├── jurisdiction.py
│   │   ├── privacy.py
│   │   ├── retention.py
│   │   ├── human_approval.py
│   │   └── decision.py
│   │
│   │
│   │==================================================================
│   │ 13. STORAGE / DATABASE
│   │==================================================================
│   │
│   ├── db/
│   │   ├── base.py
│   │   ├── session.py
│   │   ├── transaction.py
│   │   ├── health.py
│   │   │
│   │   ├── models/
│   │   │   ├── user.py
│   │   │   ├── tenant.py
│   │   │   ├── case.py
│   │   │   ├── objective.py
│   │   │   ├── investigation.py
│   │   │   ├── task.py
│   │   │   ├── employee.py
│   │   │   ├── source.py
│   │   │   ├── connector.py
│   │   │   ├── evidence.py
│   │   │   ├── artifact.py
│   │   │   ├── entity.py
│   │   │   ├── relationship.py
│   │   │   ├── observation.py
│   │   │   ├── claim.py
│   │   │   ├── hypothesis.py
│   │   │   ├── contradiction.py
│   │   │   ├── event.py
│   │   │   ├── timeline.py
│   │   │   ├── report.py
│   │   │   ├── audit.py
│   │   │   └── model_usage.py
│   │   │
│   │   ├── repositories/
│   │   │   ├── cases.py
│   │   │   ├── investigations.py
│   │   │   ├── tasks.py
│   │   │   ├── sources.py
│   │   │   ├── evidence.py
│   │   │   ├── entities.py
│   │   │   ├── relationships.py
│   │   │   ├── claims.py
│   │   │   ├── contradictions.py
│   │   │   ├── timelines.py
│   │   │   ├── reports.py
│   │   │   └── audits.py
│   │   │
│   │   └── migrations/
│   │
│   ├── storage/
│   │   ├── interface.py
│   │   ├── local.py
│   │   ├── s3.py
│   │   ├── minio.py
│   │   ├── evidence.py
│   │   ├── artifacts.py
│   │   └── backups.py
│   │
│   │
│   │==================================================================
│   │ 14. API
│   │==================================================================
│   │
│   ├── api/
│   │   ├── app.py
│   │   ├── lifespan.py
│   │   ├── dependencies.py
│   │   ├── middleware.py
│   │   ├── authentication.py
│   │   ├── pagination.py
│   │   ├── errors.py
│   │   ├── websocket.py
│   │   │
│   │   ├── routes/
│   │   │   ├── auth.py
│   │   │   ├── cases.py
│   │   │   ├── objectives.py
│   │   │   ├── investigations.py
│   │   │   ├── tasks.py
│   │   │   ├── employees.py
│   │   │   ├── sources.py
│   │   │   ├── connectors.py
│   │   │   ├── evidence.py
│   │   │   ├── entities.py
│   │   │   ├── relationships.py
│   │   │   ├── graph.py
│   │   │   ├── timeline.py
│   │   │   ├── claims.py
│   │   │   ├── hypotheses.py
│   │   │   ├── contradictions.py
│   │   │   ├── gaps.py
│   │   │   ├── geo.py
│   │   │   ├── media.py
│   │   │   ├── cti.py
│   │   │   ├── reports.py
│   │   │   ├── replay.py
│   │   │   ├── audit.py
│   │   │   ├── health.py
│   │   │   ├── metrics.py
│   │   │   └── admin.py
│   │   │
│   │   └── schemas/
│   │       ├── common.py
│   │       ├── auth.py
│   │       ├── cases.py
│   │       ├── objectives.py
│   │       ├── investigations.py
│   │       ├── sources.py
│   │       ├── evidence.py
│   │       ├── entities.py
│   │       ├── graph.py
│   │       ├── claims.py
│   │       ├── reports.py
│   │       └── errors.py
│   │
│   └── cli/
│       ├── main.py
│       ├── case.py
│       ├── investigate.py
│       ├── employee.py
│       ├── source.py
│       ├── evidence.py
│       ├── replay.py
│       ├── report.py
│       └── doctor.py
│
│
│======================================================================
│ 15. 650+ GOVERNED SOURCE CATALOG
│======================================================================
│
├── sources/
│   ├── schema/
│   │   ├── source.schema.json
│   │   ├── connector.schema.json
│   │   └── qualification.schema.json
│   │
│   ├── catalog/
│   │   ├── web.yaml
│   │   ├── search.yaml
│   │   ├── social.yaml
│   │   ├── communities.yaml
│   │   ├── people.yaml
│   │   ├── usernames.yaml
│   │   ├── companies.yaml
│   │   ├── registries.yaml
│   │   ├── government.yaml
│   │   ├── domains.yaml
│   │   ├── dns.yaml
│   │   ├── ip.yaml
│   │   ├── asn.yaml
│   │   ├── certificates.yaml
│   │   ├── infrastructure.yaml
│   │   ├── cti.yaml
│   │   ├── malware.yaml
│   │   ├── vulnerabilities.yaml
│   │   ├── geo.yaml
│   │   ├── maps.yaml
│   │   ├── satellite.yaml
│   │   ├── transport.yaml
│   │   ├── images.yaml
│   │   ├── video.yaml
│   │   ├── audio.yaml
│   │   ├── documents.yaml
│   │   ├── news.yaml
│   │   ├── archives.yaml
│   │   ├── academic.yaml
│   │   ├── code.yaml
│   │   ├── packages.yaml
│   │   ├── procurement.yaml
│   │   ├── sanctions.yaml
│   │   ├── legal.yaml
│   │   ├── exposure.yaml
│   │   └── datasets.yaml
│   │
│   ├── qualification/
│   │   ├── documented/
│   │   ├── integration_tested/
│   │   ├── live_verified/
│   │   └── production_qualified/
│   │
│   └── fixtures/
│
│
│======================================================================
│ 16. INVESTIGATOR WEBSITE
│======================================================================
│
├── web/
│   ├── package.json
│   ├── next.config.ts
│   ├── tsconfig.json
│   ├── middleware.ts
│   ├── instrumentation.ts
│   ├── globals.css
│   │
│   ├── app/
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   ├── login/page.tsx
│   │   ├── dashboard/page.tsx
│   │   │
│   │   ├── cases/
│   │   │   ├── page.tsx
│   │   │   ├── new/page.tsx
│   │   │   └── [caseId]/
│   │   │       ├── page.tsx
│   │   │       ├── objective/page.tsx
│   │   │       ├── investigation/page.tsx
│   │   │       ├── entities/page.tsx
│   │   │       ├── graph/page.tsx
│   │   │       ├── timeline/page.tsx
│   │   │       ├── map/page.tsx
│   │   │       ├── evidence/page.tsx
│   │   │       ├── claims/page.tsx
│   │   │       ├── contradictions/page.tsx
│   │   │       ├── gaps/page.tsx
│   │   │       ├── sources/page.tsx
│   │   │       ├── employees/page.tsx
│   │   │       ├── reports/page.tsx
│   │   │       └── audit/page.tsx
│   │   │
│   │   ├── people/page.tsx
│   │   ├── companies/page.tsx
│   │   ├── social/page.tsx
│   │   ├── infrastructure/page.tsx
│   │   ├── cti/page.tsx
│   │   ├── geo/page.tsx
│   │   ├── media/page.tsx
│   │   ├── documents/page.tsx
│   │   ├── sources/page.tsx
│   │   ├── employees/page.tsx
│   │   ├── administration/page.tsx
│   │   └── settings/page.tsx
│   │
│   ├── components/
│   │   ├── shell/
│   │   ├── cases/
│   │   ├── objective/
│   │   ├── investigation/
│   │   ├── employee/
│   │   ├── entity/
│   │   ├── graph/
│   │   ├── timeline/
│   │   ├── map/
│   │   ├── evidence/
│   │   ├── claim/
│   │   ├── contradiction/
│   │   ├── source/
│   │   ├── report/
│   │   ├── audit/
│   │   └── ui/
│   │
│   ├── lib/
│   │   ├── api.ts
│   │   ├── auth.ts
│   │   ├── websocket.ts
│   │   ├── graph.ts
│   │   ├── map.ts
│   │   ├── formatting.ts
│   │   └── validation.ts
│   │
│   ├── hooks/
│   ├── stores/
│   ├── types/
│   ├── public/
│   └── tests/
│
│
│======================================================================
│ 17. OBSERVABILITY
│======================================================================
│
├── observability/
│   ├── logging.py
│   ├── tracing.py
│   ├── metrics.py
│   ├── context.py
│   ├── source_metrics.py
│   ├── connector_metrics.py
│   ├── employee_metrics.py
│   ├── model_metrics.py
│   ├── investigation_metrics.py
│   ├── evidence_metrics.py
│   ├── verification_metrics.py
│   ├── cost_metrics.py
│   ├── alerts.py
│   ├── dashboards.py
│   └── health.py
│
│
│======================================================================
│ 18. EVALUATION / ENTERPRISE ACCEPTANCE
│======================================================================
│
├── evaluation/
│   ├── runner.py
│   ├── suite.py
│   ├── dataset.py
│   ├── scoring.py
│   ├── baseline.py
│   ├── regression.py
│   ├── report.py
│   │
│   ├── metrics/
│   │   ├── collection_success.py
│   │   ├── parser_accuracy.py
│   │   ├── evidence_precision.py
│   │   ├── citation_accuracy.py
│   │   ├── unsupported_claim_rate.py
│   │   ├── entity_precision.py
│   │   ├── entity_recall.py
│   │   ├── false_merge_rate.py
│   │   ├── false_split_rate.py
│   │   ├── relationship_precision.py
│   │   ├── contradiction_recall.py
│   │   ├── independence_accuracy.py
│   │   ├── planner_quality.py
│   │   ├── nba_quality.py
│   │   ├── completion_rate.py
│   │   ├── replay_success.py
│   │   ├── latency.py
│   │   ├── cost.py
│   │   └── human_correction_rate.py
│   │
│   ├── golden/
│   │   ├── domain/
│   │   ├── ip/
│   │   ├── company/
│   │   ├── person/
│   │   ├── username/
│   │   ├── social/
│   │   ├── cti/
│   │   ├── geo/
│   │   ├── image/
│   │   ├── video/
│   │   ├── audio/
│   │   ├── document/
│   │   ├── multilingual/
│   │   ├── cross_domain/
│   │   ├── failure/
│   │   └── adversarial/
│   │
│   └── benchmarks/
│       ├── maltego/
│       ├── spiderfoot/
│       ├── recon_ng/
│       └── baseline/
│
│
│======================================================================
│ 19. TEST SUITES
│======================================================================
│
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   ├── unit/
│   ├── integration/
│   ├── contracts/
│   ├── connectors/
│   ├── sources/
│   ├── objectives/
│   ├── planning/
│   ├── investigation/
│   ├── employees/
│   ├── reasoning/
│   ├── evidence/
│   ├── entity_resolution/
│   ├── graph/
│   ├── timeline/
│   ├── independence/
│   ├── contradictions/
│   ├── verification/
│   ├── ai/
│   ├── reporting/
│   ├── policy/
│   ├── api/
│   ├── database/
│   ├── storage/
│   ├── security/
│   ├── replay/
│   ├── golden/
│   ├── chaos/
│   ├── failure/
│   ├── performance/
│   ├── load/
│   └── adversarial/
│
│
│======================================================================
│ 20. DEPLOYMENT / INFRASTRUCTURE
│======================================================================
│
├── deploy/
│   ├── docker/
│   │   ├── backend.Dockerfile
│   │   ├── worker.Dockerfile
│   │   ├── web.Dockerfile
│   │   └── compose.production.yml
│   │
│   ├── kubernetes/
│   │   ├── namespace.yaml
│   │   ├── backend.yaml
│   │   ├── worker.yaml
│   │   ├── web.yaml
│   │   ├── redis.yaml
│   │   ├── ingress.yaml
│   │   ├── network-policy.yaml
│   │   └── autoscaling.yaml
│   │
│   ├── supabase/
│   │   ├── config.toml
│   │   ├── migrations/
│   │   ├── seed.sql
│   │   └── policies/
│   │
│   ├── vercel/
│   │   └── vercel.json
│   │
│   └── monitoring/
│       ├── otel-collector.yaml
│       ├── prometheus.yml
│       ├── alerts.yml
│       └── dashboards/
│
│
│======================================================================
│ 21. CI/CD
│======================================================================
│
├── .github/
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   ├── pull_request_template.md
│   │
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug.yml
│   │   ├── feature.yml
│   │   ├── connector.yml
│   │   └── security.yml
│   │
│   └── workflows/
│       ├── ci.yml
│       ├── lint.yml
│       ├── typing.yml
│       ├── unit-tests.yml
│       ├── integration-tests.yml
│       ├── connector-tests.yml
│       ├── source-canary.yml
│       ├── golden-evaluation.yml
│       ├── frontend.yml
│       ├── security.yml
│       ├── codeql.yml
│       ├── dependency-review.yml
│       ├── container-scan.yml
│       ├── performance.yml
│       ├── release.yml
│       └── deploy.yml
│
│
│======================================================================
│ 22. AUTOMATION / OPERATIONS SCRIPTS
│======================================================================
│
├── scripts/
│   ├── setup.sh
│   ├── dev.sh
│   ├── start.sh
│   ├── stop.sh
│   ├── test.sh
│   ├── lint.sh
│   ├── migrate.sh
│   ├── seed.py
│   ├── seed_sources.py
│   ├── validate_sources.py
│   ├── qualify_sources.py
│   ├── source_canary.py
│   ├── run_golden.py
│   ├── benchmark.py
│   ├── check_acceptance.py
│   ├── check_docs.py
│   ├── check_migrations.py
│   ├── backup.sh
│   ├── restore.sh
│   └── release.sh
│
│
│======================================================================
│ 23. COUNTRY / LANGUAGE PACKS
│======================================================================
│
├── packs/
│   ├── countries/
│   │   ├── india/
│   │   │   ├── registries.yaml
│   │   │   ├── government.yaml
│   │   │   ├── courts.yaml
│   │   │   ├── procurement.yaml
│   │   │   ├── geography.yaml
│   │   │   └── normalization.yaml
│   │   └── README.md
│   │
│   └── languages/
│       ├── english.yaml
│       ├── hindi.yaml
│       ├── roman_hindi.yaml
│       └── transliteration.yaml
│
│
│======================================================================
│ 24. PERSISTENT AI ENGINEERING STATE
│======================================================================
│
├── .ai/
│   ├── CURRENT_STATE.md
│   ├── ACTIVE_WORK.md
│   ├── TASKS.md
│   ├── MEMORY.md
│   ├── DECISIONS.md
│   ├── KNOWN_ISSUES.md
│   ├── BLOCKERS.md
│   ├── SCORECARD.md
│   ├── SESSION_CONTEXT.md
│   ├── IMPLEMENTATION_LEDGER.md
│   ├── SOURCE_LEDGER.md
│   ├── EVALUATION_LEDGER.md
│   ├── SECURITY_LEDGER.md
│   └── CHANGELOG.md
│
│
│======================================================================
│ 25. DOCUMENTATION AS EXECUTABLE REQUIREMENTS
│======================================================================
│
└── docs/
    ├── CURRENT_STATE.md
    ├── ARCHITECTURE.md
    ├── FLOW.md
    ├── DATA_MODEL.md
    ├── SOURCE_STRATEGY.md
    ├── INTEGRATION_MAP.md
    ├── SECURITY.md
    ├── PRIVACY.md
    ├── AI_EMPLOYEE.md
    ├── ENTITY_RESOLUTION.md
    ├── KNOWLEDGE_GRAPH.md
    ├── VERIFICATION.md
    ├── EVIDENCE.md
    ├── OPERATIONS.md
    ├── DEPLOYMENT.md
    ├── TESTING.md
    ├── EVALUATION.md
    ├── ACCEPTANCE_GATES.md
    │
    ├── architecture/
    │   ├── system.md
    │   ├── backend.md
    │   ├── frontend.md
    │   ├── workers.md
    │   ├── data.md
    │   ├── evidence.md
    │   ├── graph.md
    │   ├── ai.md
    │   └── deployment.md
    │
    ├── api/
    │   ├── overview.md
    │   ├── authentication.md
    │   ├── cases.md
    │   ├── investigations.md
    │   ├── evidence.md
    │   ├── graph.md
    │   └── reports.md
    │
    ├── sources/
    │   ├── connector-sdk.md
    │   ├── source-registry.md
    │   ├── qualification.md
    │   ├── independence.md
    │   └── lifecycle.md
    │
    ├── employees/
    │   ├── architecture.md
    │   ├── roles.md
    │   ├── skills.md
    │   ├── permissions.md
    │   ├── memory.md
    │   └── handoffs.md
    │
    ├── security/
    │   ├── threat-model.md
    │   ├── trust-boundaries.md
    │   ├── authorization.md
    │   ├── prompt-injection.md
    │   ├── connector-security.md
    │   ├── tenant-isolation.md
    │   └── incident-response.md
    │
    ├── runbooks/
    │   ├── deployment.md
    │   ├── rollback.md
    │   ├── source-outage.md
    │   ├── model-outage.md
    │   ├── database-recovery.md
    │   ├── evidence-recovery.md
    │   └── incident.md
    │
    └── program/
        ├── MASTER_GAP_REGISTER.md
        ├── DOC_REQUIREMENT_INDEX.md
        ├── DOC_TO_CODE_MATRIX.md
        ├── COMPLETION_LEDGER.md
        ├── DOC_CONFLICTS.md
        ├── ENTERPRISE_8_SCORECARD.md
        ├── ACCEPTANCE_STATUS.md
        ├── SOURCE_QUALIFICATION_LEDGER.md
        ├── CONNECTOR_MATRIX.md
        ├── GOLDEN_INVESTIGATION_RESULTS.md
        ├── ENTITY_RESOLUTION_BENCHMARK.md
        ├── SECURITY_VALIDATION.md
        ├── THREAT_MODEL.md
        ├── PERFORMANCE_RESULTS.md
        ├── DEPLOYMENT_STATUS.md
        ├── OPERATIONS_RUNBOOK.md
        ├── COMPETITOR_BENCHMARK.md
        └── RELEASE_READINESS.md






TraceAtlas-Automator/
│
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── AGENTS.md
│
├── pyproject.toml
├── uv.lock
├── package.json
├── pnpm-lock.yaml
├── tsconfig.json
├── eslint.config.js
├── docker-compose.yml
├── Dockerfile
├── Makefile
├── .env.example
├── .gitignore
├── .dockerignore
│
│
│ ================================================================
│  01. TRACEATLAS PYTHON BACKEND
│ ================================================================
│
├── traceatlas/
│   ├── __init__.py
│   ├── __main__.py
│   ├── config.py
│   ├── version.py
│   ├── constants.py
│   ├── exceptions.py
│   │
│   ├── core/
│   │   ├── case.py
│   │   ├── objective.py
│   │   ├── scope.py
│   │   ├── authorization.py
│   │   ├── target.py
│   │   ├── entity.py
│   │   ├── relationship.py
│   │   ├── evidence.py
│   │   ├── observation.py
│   │   ├── claim.py
│   │   ├── hypothesis.py
│   │   ├── contradiction.py
│   │   ├── confidence.py
│   │   ├── verification.py
│   │   ├── knowledge_state.py
│   │   ├── information_gap.py
│   │   ├── next_action.py
│   │   ├── timeline.py
│   │   ├── source.py
│   │   ├── provenance.py
│   │   ├── task.py
│   │   ├── result.py
│   │   ├── budget.py
│   │   ├── cost.py
│   │   ├── jurisdiction.py
│   │   ├── language.py
│   │   ├── identifiers.py
│   │   ├── enums.py
│   │   ├── validation.py
│   │   └── serialization.py
│   │
│   │
│   │ ============================================================
│   │  02. GOAL-ORIENTED INVESTIGATION ENGINE
│   │ ============================================================
│   │
│   ├── investigation/
│   │   ├── manager.py
│   │   ├── state.py
│   │   ├── session.py
│   │   │
│   │   ├── objective/
│   │   │   ├── parser.py
│   │   │   ├── classifier.py
│   │   │   ├── target_extractor.py
│   │   │   ├── question_generator.py
│   │   │   ├── scope_resolver.py
│   │   │   └── validator.py
│   │   │
│   │   ├── planning/
│   │   │   ├── planner.py
│   │   │   ├── semantic_planner.py
│   │   │   ├── capability_planner.py
│   │   │   ├── evidence_planner.py
│   │   │   ├── source_planner.py
│   │   │   ├── verification_planner.py
│   │   │   ├── cost_planner.py
│   │   │   └── plan_validator.py
│   │   │
│   │   ├── execution/
│   │   │   ├── executor.py
│   │   │   ├── scheduler.py
│   │   │   ├── task_queue.py
│   │   │   ├── dependencies.py
│   │   │   ├── wave_executor.py
│   │   │   ├── parallel.py
│   │   │   ├── retry.py
│   │   │   ├── cancellation.py
│   │   │   └── checkpoints.py
│   │   │
│   │   ├── reasoning/
│   │   │   ├── hypothesis_engine.py
│   │   │   ├── claim_engine.py
│   │   │   ├── gap_engine.py
│   │   │   ├── next_best_action.py
│   │   │   ├── information_gain.py
│   │   │   └── stopping_engine.py
│   │   │
│   │   └── review/
│   │       ├── completeness.py
│   │       ├── quality.py
│   │       └── readiness.py
│   │
│   │
│   │ ============================================================
│   │  03. AI EMPLOYEE OPERATING SYSTEM
│   │ ============================================================
│   │
│   ├── employees/
│   │   ├── base.py
│   │   ├── manifest.py
│   │   ├── registry.py
│   │   ├── permissions.py
│   │   ├── context.py
│   │   ├── state.py
│   │   ├── memory.py
│   │   ├── budget.py
│   │   ├── task_envelope.py
│   │   ├── result_envelope.py
│   │   ├── dispatcher.py
│   │   ├── orchestrator.py
│   │   ├── supervisor.py
│   │   ├── router.py
│   │   ├── handoff.py
│   │   ├── checkpoint.py
│   │   ├── review.py
│   │   └── telemetry.py
│   │
│   │   ├── workers/
│   │   │   ├── investigation_manager.py
│   │   │   ├── investigation_planner.py
│   │   │   ├── source_router.py
│   │   │   ├── collection_coordinator.py
│   │   │   ├── osint_analyst.py
│   │   │   ├── web_analyst.py
│   │   │   ├── search_analyst.py
│   │   │   ├── socmint_analyst.py
│   │   │   ├── person_analyst.py
│   │   │   ├── username_analyst.py
│   │   │   ├── company_analyst.py
│   │   │   ├── corporate_analyst.py
│   │   │   ├── domain_analyst.py
│   │   │   ├── dns_analyst.py
│   │   │   ├── ip_analyst.py
│   │   │   ├── infrastructure_analyst.py
│   │   │   ├── cti_analyst.py
│   │   │   ├── vulnerability_analyst.py
│   │   │   ├── malware_context_analyst.py
│   │   │   ├── geo_analyst.py
│   │   │   ├── image_analyst.py
│   │   │   ├── video_analyst.py
│   │   │   ├── audio_analyst.py
│   │   │   ├── document_analyst.py
│   │   │   ├── code_analyst.py
│   │   │   ├── archive_analyst.py
│   │   │   ├── news_analyst.py
│   │   │   ├── entity_resolution_analyst.py
│   │   │   ├── graph_analyst.py
│   │   │   ├── timeline_analyst.py
│   │   │   ├── contradiction_analyst.py
│   │   │   ├── verification_analyst.py
│   │   │   ├── evidence_gap_analyst.py
│   │   │   ├── report_analyst.py
│   │   │   ├── quality_supervisor.py
│   │   │   └── compliance_supervisor.py
│   │
│   │   └── skills/
│   │       ├── search.py
│   │       ├── extract.py
│   │       ├── correlate.py
│   │       ├── verify.py
│   │       ├── resolve.py
│   │       ├── graph.py
│   │       ├── timeline.py
│   │       ├── geolocate.py
│   │       ├── analyze_media.py
│   │       ├── analyze_document.py
│   │       └── report.py
│   │
│   │
│   │ ============================================================
│   │  04. INTELLIGENCE DISCIPLINES
│   │ ============================================================
│   │
│   ├── intelligence/
│   │   ├── osint/
│   │   ├── webint/
│   │   ├── searchint/
│   │   ├── socmint/
│   │   ├── personint/
│   │   ├── usernameint/
│   │   ├── corpint/
│   │   ├── businessint/
│   │   ├── regint/
│   │   ├── procurementint/
│   │   ├── legalint/
│   │   ├── domainint/
│   │   ├── dnsint/
│   │   ├── ipint/
│   │   ├── asnint/
│   │   ├── infraint/
│   │   ├── netint/
│   │   ├── cloudint/
│   │   ├── cti/
│   │   ├── malint/
│   │   ├── vulnint/
│   │   ├── codeint/
│   │   ├── packageint/
│   │   ├── geoint/
│   │   ├── imint/
│   │   ├── vidint/
│   │   ├── audint/
│   │   ├── docint/
│   │   ├── archiveint/
│   │   ├── newsint/
│   │   ├── supplychain/
│   │   ├── datasetint/
│   │   └── darkint/
│   │
│   │
│   │ ============================================================
│   │  05. SOURCE INTELLIGENCE FABRIC
│   │ ============================================================
│   │
│   ├── sources/
│   │   ├── registry.py
│   │   ├── manifest.py
│   │   ├── capabilities.py
│   │   ├── selector.py
│   │   ├── ranking.py
│   │   ├── health.py
│   │   ├── qualification.py
│   │   ├── lineage.py
│   │   ├── independence.py
│   │   ├── cost.py
│   │   ├── quotas.py
│   │   ├── credentials.py
│   │   ├── lifecycle.py
│   │   └── errors.py
│   │
│   │   ├── connectors/
│   │   │   ├── base.py
│   │   │   ├── rest.py
│   │   │   ├── graphql.py
│   │   │   ├── rss.py
│   │   │   ├── atom.py
│   │   │   ├── search.py
│   │   │   ├── archive.py
│   │   │   ├── dataset.py
│   │   │   ├── file_feed.py
│   │   │   ├── webhook.py
│   │   │   ├── dns.py
│   │   │   ├── rdap.py
│   │   │   ├── stix.py
│   │   │   ├── taxii.py
│   │   │   ├── misp.py
│   │   │   └── stream.py
│   │
│   │   └── providers/
│   │       ├── dns/
│   │       ├── domains/
│   │       ├── infrastructure/
│   │       ├── social/
│   │       ├── companies/
│   │       ├── government/
│   │       ├── cti/
│   │       ├── vulnerabilities/
│   │       ├── geo/
│   │       ├── media/
│   │       ├── documents/
│   │       ├── news/
│   │       ├── archives/
│   │       ├── academic/
│   │       ├── code/
│   │       ├── packages/
│   │       ├── procurement/
│   │       ├── sanctions/
│   │       └── exposure/
│   │
│   │
│   │ ============================================================
│   │  06. EVIDENCE ENGINE
│   │ ============================================================
│   │
│   ├── evidence/
│   │   ├── object.py
│   │   ├── store.py
│   │   ├── capture.py
│   │   ├── hashing.py
│   │   ├── integrity.py
│   │   ├── provenance.py
│   │   ├── custody.py
│   │   ├── metadata.py
│   │   ├── artifacts.py
│   │   ├── lineage.py
│   │   ├── versioning.py
│   │   ├── deduplication.py
│   │   ├── retention.py
│   │   ├── access.py
│   │   ├── replay.py
│   │   ├── manifest.py
│   │   ├── citations.py
│   │   ├── export.py
│   │   └── validation.py
│   │
│   │
│   │ ============================================================
│   │  07. ENTITY RESOLUTION
│   │ ============================================================
│   │
│   ├── entities/
│   │   ├── registry.py
│   │   ├── normalizer.py
│   │   ├── blocking.py
│   │   ├── candidates.py
│   │   ├── features.py
│   │   ├── exact_match.py
│   │   ├── probabilistic.py
│   │   ├── temporal.py
│   │   ├── geographic.py
│   │   ├── conflicts.py
│   │   ├── scoring.py
│   │   ├── calibration.py
│   │   ├── resolver.py
│   │   ├── merger.py
│   │   ├── splitter.py
│   │   ├── reversible_merge.py
│   │   ├── history.py
│   │   └── explanation.py
│   │
│   │
│   │ ============================================================
│   │  08. TEMPORAL KNOWLEDGE GRAPH
│   │ ============================================================
│   │
│   ├── graph/
│   │   ├── model.py
│   │   ├── node.py
│   │   ├── edge.py
│   │   ├── builder.py
│   │   ├── repository.py
│   │   ├── query.py
│   │   ├── expansion.py
│   │   ├── shortest_path.py
│   │   ├── khop.py
│   │   ├── components.py
│   │   ├── community.py
│   │   ├── centrality.py
│   │   ├── bridges.py
│   │   ├── temporal.py
│   │   ├── snapshots.py
│   │   ├── diff.py
│   │   ├── evidence_links.py
│   │   ├── confidence.py
│   │   └── export.py
│   │
│   ├── timeline/
│   │   ├── model.py
│   │   ├── builder.py
│   │   ├── normalizer.py
│   │   ├── events.py
│   │   ├── correlation.py
│   │   ├── conflicts.py
│   │   ├── snapshots.py
│   │   ├── query.py
│   │   └── export.py
│   │
│   │
│   │ ============================================================
│   │  09. VERIFICATION ENGINE
│   │ ============================================================
│   │
│   ├── verification/
│   │   ├── engine.py
│   │   ├── integrity.py
│   │   ├── corroboration.py
│   │   ├── adversarial.py
│   │   ├── claim_verifier.py
│   │   ├── identity_verifier.py
│   │   ├── relationship_verifier.py
│   │   ├── source_authority.py
│   │   ├── source_independence.py
│   │   ├── freshness.py
│   │   ├── temporal_consistency.py
│   │   ├── contradiction_detector.py
│   │   ├── alternatives.py
│   │   ├── confidence.py
│   │   ├── calibration.py
│   │   └── decision.py
│   │
│   │
│   │ ============================================================
│   │  10. AI / MODEL GATEWAY
│   │ ============================================================
│   │
│   ├── ai/
│   │   ├── gateway.py
│   │   ├── router.py
│   │   ├── policy.py
│   │   ├── budget.py
│   │   ├── fallback.py
│   │   ├── structured_output.py
│   │   ├── context.py
│   │   ├── untrusted_content.py
│   │   ├── injection_detection.py
│   │   │
│   │   ├── providers/
│   │   │   ├── ollama.py
│   │   │   ├── openai.py
│   │   │   ├── anthropic.py
│   │   │   ├── gemini.py
│   │   │   ├── grok.py
│   │   │   ├── qwen.py
│   │   │   ├── deepseek.py
│   │   │   └── mistral.py
│   │   │
│   │   └── tasks/
│   │       ├── extraction.py
│   │       ├── classification.py
│   │       ├── planning.py
│   │       ├── reasoning.py
│   │       ├── summarization.py
│   │       └── verification.py
│   │
│   │
│   │ ============================================================
│   │  11. REPORTING
│   │ ============================================================
│   │
│   ├── reporting/
│   │   ├── builder.py
│   │   ├── executive_summary.py
│   │   ├── methodology.py
│   │   ├── findings.py
│   │   ├── entities.py
│   │   ├── relationships.py
│   │   ├── timeline.py
│   │   ├── contradictions.py
│   │   ├── unknowns.py
│   │   ├── evidence_table.py
│   │   ├── limitations.py
│   │   ├── recommendations.py
│   │   ├── replay_manifest.py
│   │   ├── export_html.py
│   │   ├── export_pdf.py
│   │   ├── export_json.py
│   │   └── export_stix.py
│   │
│   │
│   │ ============================================================
│   │  12. SECURITY + GOVERNANCE
│   │ ============================================================
│   │
│   ├── security/
│   │   ├── authentication.py
│   │   ├── authorization.py
│   │   ├── rbac.py
│   │   ├── abac.py
│   │   ├── tenant.py
│   │   ├── case_policy.py
│   │   ├── secrets.py
│   │   ├── encryption.py
│   │   ├── redaction.py
│   │   ├── ssrf.py
│   │   ├── url_policy.py
│   │   ├── egress.py
│   │   ├── prompt_injection.py
│   │   ├── tool_policy.py
│   │   ├── agent_policy.py
│   │   ├── pii.py
│   │   ├── retention.py
│   │   ├── rate_limit.py
│   │   ├── quota.py
│   │   ├── malicious_document.py
│   │   ├── media_sandbox.py
│   │   └── audit.py
│   │
│   │
│   │ ============================================================
│   │  13. BACKEND API
│   │ ============================================================
│   │
│   ├── api/
│   │   ├── app.py
│   │   ├── dependencies.py
│   │   ├── middleware.py
│   │   ├── errors.py
│   │   │
│   │   ├── routes/
│   │   │   ├── auth.py
│   │   │   ├── cases.py
│   │   │   ├── objectives.py
│   │   │   ├── investigations.py
│   │   │   ├── tasks.py
│   │   │   ├── employees.py
│   │   │   ├── sources.py
│   │   │   ├── evidence.py
│   │   │   ├── entities.py
│   │   │   ├── relationships.py
│   │   │   ├── graph.py
│   │   │   ├── timeline.py
│   │   │   ├── claims.py
│   │   │   ├── contradictions.py
│   │   │   ├── gaps.py
│   │   │   ├── geo.py
│   │   │   ├── media.py
│   │   │   ├── cti.py
│   │   │   ├── reports.py
│   │   │   ├── audit.py
│   │   │   ├── health.py
│   │   │   └── admin.py
│   │   │
│   │   └── schemas/
│   │
│   │
│   │ ============================================================
│   │  14. DATABASE
│   │ ============================================================
│   │
│   └── db/
│       ├── base.py
│       ├── session.py
│       ├── models/
│       ├── repositories/
│       └── migrations/
│
│
│ ================================================================
│  15. 650+ SOURCE CATALOG
│ ================================================================
│
├── sources/
│   └── catalog/
│       ├── web.yaml
│       ├── search.yaml
│       ├── social.yaml
│       ├── communities.yaml
│       ├── people.yaml
│       ├── usernames.yaml
│       ├── companies.yaml
│       ├── registries.yaml
│       ├── government.yaml
│       ├── domains.yaml
│       ├── dns.yaml
│       ├── ip.yaml
│       ├── asn.yaml
│       ├── certificates.yaml
│       ├── infrastructure.yaml
│       ├── cti.yaml
│       ├── malware.yaml
│       ├── vulnerabilities.yaml
│       ├── geo.yaml
│       ├── maps.yaml
│       ├── satellite.yaml
│       ├── transport.yaml
│       ├── images.yaml
│       ├── video.yaml
│       ├── audio.yaml
│       ├── documents.yaml
│       ├── news.yaml
│       ├── archives.yaml
│       ├── academic.yaml
│       ├── code.yaml
│       ├── packages.yaml
│       ├── procurement.yaml
│       ├── sanctions.yaml
│       ├── legal.yaml
│       ├── exposure.yaml
│       └── datasets.yaml
│
│
│ ================================================================
│  16. WEBSITE / INVESTIGATOR WORKBENCH
│ ================================================================
│
├── web/
│   ├── package.json
│   ├── next.config.ts
│   ├── middleware.ts
│   │
│   ├── app/
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   │
│   │   ├── investigations/
│   │   ├── cases/
│   │   ├── entities/
│   │   ├── people/
│   │   ├── companies/
│   │   ├── social/
│   │   ├── infrastructure/
│   │   ├── cti/
│   │   ├── geo/
│   │   ├── media/
│   │   ├── documents/
│   │   ├── graph/
│   │   ├── timeline/
│   │   ├── evidence/
│   │   ├── claims/
│   │   ├── contradictions/
│   │   ├── gaps/
│   │   ├── employees/
│   │   ├── sources/
│   │   ├── reports/
│   │   ├── audit/
│   │   ├── admin/
│   │   └── settings/
│   │
│   ├── components/
│   │   ├── investigation/
│   │   ├── graph/
│   │   ├── timeline/
│   │   ├── map/
│   │   ├── evidence/
│   │   ├── entities/
│   │   ├── claims/
│   │   ├── employees/
│   │   ├── reports/
│   │   └── ui/
│   │
│   ├── lib/
│   ├── hooks/
│   ├── stores/
│   ├── types/
│   └── tests/
│
│
│ ================================================================
│  17. EVALUATION
│ ================================================================
│
├── evaluation/
│   ├── runner.py
│   ├── scoring.py
│   ├── evidence_precision.py
│   ├── citation_accuracy.py
│   ├── entity_precision.py
│   ├── entity_recall.py
│   ├── false_merge_rate.py
│   ├── false_split_rate.py
│   ├── relationship_precision.py
│   ├── contradiction_recall.py
│   ├── independence_accuracy.py
│   ├── planner_quality.py
│   ├── nba_quality.py
│   ├── report_quality.py
│   ├── replay_success.py
│   ├── autonomous_defensible_investigation_rate.py
│   │
│   └── golden/
│       ├── domain/
│       ├── ip/
│       ├── company/
│       ├── person/
│       ├── username/
│       ├── social/
│       ├── cti/
│       ├── geo/
│       ├── image/
│       ├── video/
│       ├── audio/
│       ├── document/
│       ├── cross_domain/
│       └── adversarial/
│
│
│ ================================================================
│  18. TESTING
│ ================================================================
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── contracts/
│   ├── connectors/
│   ├── sources/
│   ├── investigation/
│   ├── employees/
│   ├── evidence/
│   ├── entities/
│   ├── graph/
│   ├── verification/
│   ├── ai/
│   ├── api/
│   ├── database/
│   ├── security/
│   ├── replay/
│   ├── golden/
│   ├── failure/
│   └── performance/
│
│
│ ================================================================
│  19. OPERATIONS
│ ================================================================
│
├── observability/
│   ├── logging.py
│   ├── tracing.py
│   ├── metrics.py
│   ├── source_metrics.py
│   ├── employee_metrics.py
│   ├── model_metrics.py
│   ├── investigation_metrics.py
│   ├── cost_metrics.py
│   ├── alerts.py
│   └── health.py
│
├── scripts/
│   ├── setup.sh
│   ├── dev.sh
│   ├── test.sh
│   ├── migrate.sh
│   ├── seed_sources.py
│   ├── qualify_sources.py
│   ├── run_golden.py
│   ├── check_acceptance.py
│   ├── backup.sh
│   └── restore.sh
│
├── deploy/
│   ├── docker/
│   ├── kubernetes/
│   ├── vercel/
│   ├── supabase/
│   └── monitoring/
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── security.yml
│       ├── connectors.yml
│       ├── golden.yml
│       ├── frontend.yml
│       ├── release.yml
│       └── source-canary.yml
│
│
│ ================================================================
│  20. PERSISTENT ENGINEERING MEMORY
│ ================================================================
│
├── .ai/
│   ├── CURRENT_STATE.md
│   ├── ACTIVE_WORK.md
│   ├── TASKS.md
│   ├── MEMORY.md
│   ├── DECISIONS.md
│   ├── KNOWN_ISSUES.md
│   ├── BLOCKERS.md
│   ├── SCORECARD.md
│   ├── SESSION_CONTEXT.md
│   └── CHANGELOG.md
│
└── docs/
    ├── ... EXISTING DOCUMENTATION ...
    │
    └── program/
        ├── MASTER_GAP_REGISTER.md
        ├── DOC_REQUIREMENT_INDEX.md
        ├── DOC_TO_CODE_MATRIX.md
        ├── COMPLETION_LEDGER.md
        ├── DOC_CONFLICTS.md
        ├── ENTERPRISE_8_SCORECARD.md
        ├── ACCEPTANCE_STATUS.md
        ├── SOURCE_QUALIFICATION_LEDGER.md
        ├── CONNECTOR_MATRIX.md
        ├── GOLDEN_INVESTIGATION_RESULTS.md
        ├── ENTITY_RESOLUTION_BENCHMARK.md
        ├── SECURITY_VALIDATION.md
        ├── THREAT_MODEL.md
        ├── DEPLOYMENT_STATUS.md
        ├── OPERATIONS_RUNBOOK.md
        ├── COMPETITOR_BENCHMARK.md
        └── RELEASE_READINESS.md
