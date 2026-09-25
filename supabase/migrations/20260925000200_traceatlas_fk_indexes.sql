begin;

-- Cover every foreign-key column sequence reported by the hosted database
-- advisor. Existing query indexes are retained because they serve different
-- sort/filter paths; these indexes make referential updates and deletes bounded.
create index if not exists assets_created_by_fk_idx
  on public.assets(created_by);
create index if not exists audit_events_actor_fk_idx
  on public.audit_events(actor_id);
create index if not exists cases_created_by_fk_idx
  on public.cases(created_by);
create index if not exists evidence_items_case_org_fk_idx
  on public.evidence_items(case_id, organisation_id);
create index if not exists evidence_items_job_org_fk_idx
  on public.evidence_items(job_id, organisation_id);
create index if not exists evidence_items_org_fk_idx
  on public.evidence_items(organisation_id);
create index if not exists graph_edges_case_org_fk_idx
  on public.graph_edges(case_id, organisation_id);
create index if not exists graph_edges_evidence_org_fk_idx
  on public.graph_edges(evidence_id, organisation_id);
create index if not exists graph_edges_org_fk_idx
  on public.graph_edges(organisation_id);
create index if not exists graph_edges_source_org_fk_idx
  on public.graph_edges(source_entity_id, organisation_id);
create index if not exists graph_edges_target_org_fk_idx
  on public.graph_edges(target_entity_id, organisation_id);
create index if not exists graph_entities_case_org_fk_idx
  on public.graph_entities(case_id, organisation_id);
create index if not exists graph_entities_evidence_org_fk_idx
  on public.graph_entities(evidence_id, organisation_id);
create index if not exists graph_entities_org_fk_idx
  on public.graph_entities(organisation_id);
create index if not exists investigation_jobs_asset_org_fk_idx
  on public.investigation_jobs(asset_id, organisation_id);
create index if not exists investigation_jobs_case_org_fk_idx
  on public.investigation_jobs(case_id, organisation_id);
create index if not exists investigation_jobs_created_by_fk_idx
  on public.investigation_jobs(created_by);
create index if not exists job_events_case_org_fk_idx
  on public.job_events(case_id, organisation_id);
create index if not exists job_events_job_org_fk_idx
  on public.job_events(job_id, organisation_id);
create index if not exists job_events_org_fk_idx
  on public.job_events(organisation_id);
create index if not exists organisations_created_by_fk_idx
  on public.organisations(created_by);

commit;
