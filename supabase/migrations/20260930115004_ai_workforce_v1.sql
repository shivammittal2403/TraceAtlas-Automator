-- TraceAtlas bounded AI workforce and Evidence Fabric v2.
-- Authenticated clients may read tenant records and call the governed approval
-- RPC. Only the service role may create tasks, evidence, claims or traces.
begin;

create table public.workforce_authorization_contexts (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  actor_id uuid not null references auth.users(id) on delete restrict,
  lawful_purpose text not null check (char_length(lawful_purpose) between 10 and 500),
  scope jsonb not null check (jsonb_typeof(scope) = 'array'),
  allowed_actions jsonb not null check (jsonb_typeof(allowed_actions) = 'array'),
  allowed_tools jsonb not null check (jsonb_typeof(allowed_tools) = 'array'),
  jurisdiction text not null check (char_length(jurisdiction) between 2 and 80),
  retention_policy text not null check (char_length(retention_policy) between 2 and 120),
  policy_digest text not null check (policy_digest ~ '^[a-f0-9]{64}$'),
  issued_at timestamptz not null,
  expires_at timestamptz not null check (expires_at > issued_at),
  created_at timestamptz not null default now(),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict
);

create table public.workforce_tasks (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  authorization_context_id uuid not null,
  created_by uuid not null references auth.users(id) on delete restrict,
  employee_id text not null check (char_length(employee_id) between 2 and 128),
  employee_definition_digest text not null check (employee_definition_digest ~ '^[a-f0-9]{64}$'),
  envelope jsonb not null check (jsonb_typeof(envelope) = 'object'),
  envelope_digest text not null check (envelope_digest ~ '^[a-f0-9]{64}$'),
  trace_id text not null check (char_length(trace_id) between 2 and 128),
  status text not null default 'planned' check (status in ('planned','approved','running','completed','failed','stopped','expired')),
  created_at timestamptz not null default now(),
  approved_at timestamptz,
  completed_at timestamptz,
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  foreign key (authorization_context_id, organisation_id)
    references public.workforce_authorization_contexts(id, organisation_id) on delete restrict
);

create table public.workforce_approvals (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  task_id uuid not null,
  actor_id uuid not null references auth.users(id) on delete restrict,
  decision text not null check (decision in ('approved','rejected')),
  rationale text not null check (char_length(trim(rationale)) between 10 and 2000),
  envelope_digest text not null check (envelope_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz not null default now(),
  unique (task_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  foreign key (task_id, organisation_id) references public.workforce_tasks(id, organisation_id) on delete restrict
);

create table public.acquisitions_v2 (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  task_id uuid,
  source_id text not null check (char_length(source_id) between 2 and 160),
  acquisition_method text not null check (char_length(acquisition_method) between 2 and 120),
  source_uri text not null check (char_length(source_uri) between 1 and 2048),
  retrieved_at timestamptz not null,
  trace_id text not null check (char_length(trace_id) between 2 and 128),
  created_at timestamptz not null default now(),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  foreign key (task_id, organisation_id) references public.workforce_tasks(id, organisation_id) on delete restrict
);

create table public.evidence_objects_v2 (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  acquisition_id uuid not null,
  legacy_evidence_id uuid,
  evidence_key text not null check (char_length(evidence_key) between 2 and 128),
  version integer not null check (version between 1 and 1000000),
  prior_version_id uuid,
  source_id text not null check (char_length(source_id) between 2 and 160),
  content_hash text not null check (content_hash ~ '^[a-f0-9]{64}$'),
  media_type text not null check (char_length(media_type) between 1 and 160),
  raw_artifact_pointer text not null check (char_length(raw_artifact_pointer) between 1 and 2048),
  parser text not null check (char_length(parser) between 1 and 120),
  parser_version text not null check (char_length(parser_version) between 1 and 80),
  extractor text not null check (char_length(extractor) between 1 and 120),
  extractor_version text not null check (char_length(extractor_version) between 1 and 80),
  chain_of_custody jsonb not null check (jsonb_typeof(chain_of_custody) = 'array'),
  access_policy text not null check (char_length(access_policy) between 2 and 120),
  retention_policy text not null check (char_length(retention_policy) between 2 and 120),
  classification text not null check (char_length(classification) between 2 and 80),
  metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
  created_at timestamptz not null default now(),
  unique (case_id, evidence_key, version),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  foreign key (acquisition_id, organisation_id) references public.acquisitions_v2(id, organisation_id) on delete restrict,
  foreign key (legacy_evidence_id, organisation_id) references public.evidence_items(id, organisation_id) on delete restrict,
  foreign key (prior_version_id, organisation_id) references public.evidence_objects_v2(id, organisation_id) on delete restrict
);

create table public.observations_v2 (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  evidence_object_id uuid not null,
  acquisition_id uuid not null,
  semantic_class text not null check (semantic_class in ('OBSERVATION','ALLEGATION')),
  statement text not null check (char_length(statement) between 1 and 4000),
  observed_at timestamptz not null,
  created_at timestamptz not null default now(),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  foreign key (evidence_object_id, organisation_id) references public.evidence_objects_v2(id, organisation_id) on delete restrict,
  foreign key (acquisition_id, organisation_id) references public.acquisitions_v2(id, organisation_id) on delete restrict
);

create table public.source_lineage_v2 (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  source_id text not null check (char_length(source_id) between 2 and 160),
  independence_group text not null check (char_length(independence_group) between 2 and 160),
  original_source_id text,
  content_fingerprint text not null check (content_fingerprint ~ '^[a-f0-9]{64}$'),
  ownership_group text,
  reasons jsonb not null check (jsonb_typeof(reasons) = 'array'),
  created_at timestamptz not null default now(),
  unique (case_id, source_id),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict
);

create table public.claims_v2 (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  task_id uuid,
  semantic_class text not null check (semantic_class in ('FACT','CLAIM','INFERENCE','HYPOTHESIS','UNKNOWN')),
  statement text not null check (char_length(statement) between 1 and 4000),
  material boolean not null default false,
  observation_ids jsonb not null check (jsonb_typeof(observation_ids) = 'array'),
  model_confidence double precision check (model_confidence is null or model_confidence between 0 and 1),
  created_at timestamptz not null default now(),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  foreign key (task_id, organisation_id) references public.workforce_tasks(id, organisation_id) on delete restrict
);

create table public.verification_decisions_v2 (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  claim_id uuid not null,
  status text not null check (status in ('SUPPORTED','PARTIALLY_SUPPORTED','DISPUTED','INCONCLUSIVE','UNSUPPORTED')),
  integrity_passed boolean not null,
  independent_groups jsonb not null check (jsonb_typeof(independent_groups) = 'array'),
  supporting_observation_ids jsonb not null check (jsonb_typeof(supporting_observation_ids) = 'array'),
  contradicting_observation_ids jsonb not null check (jsonb_typeof(contradicting_observation_ids) = 'array'),
  information_gaps jsonb not null check (jsonb_typeof(information_gaps) = 'array'),
  human_review_required boolean not null,
  created_at timestamptz not null default now(),
  unique (claim_id),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  foreign key (claim_id, organisation_id) references public.claims_v2(id, organisation_id) on delete restrict
);

create table public.workforce_results (
  task_id uuid primary key,
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  result jsonb not null check (jsonb_typeof(result) = 'object'),
  result_digest text not null check (result_digest ~ '^[a-f0-9]{64}$'),
  stop_reason text not null check (char_length(stop_reason) between 2 and 120),
  created_at timestamptz not null default now(),
  unique (task_id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  foreign key (task_id, organisation_id) references public.workforce_tasks(id, organisation_id) on delete restrict
);

create table public.workforce_trace_spans (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  task_id uuid not null,
  trace_id text not null check (char_length(trace_id) between 2 and 128),
  parent_span_id uuid,
  operation text not null check (char_length(operation) between 2 and 120),
  status text not null check (char_length(status) between 2 and 80),
  latency_ms integer not null check (latency_ms between 0 and 86400000),
  token_count integer not null default 0 check (token_count >= 0),
  estimated_cost numeric(14,6) not null default 0 check (estimated_cost >= 0),
  provider text,
  model text,
  created_at timestamptz not null default now(),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  foreign key (task_id, organisation_id) references public.workforce_tasks(id, organisation_id) on delete restrict,
  foreign key (parent_span_id, organisation_id) references public.workforce_trace_spans(id, organisation_id) on delete restrict
);

create index workforce_tasks_case_idx on public.workforce_tasks(case_id, created_at desc);
create index workforce_tasks_status_idx on public.workforce_tasks(status, created_at) where status in ('approved','running');
create index evidence_objects_v2_case_hash_idx on public.evidence_objects_v2(case_id, content_hash);
create index observations_v2_evidence_idx on public.observations_v2(evidence_object_id, observed_at);
create index claims_v2_case_idx on public.claims_v2(case_id, created_at desc);
create index workforce_trace_task_idx on public.workforce_trace_spans(task_id, created_at);
-- PostgreSQL does not create child-side foreign-key indexes. These indexes also
-- keep tenant RLS membership filters and cascade/restrict checks bounded.
create index workforce_auth_org_idx on public.workforce_authorization_contexts(organisation_id, created_at desc);
create index workforce_auth_case_org_fk_idx on public.workforce_authorization_contexts(case_id, organisation_id);
create index workforce_auth_actor_idx on public.workforce_authorization_contexts(actor_id);
create index workforce_tasks_org_idx on public.workforce_tasks(organisation_id, created_at desc);
create index workforce_tasks_case_org_fk_idx on public.workforce_tasks(case_id, organisation_id);
create index workforce_tasks_auth_org_fk_idx on public.workforce_tasks(authorization_context_id, organisation_id);
create index workforce_tasks_created_by_idx on public.workforce_tasks(created_by);
create index workforce_approvals_org_idx on public.workforce_approvals(organisation_id, created_at desc);
create index workforce_approvals_case_org_fk_idx on public.workforce_approvals(case_id, organisation_id);
create index workforce_approvals_task_org_fk_idx on public.workforce_approvals(task_id, organisation_id);
create index workforce_approvals_actor_idx on public.workforce_approvals(actor_id);
create index acquisitions_v2_org_idx on public.acquisitions_v2(organisation_id, created_at desc);
create index acquisitions_v2_case_org_fk_idx on public.acquisitions_v2(case_id, organisation_id);
create index acquisitions_v2_task_org_fk_idx on public.acquisitions_v2(task_id, organisation_id) where task_id is not null;
create index evidence_objects_v2_org_idx on public.evidence_objects_v2(organisation_id, created_at desc);
create index evidence_objects_v2_case_org_fk_idx on public.evidence_objects_v2(case_id, organisation_id);
create index evidence_objects_v2_acquisition_org_fk_idx on public.evidence_objects_v2(acquisition_id, organisation_id);
create index evidence_objects_v2_legacy_org_fk_idx on public.evidence_objects_v2(legacy_evidence_id, organisation_id) where legacy_evidence_id is not null;
create index evidence_objects_v2_prior_org_fk_idx on public.evidence_objects_v2(prior_version_id, organisation_id) where prior_version_id is not null;
create index observations_v2_org_idx on public.observations_v2(organisation_id, created_at desc);
create index observations_v2_case_org_fk_idx on public.observations_v2(case_id, organisation_id);
create index observations_v2_evidence_org_fk_idx on public.observations_v2(evidence_object_id, organisation_id);
create index observations_v2_acquisition_org_fk_idx on public.observations_v2(acquisition_id, organisation_id);
create index source_lineage_v2_org_idx on public.source_lineage_v2(organisation_id, created_at desc);
create index source_lineage_v2_case_org_fk_idx on public.source_lineage_v2(case_id, organisation_id);
create index claims_v2_org_idx on public.claims_v2(organisation_id, created_at desc);
create index claims_v2_case_org_fk_idx on public.claims_v2(case_id, organisation_id);
create index claims_v2_task_org_fk_idx on public.claims_v2(task_id, organisation_id) where task_id is not null;
create index verification_v2_org_idx on public.verification_decisions_v2(organisation_id, created_at desc);
create index verification_v2_case_org_fk_idx on public.verification_decisions_v2(case_id, organisation_id);
create index verification_v2_claim_org_fk_idx on public.verification_decisions_v2(claim_id, organisation_id);
create index workforce_results_org_idx on public.workforce_results(organisation_id, created_at desc);
create index workforce_results_case_org_fk_idx on public.workforce_results(case_id, organisation_id);
create index workforce_results_task_org_fk_idx on public.workforce_results(task_id, organisation_id);
create index workforce_trace_org_idx on public.workforce_trace_spans(organisation_id, created_at desc);
create index workforce_trace_case_org_fk_idx on public.workforce_trace_spans(case_id, organisation_id);
create index workforce_trace_task_org_fk_idx on public.workforce_trace_spans(task_id, organisation_id);
create index workforce_trace_parent_org_fk_idx on public.workforce_trace_spans(parent_span_id, organisation_id) where parent_span_id is not null;

alter table public.workforce_authorization_contexts enable row level security;
alter table public.workforce_tasks enable row level security;
alter table public.workforce_approvals enable row level security;
alter table public.acquisitions_v2 enable row level security;
alter table public.evidence_objects_v2 enable row level security;
alter table public.observations_v2 enable row level security;
alter table public.source_lineage_v2 enable row level security;
alter table public.claims_v2 enable row level security;
alter table public.verification_decisions_v2 enable row level security;
alter table public.workforce_results enable row level security;
alter table public.workforce_trace_spans enable row level security;

revoke all on public.workforce_authorization_contexts, public.workforce_tasks,
  public.workforce_approvals, public.acquisitions_v2, public.evidence_objects_v2,
  public.observations_v2, public.source_lineage_v2, public.claims_v2,
  public.verification_decisions_v2, public.workforce_results,
  public.workforce_trace_spans from public, anon, authenticated;
grant select on public.workforce_authorization_contexts, public.workforce_tasks,
  public.workforce_approvals, public.acquisitions_v2, public.evidence_objects_v2,
  public.observations_v2, public.source_lineage_v2, public.claims_v2,
  public.verification_decisions_v2, public.workforce_results,
  public.workforce_trace_spans to authenticated;
grant all on public.workforce_authorization_contexts, public.workforce_tasks,
  public.workforce_approvals, public.acquisitions_v2, public.evidence_objects_v2,
  public.observations_v2, public.source_lineage_v2, public.claims_v2,
  public.verification_decisions_v2, public.workforce_results,
  public.workforce_trace_spans to service_role;

create policy workforce_auth_select on public.workforce_authorization_contexts for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy workforce_tasks_select on public.workforce_tasks for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy workforce_approvals_select on public.workforce_approvals for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy acquisitions_v2_select on public.acquisitions_v2 for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy evidence_objects_v2_select on public.evidence_objects_v2 for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy observations_v2_select on public.observations_v2 for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy source_lineage_v2_select on public.source_lineage_v2 for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy claims_v2_select on public.claims_v2 for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy verification_decisions_v2_select on public.verification_decisions_v2 for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy workforce_results_select on public.workforce_results for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy workforce_trace_select on public.workforce_trace_spans for select to authenticated
using ((select private.is_org_member(organisation_id, null)));

create or replace function public.approve_workforce_task(
  p_task_id uuid, p_envelope_digest text, p_rationale text
)
returns setof public.workforce_tasks language plpgsql security definer set search_path = '' as $$
declare
  v_user_id uuid := (select auth.uid());
  v_task public.workforce_tasks;
  v_existing public.workforce_approvals;
begin
  if v_user_id is null then
    raise exception 'authentication required' using errcode = '42501';
  end if;
  if p_envelope_digest is null or p_envelope_digest !~ '^[a-f0-9]{64}$'
     or p_rationale is null or char_length(trim(p_rationale)) not between 10 and 2000 then
    raise exception 'invalid workforce approval' using errcode = '22023';
  end if;
  select * into v_task from public.workforce_tasks where id = p_task_id;
  if v_task.id is null or not (select private.is_org_member(v_task.organisation_id, array['owner','admin','analyst'])) then
    raise exception 'workforce task unavailable' using errcode = '42501';
  end if;
  select * into v_task from public.workforce_tasks where id = p_task_id for update;
  select * into v_existing from public.workforce_approvals where task_id = p_task_id;
  if v_existing.id is not null then
    if v_existing.actor_id = v_user_id and v_existing.envelope_digest = p_envelope_digest
       and v_existing.rationale = trim(p_rationale) then
      return next v_task;
      return;
    end if;
    raise exception 'workforce approval conflicts with existing decision' using errcode = '23505';
  end if;
  if v_task.status <> 'planned' or v_task.envelope_digest <> p_envelope_digest then
    raise exception 'workforce task changed or is not pending' using errcode = '23505';
  end if;
  insert into public.workforce_approvals(
    organisation_id, case_id, task_id, actor_id, decision, rationale, envelope_digest
  ) values (
    v_task.organisation_id, v_task.case_id, v_task.id, v_user_id, 'approved',
    trim(p_rationale), p_envelope_digest
  );
  update public.workforce_tasks set status = 'approved', approved_at = now()
  where id = p_task_id returning * into v_task;
  insert into public.audit_events(organisation_id, actor_id, action, target_type, target_id, result)
  values (v_task.organisation_id, v_user_id, 'workforce.approved', 'workforce_task', v_task.id, 'completed');
  return next v_task;
end;
$$;
revoke all on function public.approve_workforce_task(uuid, text, text) from public, anon;
grant execute on function public.approve_workforce_task(uuid, text, text) to authenticated;

commit;
