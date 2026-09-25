-- TraceAtlas 1.1 control plane. No table is exposed to anon.
begin;

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated, service_role;

create table public.organisations (
  id uuid primary key default gen_random_uuid(),
  created_by uuid not null default auth.uid() references auth.users(id) on delete restrict,
  name text not null check (char_length(name) between 2 and 120),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.organisation_members (
  organisation_id uuid not null references public.organisations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner', 'admin', 'analyst', 'viewer')),
  created_at timestamptz not null default now(),
  primary key (organisation_id, user_id)
);

create table public.cases (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  created_by uuid not null default auth.uid() references auth.users(id) on delete restrict,
  title text not null check (char_length(title) between 3 and 160),
  purpose text not null check (char_length(purpose) between 10 and 1000),
  scope jsonb not null default '{}'::jsonb check (jsonb_typeof(scope) = 'object'),
  status text not null default 'open' check (status in ('open', 'review', 'closed', 'archived')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organisation_id)
);

create table public.assets (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  created_by uuid not null default auth.uid() references auth.users(id) on delete restrict,
  label text not null check (char_length(label) between 1 and 120),
  target_type text not null check (target_type in ('domain', 'ip', 'url', 'hash')),
  target_value text not null check (char_length(target_value) between 1 and 2048),
  target_fingerprint text generated always as (
    encode(extensions.digest(
      target_type || ':' || case when target_type in ('domain','hash') then lower(target_value) else target_value end,
      'sha256'
    ), 'hex')
  ) stored,
  ownership_basis text not null check (ownership_basis in ('owned_asset', 'written_authorization')),
  verified_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organisation_id, target_fingerprint),
  unique (id, organisation_id)
);

create table public.investigation_jobs (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  asset_id uuid not null,
  created_by uuid not null default auth.uid() references auth.users(id) on delete restrict,
  kind text not null check (kind in ('domain_passive', 'ip_passive', 'url_metadata', 'hash_reputation')),
  status text not null default 'queued' check (status in ('queued', 'running', 'completed', 'failed', 'cancelled')),
  idempotency_key text not null check (
    char_length(idempotency_key) between 16 and 128 and idempotency_key ~ '^[A-Za-z0-9._:-]+$'
  ),
  attempt smallint not null default 0 check (attempt between 0 and 5),
  worker_id text check (worker_id is null or char_length(worker_id) between 3 and 120),
  heartbeat_at timestamptz,
  started_at timestamptz,
  completed_at timestamptz,
  result jsonb not null default '{}'::jsonb check (jsonb_typeof(result) = 'object'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organisation_id, idempotency_key),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  foreign key (asset_id, organisation_id) references public.assets(id, organisation_id) on delete restrict
);

create table public.job_events (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  job_id uuid not null,
  level text not null check (level in ('info', 'warning', 'error')),
  event_type text not null check (char_length(event_type) between 2 and 80),
  message text not null check (char_length(message) between 1 and 1000),
  details jsonb not null default '{}'::jsonb check (jsonb_typeof(details) = 'object'),
  created_at timestamptz not null default now(),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  foreign key (job_id, organisation_id) references public.investigation_jobs(id, organisation_id) on delete cascade
);

create table public.evidence_items (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  job_id uuid,
  source text not null check (char_length(source) between 2 and 160),
  classification text not null check (classification in ('observed', 'inference', 'model-output')),
  content_hash text not null check (content_hash ~ '^[a-f0-9]{64}$'),
  payload jsonb not null default '{}'::jsonb check (jsonb_typeof(payload) = 'object'),
  created_at timestamptz not null default now(),
  unique (case_id, content_hash),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  foreign key (job_id, organisation_id) references public.investigation_jobs(id, organisation_id) on delete restrict
);

create table public.graph_entities (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  evidence_id uuid,
  entity_type text not null check (char_length(entity_type) between 2 and 80),
  label text not null check (char_length(label) between 1 and 500),
  confidence smallint not null check (confidence between 0 and 100),
  classification text not null check (classification in ('observed', 'inference', 'model-output')),
  properties jsonb not null default '{}'::jsonb check (jsonb_typeof(properties) = 'object'),
  fingerprint text not null check (fingerprint ~ '^[a-f0-9]{64}$'),
  created_at timestamptz not null default now(),
  unique (case_id, fingerprint),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete cascade,
  foreign key (evidence_id, organisation_id) references public.evidence_items(id, organisation_id) on delete restrict
);

create table public.graph_edges (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  evidence_id uuid,
  source_entity_id uuid not null,
  target_entity_id uuid not null,
  relationship text not null check (char_length(relationship) between 2 and 120),
  confidence smallint not null check (confidence between 0 and 100),
  classification text not null check (classification in ('observed', 'inference', 'model-output')),
  properties jsonb not null default '{}'::jsonb check (jsonb_typeof(properties) = 'object'),
  created_at timestamptz not null default now(),
  check (source_entity_id <> target_entity_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete cascade,
  foreign key (evidence_id, organisation_id) references public.evidence_items(id, organisation_id) on delete restrict,
  foreign key (source_entity_id, organisation_id) references public.graph_entities(id, organisation_id) on delete cascade,
  foreign key (target_entity_id, organisation_id) references public.graph_entities(id, organisation_id) on delete cascade
);

create table public.audit_events (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  actor_id uuid references auth.users(id) on delete set null,
  action text not null check (char_length(action) between 2 and 120),
  target_type text not null check (char_length(target_type) between 2 and 80),
  target_id uuid,
  result text not null check (result in ('allowed', 'denied', 'completed', 'failed')),
  request_id text check (request_id is null or char_length(request_id) <= 160),
  details jsonb not null default '{}'::jsonb check (jsonb_typeof(details) = 'object'),
  created_at timestamptz not null default now()
);

create index organisation_members_user_idx on public.organisation_members(user_id, organisation_id);
create index cases_org_idx on public.cases(organisation_id, created_at desc);
create index assets_org_idx on public.assets(organisation_id, created_at desc);
create index jobs_queue_idx on public.investigation_jobs(status, created_at) where status = 'queued';
create index jobs_org_idx on public.investigation_jobs(organisation_id, created_at desc);
create index job_events_job_idx on public.job_events(job_id, created_at);
create index evidence_case_idx on public.evidence_items(case_id, created_at desc);
create index graph_entities_case_idx on public.graph_entities(case_id, entity_type);
create index graph_edges_case_idx on public.graph_edges(case_id, source_entity_id, target_entity_id);
create index audit_org_idx on public.audit_events(organisation_id, created_at desc);

create or replace function private.is_org_member(p_organisation_id uuid, p_roles text[] default null)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.organisation_members m
    where m.organisation_id = p_organisation_id
      and m.user_id = (select auth.uid())
      and (p_roles is null or m.role = any(p_roles))
  );
$$;
revoke all on function private.is_org_member(uuid, text[]) from public, anon;
grant execute on function private.is_org_member(uuid, text[]) to authenticated, service_role;

create or replace function private.bootstrap_org_owner()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.organisation_members(organisation_id, user_id, role)
  values (new.id, new.created_by, 'owner');
  return new;
end;
$$;
revoke all on function private.bootstrap_org_owner() from public, anon, authenticated;
create trigger organisations_bootstrap_owner after insert on public.organisations
for each row execute function private.bootstrap_org_owner();

create or replace function private.touch_updated_at()
returns trigger language plpgsql set search_path = '' as $$
begin new.updated_at = now(); return new; end;
$$;
revoke all on function private.touch_updated_at() from public, anon, authenticated;
create trigger organisations_touch before update on public.organisations for each row execute function private.touch_updated_at();
create trigger cases_touch before update on public.cases for each row execute function private.touch_updated_at();
create trigger assets_touch before update on public.assets for each row execute function private.touch_updated_at();
create trigger jobs_touch before update on public.investigation_jobs for each row execute function private.touch_updated_at();

create or replace function private.enforce_job_rate_limit()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if (select count(*) from public.investigation_jobs
      where organisation_id = new.organisation_id and status in ('queued', 'running')) >= 20 then
    raise exception 'organisation concurrent job limit reached' using errcode = '23514';
  end if;
  if (select count(*) from public.investigation_jobs
      where created_by = new.created_by and created_at > now() - interval '1 hour') >= 60 then
    raise exception 'user hourly job limit reached' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function private.enforce_job_rate_limit() from public, anon, authenticated;
create trigger jobs_rate_limit before insert on public.investigation_jobs
for each row execute function private.enforce_job_rate_limit();

alter table public.organisations enable row level security;
alter table public.organisation_members enable row level security;
alter table public.cases enable row level security;
alter table public.assets enable row level security;
alter table public.investigation_jobs enable row level security;
alter table public.job_events enable row level security;
alter table public.evidence_items enable row level security;
alter table public.graph_entities enable row level security;
alter table public.graph_edges enable row level security;
alter table public.audit_events enable row level security;

revoke all on all tables in schema public from anon, authenticated;
grant select, insert on public.organisations to authenticated;
grant select on public.organisation_members to authenticated;
grant select, insert on public.cases to authenticated;
grant select, insert on public.assets to authenticated;
grant select on public.investigation_jobs, public.job_events, public.evidence_items,
  public.graph_entities, public.graph_edges, public.audit_events to authenticated;
grant all on all tables in schema public to service_role;

create policy organisations_select on public.organisations for select to authenticated
using ((select private.is_org_member(id, null)));
create policy organisations_insert on public.organisations for insert to authenticated
with check (created_by = (select auth.uid()));
create policy members_select on public.organisation_members for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy cases_select on public.cases for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy cases_insert on public.cases for insert to authenticated
with check (created_by = (select auth.uid()) and
  (select private.is_org_member(organisation_id, array['owner','admin','analyst'])));
create policy assets_select on public.assets for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy assets_insert on public.assets for insert to authenticated
with check (created_by = (select auth.uid()) and
  (select private.is_org_member(organisation_id, array['owner','admin','analyst'])));
create policy jobs_select on public.investigation_jobs for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy job_events_select on public.job_events for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy evidence_select on public.evidence_items for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy graph_entities_select on public.graph_entities for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy graph_edges_select on public.graph_edges for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy audit_select on public.audit_events for select to authenticated
using ((select private.is_org_member(organisation_id, array['owner','admin'])));

create or replace function public.enqueue_investigation_job(
  p_case_id uuid, p_asset_id uuid, p_kind text, p_idempotency_key text
)
returns setof public.investigation_jobs language plpgsql security definer set search_path = '' as $$
declare
  v_organisation_id uuid;
  v_asset_type text;
  v_user_id uuid := (select auth.uid());
  v_job public.investigation_jobs;
begin
  if v_user_id is null then raise exception 'authentication required' using errcode = '42501'; end if;
  select c.organisation_id into v_organisation_id from public.cases c
  where c.id = p_case_id and c.status in ('open', 'review');
  if v_organisation_id is null
     or not (select private.is_org_member(v_organisation_id, array['owner','admin','analyst'])) then
    raise exception 'case unavailable' using errcode = '42501';
  end if;
  select a.target_type into v_asset_type from public.assets a
  where a.id = p_asset_id and a.organisation_id = v_organisation_id;
  if v_asset_type is null then raise exception 'asset unavailable' using errcode = '42501'; end if;
  if (p_kind = 'domain_passive' and v_asset_type <> 'domain')
     or (p_kind = 'ip_passive' and v_asset_type <> 'ip')
     or (p_kind = 'url_metadata' and v_asset_type <> 'url')
     or (p_kind = 'hash_reputation' and v_asset_type <> 'hash')
     or p_kind not in ('domain_passive','ip_passive','url_metadata','hash_reputation') then
    raise exception 'job kind is incompatible with asset type' using errcode = '23514';
  end if;
  insert into public.investigation_jobs(
    organisation_id, case_id, asset_id, created_by, kind, idempotency_key
  ) values (v_organisation_id, p_case_id, p_asset_id, v_user_id, p_kind, p_idempotency_key)
  returning * into v_job;
  insert into public.audit_events(organisation_id, actor_id, action, target_type, target_id, result)
  values (v_organisation_id, v_user_id, 'job.enqueued', 'investigation_job', v_job.id, 'allowed');
  return next v_job;
end;
$$;
revoke all on function public.enqueue_investigation_job(uuid, uuid, text, text) from public, anon;
grant execute on function public.enqueue_investigation_job(uuid, uuid, text, text) to authenticated;

create or replace function public.claim_next_investigation_job(p_worker_id text)
returns setof public.investigation_jobs language plpgsql security definer set search_path = '' as $$
declare v_job_id uuid;
begin
  if char_length(p_worker_id) not between 3 and 120 then
    raise exception 'invalid worker id' using errcode = '22023';
  end if;
  select j.id into v_job_id from public.investigation_jobs j
  where j.status = 'queued' and j.attempt < 5 order by j.created_at
  for update skip locked limit 1;
  if v_job_id is null then return; end if;
  return query update public.investigation_jobs
  set status = 'running', worker_id = p_worker_id, attempt = attempt + 1,
      started_at = coalesce(started_at, now()), heartbeat_at = now(), updated_at = now()
  where id = v_job_id returning *;
end;
$$;
revoke all on function public.claim_next_investigation_job(text) from public, anon, authenticated;
grant execute on function public.claim_next_investigation_job(text) to service_role;

create or replace function public.complete_investigation_job(
  p_job_id uuid, p_worker_id text, p_status text, p_result jsonb
)
returns boolean language plpgsql security definer set search_path = '' as $$
begin
  if p_status not in ('completed', 'failed') or jsonb_typeof(p_result) <> 'object'
     or octet_length(p_result::text) > 65536 then
    raise exception 'invalid completion payload' using errcode = '22023';
  end if;
  update public.investigation_jobs
  set status = p_status, result = p_result, completed_at = now(), heartbeat_at = now(), updated_at = now()
  where id = p_job_id and status = 'running' and worker_id = p_worker_id;
  return found;
end;
$$;
revoke all on function public.complete_investigation_job(uuid, text, text, jsonb) from public, anon, authenticated;
grant execute on function public.complete_investigation_job(uuid, text, text, jsonb) to service_role;

create or replace function public.recover_stale_investigation_jobs()
returns integer language plpgsql security definer set search_path = '' as $$
declare v_recovered integer;
begin
  update public.investigation_jobs
  set status = case when attempt >= 5 then 'failed' else 'queued' end,
      worker_id = null,
      result = case when attempt >= 5 then '{"error":"worker_lease_exhausted"}'::jsonb else result end,
      completed_at = case when attempt >= 5 then now() else null end,
      updated_at = now()
  where status = 'running'
    and coalesce(heartbeat_at, started_at, created_at) < now() - interval '15 minutes';
  get diagnostics v_recovered = row_count;
  return v_recovered;
end;
$$;
revoke all on function public.recover_stale_investigation_jobs() from public, anon, authenticated;
grant execute on function public.recover_stale_investigation_jobs() to service_role;

alter default privileges for role postgres in schema public
  revoke select, insert, update, delete on tables from anon, authenticated;
alter default privileges for role postgres in schema public
  revoke execute on functions from public, anon, authenticated;
alter default privileges for role postgres in schema public
  revoke usage, select on sequences from anon, authenticated;

commit;
