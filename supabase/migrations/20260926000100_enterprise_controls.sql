-- TraceAtlas enterprise run provenance, retention and append-only audit controls.
begin;

create table public.source_runs (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  source text not null check (source ~ '^[a-z0-9][a-z0-9._:-]{1,79}$'),
  mode text not null check (mode in ('live', 'approved-export', 'service', 'worker')),
  status text not null check (status in ('queued', 'running', 'completed', 'partial', 'failed', 'skipped')),
  target_fingerprint text not null check (target_fingerprint ~ '^[a-f0-9]{64}$'),
  idempotency_key text not null check (
    char_length(idempotency_key) between 16 and 128 and idempotency_key ~ '^[A-Za-z0-9._:-]+$'
  ),
  records_received integer not null default 0 check (records_received between 0 and 1000000),
  records_stored integer not null default 0 check (records_stored between 0 and records_received),
  failure_code text check (failure_code is null or failure_code ~ '^[a-z0-9_]{3,120}$'),
  started_at timestamptz not null default now(),
  completed_at timestamptz,
  details jsonb not null default '{}'::jsonb check (
    jsonb_typeof(details) = 'object' and octet_length(details::text) <= 32768
  ),
  unique (organisation_id, idempotency_key),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete restrict,
  check (
    (status in ('queued', 'running') and completed_at is null)
    or (status in ('completed', 'partial', 'failed', 'skipped') and completed_at is not null)
  )
);

create table public.case_retention (
  case_id uuid primary key,
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  retention_days integer not null default 365 check (retention_days between 30 and 3650),
  legal_hold boolean not null default false,
  reason text check (reason is null or char_length(reason) between 10 and 1000),
  updated_by uuid not null default auth.uid() references auth.users(id) on delete restrict,
  updated_at timestamptz not null default now(),
  unique (case_id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete cascade,
  check (not legal_hold or reason is not null)
);

create index source_runs_case_idx on public.source_runs(case_id, started_at desc);
create index source_runs_org_status_idx on public.source_runs(organisation_id, status, started_at desc);
create index source_runs_org_fk_idx on public.source_runs(organisation_id);
create index case_retention_org_fk_idx on public.case_retention(organisation_id);
create index case_retention_updated_by_fk_idx on public.case_retention(updated_by);

alter table public.source_runs enable row level security;
alter table public.case_retention enable row level security;

revoke all on public.source_runs, public.case_retention from anon, authenticated;
grant select on public.source_runs to authenticated;
grant select on public.case_retention to authenticated;
grant all on public.source_runs, public.case_retention to service_role;

create policy source_runs_select on public.source_runs for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy case_retention_select on public.case_retention for select to authenticated
using ((select private.is_org_member(organisation_id, null)));

create or replace function private.reject_audit_mutation()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  raise exception 'audit events are append-only' using errcode = '42501';
end;
$$;
revoke all on function private.reject_audit_mutation() from public, anon, authenticated;
create trigger audit_events_append_only before update or delete on public.audit_events
for each row execute function private.reject_audit_mutation();

create or replace function private.enforce_case_legal_hold()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if exists (
    select 1 from public.case_retention r where r.case_id = old.id and r.legal_hold
  ) then
    raise exception 'case is under legal hold' using errcode = '42501';
  end if;
  return old;
end;
$$;
revoke all on function private.enforce_case_legal_hold() from public, anon, authenticated;
create trigger cases_legal_hold before delete on public.cases
for each row execute function private.enforce_case_legal_hold();

create or replace function public.set_case_retention(
  p_case_id uuid, p_retention_days integer, p_legal_hold boolean, p_reason text
)
returns setof public.case_retention language plpgsql security definer set search_path = '' as $$
declare
  v_user_id uuid := (select auth.uid());
  v_organisation_id uuid;
  v_row public.case_retention;
begin
  if v_user_id is null then
    raise exception 'authentication required' using errcode = '42501';
  end if;
  if p_retention_days not between 30 and 3650
     or (p_legal_hold and (p_reason is null or char_length(trim(p_reason)) not between 10 and 1000)) then
    raise exception 'invalid retention policy' using errcode = '22023';
  end if;
  select organisation_id into v_organisation_id from public.cases where id = p_case_id;
  if v_organisation_id is null
     or not (select private.is_org_member(v_organisation_id, array['owner','admin'])) then
    raise exception 'case unavailable' using errcode = '42501';
  end if;
  insert into public.case_retention(
    case_id, organisation_id, retention_days, legal_hold, reason, updated_by, updated_at
  ) values (
    p_case_id, v_organisation_id, p_retention_days, p_legal_hold, nullif(trim(p_reason), ''),
    v_user_id, now()
  ) on conflict (case_id) do update set
    retention_days = excluded.retention_days, legal_hold = excluded.legal_hold,
    reason = excluded.reason, updated_by = excluded.updated_by, updated_at = now()
  returning * into v_row;
  insert into public.audit_events(organisation_id, actor_id, action, target_type, target_id, result)
  values (v_organisation_id, v_user_id, 'case.retention_updated', 'case', p_case_id, 'completed');
  return next v_row;
end;
$$;
revoke all on function public.set_case_retention(uuid, integer, boolean, text) from public, anon;
grant execute on function public.set_case_retention(uuid, integer, boolean, text) to authenticated;

alter default privileges for role postgres in schema public
  revoke select, insert, update, delete on tables from anon, authenticated;
alter default privileges for role postgres in schema public
  revoke execute on functions from public, anon, authenticated;

commit;
