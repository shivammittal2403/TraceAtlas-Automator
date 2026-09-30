begin;

alter table public.investigation_jobs
  drop constraint investigation_jobs_organisation_id_idempotency_key_key;
alter table public.investigation_jobs
  add constraint investigation_jobs_case_idempotency_key
  unique (organisation_id, case_id, idempotency_key);

-- All admission paths serialize in the same order, including service-role inserts.
-- Transaction-scoped locks protect both user and organisation admission counters.
create or replace function private.enforce_job_rate_limit()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('job-user:' || new.created_by::text, 0));
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('job-org:' || new.organisation_id::text, 0));
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
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('job-user:' || v_user_id::text, 0));
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('job-org:' || v_organisation_id::text, 0));
  select * into v_job from public.investigation_jobs
    where organisation_id = v_organisation_id and case_id = p_case_id and idempotency_key = p_idempotency_key;
  if found then
    if v_job.asset_id is distinct from p_asset_id or v_job.kind is distinct from p_kind then
      raise exception 'idempotency key reused with a different request' using errcode = '23505';
    end if;
    return next v_job;
    return;
  end if;
  select a.target_type into v_asset_type from public.assets a
  where a.id = p_asset_id and a.organisation_id = v_organisation_id;
  if v_asset_type is null then raise exception 'asset unavailable' using errcode = '42501'; end if;
  if p_kind is null or (p_kind = 'domain_passive' and v_asset_type <> 'domain')
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

commit;
