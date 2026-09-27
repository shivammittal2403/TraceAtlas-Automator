-- Persistent graph views and conflict-safe collaboration feed.
begin;

create table public.case_views (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  name text not null check (char_length(name) between 2 and 120),
  layout jsonb not null default '{}'::jsonb check (
    jsonb_typeof(layout) = 'object' and octet_length(layout::text) <= 65536
  ),
  filters jsonb not null default '{}'::jsonb check (
    jsonb_typeof(filters) = 'object' and octet_length(filters::text) <= 16384
  ),
  revision integer not null default 1 check (revision between 1 and 1000000),
  created_by uuid not null default auth.uid() references auth.users(id) on delete restrict,
  updated_by uuid not null default auth.uid() references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (case_id, name),
  unique (id, organisation_id),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete cascade
);

create table public.collaboration_events (
  sequence bigint generated always as identity primary key,
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  actor_id uuid not null references auth.users(id) on delete restrict,
  object_type text not null check (object_type in ('graph_view')),
  object_id uuid not null,
  operation text not null check (operation in ('created', 'updated')),
  base_revision integer not null check (base_revision between 0 and 999999),
  resulting_revision integer not null check (resulting_revision between 1 and 1000000),
  created_at timestamptz not null default now(),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete cascade,
  foreign key (object_id, organisation_id) references public.case_views(id, organisation_id) on delete cascade
);

create index case_views_case_idx on public.case_views(case_id, updated_at desc);
create index case_views_org_fk_idx on public.case_views(organisation_id);
create index case_views_created_by_fk_idx on public.case_views(created_by);
create index case_views_updated_by_fk_idx on public.case_views(updated_by);
create index collaboration_events_case_sequence_idx
  on public.collaboration_events(case_id, sequence);
create index collaboration_events_org_fk_idx on public.collaboration_events(organisation_id);
create index collaboration_events_actor_fk_idx on public.collaboration_events(actor_id);
create index collaboration_events_object_org_fk_idx
  on public.collaboration_events(object_id, organisation_id);

alter table public.case_views enable row level security;
alter table public.collaboration_events enable row level security;

revoke all on public.case_views, public.collaboration_events from anon, authenticated;
grant select on public.case_views, public.collaboration_events to authenticated;
grant all on public.case_views, public.collaboration_events to service_role;

create policy case_views_select on public.case_views for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy collaboration_events_select on public.collaboration_events for select to authenticated
using ((select private.is_org_member(organisation_id, null)));

create or replace function public.save_case_view(
  p_case_id uuid, p_view_id uuid, p_name text, p_layout jsonb,
  p_filters jsonb, p_expected_revision integer
)
returns setof public.case_views language plpgsql security definer set search_path = '' as $$
declare
  v_actor uuid := (select auth.uid());
  v_organisation_id uuid;
  v_current_revision integer;
  v_operation text;
  v_row public.case_views;
begin
  if v_actor is null then
    raise exception 'authentication required' using errcode = '42501';
  end if;
  if p_name is null or char_length(trim(p_name)) not between 2 and 120
     or p_layout is null or jsonb_typeof(p_layout) <> 'object'
     or octet_length(p_layout::text) > 65536
     or p_filters is null or jsonb_typeof(p_filters) <> 'object'
     or octet_length(p_filters::text) > 16384
     or p_expected_revision not between 0 and 1000000 then
    raise exception 'invalid graph view' using errcode = '22023';
  end if;
  select organisation_id into v_organisation_id
  from public.cases where id = p_case_id;
  if v_organisation_id is null or not (
    select private.is_org_member(v_organisation_id, array['owner','admin','analyst'])
  ) then
    raise exception 'case unavailable' using errcode = '42501';
  end if;

  select revision into v_current_revision from public.case_views
  where id = p_view_id and case_id = p_case_id and organisation_id = v_organisation_id
  for update;
  if v_current_revision is null then
    if p_expected_revision <> 0 then
      raise exception 'view revision conflict' using errcode = '40001';
    end if;
    insert into public.case_views(
      id, organisation_id, case_id, name, layout, filters, revision, created_by, updated_by
    ) values (
      p_view_id, v_organisation_id, p_case_id, trim(p_name), p_layout, p_filters, 1,
      v_actor, v_actor
    ) returning * into v_row;
    v_operation := 'created';
  else
    if v_current_revision <> p_expected_revision then
      raise exception 'view revision conflict' using errcode = '40001';
    end if;
    update public.case_views set
      name = trim(p_name), layout = p_layout, filters = p_filters,
      revision = revision + 1, updated_by = v_actor, updated_at = now()
    where id = p_view_id and case_id = p_case_id
      and organisation_id = v_organisation_id and revision = p_expected_revision
    returning * into v_row;
    if v_row.id is null then
      raise exception 'view revision conflict' using errcode = '40001';
    end if;
    v_operation := 'updated';
  end if;

  insert into public.collaboration_events(
    organisation_id, case_id, actor_id, object_type, object_id, operation,
    base_revision, resulting_revision
  ) values (
    v_organisation_id, p_case_id, v_actor, 'graph_view', v_row.id, v_operation,
    p_expected_revision, v_row.revision
  );
  insert into public.audit_events(
    organisation_id, actor_id, action, target_type, target_id, result, details
  ) values (
    v_organisation_id, v_actor, 'case_view.' || v_operation, 'case_view', v_row.id,
    'completed', jsonb_build_object('revision', v_row.revision)
  );
  return next v_row;
end;
$$;
revoke all on function public.save_case_view(uuid, uuid, text, jsonb, jsonb, integer)
  from public, anon;
grant execute on function public.save_case_view(uuid, uuid, text, jsonb, jsonb, integer)
  to authenticated;

-- Supabase Realtime streams only the privacy-reduced event envelope. View
-- content remains behind RLS and is fetched separately after each event.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
       where pubname = 'supabase_realtime' and schemaname = 'public'
         and tablename = 'collaboration_events'
     ) then
    alter publication supabase_realtime add table public.collaboration_events;
  end if;
end;
$$;

alter default privileges for role postgres in schema public
  revoke select, insert, update, delete on tables from anon, authenticated;
alter default privileges for role postgres in schema public
  revoke execute on functions from public, anon, authenticated;

commit;
