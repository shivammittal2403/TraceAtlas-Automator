-- TraceAtlas analyst notes and human review queue. No table is exposed to anon.
begin;

create table public.case_notes (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  created_by uuid not null default auth.uid() references auth.users(id) on delete restrict,
  classification text not null check (classification in ('fact', 'analysis', 'question')),
  body text not null check (char_length(body) between 1 and 4000),
  created_at timestamptz not null default now(),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete cascade
);

create table public.review_tasks (
  id uuid primary key default gen_random_uuid(),
  organisation_id uuid not null references public.organisations(id) on delete restrict,
  case_id uuid not null,
  evidence_id uuid,
  created_by uuid references auth.users(id) on delete set null,
  assigned_to uuid references auth.users(id) on delete set null,
  kind text not null check (kind in ('evidence', 'entity-resolution', 'correlation', 'model-output')),
  title text not null check (char_length(title) between 3 and 240),
  priority text not null default 'normal' check (priority in ('low', 'normal', 'high')),
  status text not null default 'pending' check (status in ('pending', 'accepted', 'rejected')),
  context jsonb not null default '{}'::jsonb check (
    jsonb_typeof(context) = 'object' and octet_length(context::text) <= 16384
  ),
  decision_rationale text check (
    decision_rationale is null or char_length(decision_rationale) between 10 and 2000
  ),
  decided_by uuid references auth.users(id) on delete set null,
  decided_at timestamptz,
  created_at timestamptz not null default now(),
  foreign key (case_id, organisation_id) references public.cases(id, organisation_id) on delete cascade,
  foreign key (evidence_id, organisation_id) references public.evidence_items(id, organisation_id) on delete restrict,
  check (
    (status = 'pending' and decision_rationale is null and decided_by is null and decided_at is null)
    or (status in ('accepted', 'rejected') and decision_rationale is not null
        and decided_by is not null and decided_at is not null)
  )
);

create index case_notes_case_idx on public.case_notes(case_id, created_at desc);
create index case_notes_org_fk_idx on public.case_notes(organisation_id);
create index case_notes_created_by_fk_idx on public.case_notes(created_by);
create index review_tasks_case_status_idx on public.review_tasks(case_id, status, created_at desc);
create index review_tasks_org_fk_idx on public.review_tasks(organisation_id);
create index review_tasks_evidence_org_fk_idx on public.review_tasks(evidence_id, organisation_id);
create index review_tasks_created_by_fk_idx on public.review_tasks(created_by);
create index review_tasks_assigned_to_fk_idx on public.review_tasks(assigned_to);
create index review_tasks_decided_by_fk_idx on public.review_tasks(decided_by);

alter table public.case_notes enable row level security;
alter table public.review_tasks enable row level security;

revoke all on public.case_notes, public.review_tasks from anon, authenticated;
grant select, insert on public.case_notes to authenticated;
grant select, insert on public.review_tasks to authenticated;
grant all on public.case_notes, public.review_tasks to service_role;

create policy case_notes_select on public.case_notes for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy case_notes_insert on public.case_notes for insert to authenticated
with check (
  created_by = (select auth.uid())
  and (select private.is_org_member(organisation_id, array['owner','admin','analyst']))
);
create policy review_tasks_select on public.review_tasks for select to authenticated
using ((select private.is_org_member(organisation_id, null)));
create policy review_tasks_insert on public.review_tasks for insert to authenticated
with check (
  created_by = (select auth.uid())
  and (select private.is_org_member(organisation_id, array['owner','admin','analyst']))
);

create or replace function public.decide_review_task(
  p_task_id uuid, p_decision text, p_rationale text
)
returns setof public.review_tasks language plpgsql security definer set search_path = '' as $$
declare
  v_user_id uuid := (select auth.uid());
  v_organisation_id uuid;
  v_task public.review_tasks;
begin
  if v_user_id is null then
    raise exception 'authentication required' using errcode = '42501';
  end if;
  if p_decision not in ('accepted', 'rejected') or p_rationale is null
     or char_length(trim(p_rationale)) not between 10 and 2000 then
    raise exception 'invalid review decision' using errcode = '22023';
  end if;
  select organisation_id into v_organisation_id from public.review_tasks
  where id = p_task_id and status = 'pending';
  if v_organisation_id is null
     or not (select private.is_org_member(v_organisation_id, array['owner','admin','analyst'])) then
    raise exception 'review task unavailable' using errcode = '42501';
  end if;
  update public.review_tasks set
    status = p_decision, decision_rationale = trim(p_rationale),
    decided_by = v_user_id, decided_at = now()
  where id = p_task_id and status = 'pending'
  returning * into v_task;
  if v_task.id is null then
    raise exception 'review task already decided' using errcode = '23514';
  end if;
  insert into public.audit_events(organisation_id, actor_id, action, target_type, target_id, result)
  values (v_organisation_id, v_user_id, 'review.decided', 'review_task', v_task.id, 'completed');
  return next v_task;
end;
$$;
revoke all on function public.decide_review_task(uuid, text, text) from public, anon;
grant execute on function public.decide_review_task(uuid, text, text) to authenticated;

alter default privileges for role postgres in schema public
  revoke select, insert, update, delete on tables from anon, authenticated;
alter default privileges for role postgres in schema public
  revoke execute on functions from public, anon, authenticated;

commit;
