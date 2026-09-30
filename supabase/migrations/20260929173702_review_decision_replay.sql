begin;
-- The immutable task UUID is the operation key. Tenant membership is checked
-- before inspecting a decision; only the same actor and body can replay it.
create or replace function public.decide_review_task(
  p_task_id uuid, p_decision text, p_rationale text
)
returns setof public.review_tasks language plpgsql security definer set search_path = '' as $$
declare
  v_user_id uuid := (select auth.uid());
  v_task public.review_tasks;
begin
  if v_user_id is null then
    raise exception 'authentication required' using errcode = '42501';
  end if;
  if p_decision is null or p_decision not in ('accepted', 'rejected') or p_rationale is null
     or char_length(trim(p_rationale)) not between 10 and 2000 then
    raise exception 'invalid review decision' using errcode = '22023';
  end if;
  select * into v_task from public.review_tasks where id = p_task_id;
  if v_task.id is null or not (select private.is_org_member(v_task.organisation_id, array['owner','admin','analyst'])) then
    raise exception 'review task unavailable' using errcode = '42501';
  end if;
  select * into v_task from public.review_tasks where id = p_task_id for update;
  if v_task.id is null then
    raise exception 'review task unavailable' using errcode = '42501';
  end if;
  if v_task.status <> 'pending' then
    if v_task.status = p_decision and v_task.decision_rationale = trim(p_rationale)
       and v_task.decided_by = v_user_id then
      return next v_task;
      return;
    end if;
    raise exception 'review decision conflicts with an existing decision' using errcode = '23505';
  end if;
  update public.review_tasks set status = p_decision, decision_rationale = trim(p_rationale),
    decided_by = v_user_id, decided_at = now()
  where id = p_task_id returning * into v_task;
  insert into public.audit_events(organisation_id, actor_id, action, target_type, target_id, result)
  values (v_task.organisation_id, v_user_id, 'review.decided', 'review_task', v_task.id, 'completed');
  return next v_task;
end;
$$;
revoke all on function public.decide_review_task(uuid, text, text) from public, anon;
grant execute on function public.decide_review_task(uuid, text, text) to authenticated;
commit;
