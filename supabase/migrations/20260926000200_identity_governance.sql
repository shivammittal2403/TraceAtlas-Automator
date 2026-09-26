-- TraceAtlas privileged membership lifecycle. Role changes require MFA AAL2.
begin;

create or replace function private.require_aal2()
returns void language plpgsql stable security definer set search_path = '' as $$
begin
  if (select auth.uid()) is null then
    raise exception 'authentication required' using errcode = '42501';
  end if;
  if coalesce((select auth.jwt() ->> 'aal'), '') <> 'aal2' then
    raise exception 'aal2 required' using errcode = '42501';
  end if;
end;
$$;
revoke all on function private.require_aal2() from public, anon, authenticated;

create or replace function public.set_organisation_member_role(
  p_organisation_id uuid, p_user_id uuid, p_role text
)
returns setof public.organisation_members
language plpgsql security definer set search_path = '' as $$
declare
  v_actor uuid := (select auth.uid());
  v_previous text;
  v_row public.organisation_members;
begin
  perform private.require_aal2();
  if p_role not in ('owner', 'admin', 'analyst', 'viewer') then
    raise exception 'invalid role' using errcode = '22023';
  end if;
  if not (select private.is_org_member(p_organisation_id, array['owner'])) then
    raise exception 'organisation unavailable' using errcode = '42501';
  end if;
  -- Serialize owner-set changes so concurrent demotions cannot remove every owner.
  perform 1 from public.organisation_members
  where organisation_id = p_organisation_id and role = 'owner' for update;
  select role into v_previous from public.organisation_members
  where organisation_id = p_organisation_id and user_id = p_user_id for update;
  if v_previous is null then
    raise exception 'member unavailable' using errcode = '42501';
  end if;
  if v_previous = 'owner' and p_role <> 'owner' and (
    select count(*) from public.organisation_members
    where organisation_id = p_organisation_id and role = 'owner'
  ) <= 1 then
    raise exception 'last owner cannot be demoted' using errcode = '23514';
  end if;
  update public.organisation_members set role = p_role
  where organisation_id = p_organisation_id and user_id = p_user_id
  returning * into v_row;
  insert into public.audit_events(
    organisation_id, actor_id, action, target_type, target_id, result,
    details
  ) values (
    p_organisation_id, v_actor, 'member.role_changed', 'user', p_user_id, 'completed',
    jsonb_build_object('previous_role', v_previous, 'new_role', p_role, 'aal', 'aal2')
  );
  return next v_row;
end;
$$;
revoke all on function public.set_organisation_member_role(uuid, uuid, text) from public, anon;
grant execute on function public.set_organisation_member_role(uuid, uuid, text) to authenticated;

create or replace function public.remove_organisation_member(
  p_organisation_id uuid, p_user_id uuid
)
returns boolean language plpgsql security definer set search_path = '' as $$
declare
  v_actor uuid := (select auth.uid());
  v_previous text;
begin
  perform private.require_aal2();
  if not (select private.is_org_member(p_organisation_id, array['owner'])) then
    raise exception 'organisation unavailable' using errcode = '42501';
  end if;
  -- Serialize owner-set changes so concurrent removals cannot remove every owner.
  perform 1 from public.organisation_members
  where organisation_id = p_organisation_id and role = 'owner' for update;
  select role into v_previous from public.organisation_members
  where organisation_id = p_organisation_id and user_id = p_user_id for update;
  if v_previous is null then
    raise exception 'member unavailable' using errcode = '42501';
  end if;
  if v_previous = 'owner' and (
    select count(*) from public.organisation_members
    where organisation_id = p_organisation_id and role = 'owner'
  ) <= 1 then
    raise exception 'last owner cannot be removed' using errcode = '23514';
  end if;
  delete from public.organisation_members
  where organisation_id = p_organisation_id and user_id = p_user_id;
  insert into public.audit_events(
    organisation_id, actor_id, action, target_type, target_id, result, details
  ) values (
    p_organisation_id, v_actor, 'member.removed', 'user', p_user_id, 'completed',
    jsonb_build_object('previous_role', v_previous, 'aal', 'aal2')
  );
  return true;
end;
$$;
revoke all on function public.remove_organisation_member(uuid, uuid) from public, anon;
grant execute on function public.remove_organisation_member(uuid, uuid) to authenticated;

commit;
