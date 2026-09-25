begin;
select plan(23);

select ok((select relrowsecurity from pg_class where oid = 'public.organisations'::regclass), 'organisations RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.organisation_members'::regclass), 'members RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.cases'::regclass), 'cases RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.assets'::regclass), 'assets RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.investigation_jobs'::regclass), 'jobs RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.job_events'::regclass), 'job events RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.evidence_items'::regclass), 'evidence RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.graph_entities'::regclass), 'entities RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.graph_edges'::regclass), 'edges RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.audit_events'::regclass), 'audit RLS enabled');
select ok(not has_table_privilege('anon', 'public.organisations', 'select'), 'anon cannot read organisations');
select ok(not has_table_privilege('anon', 'public.cases', 'select'), 'anon cannot read cases');
select ok(not has_table_privilege('anon', 'public.assets', 'select'), 'anon cannot read assets');
select ok(not has_table_privilege('anon', 'public.investigation_jobs', 'select'), 'anon cannot read jobs');
select ok(not has_table_privilege('authenticated', 'public.investigation_jobs', 'insert'), 'users cannot directly insert jobs');
select ok(not has_table_privilege('authenticated', 'public.investigation_jobs', 'update'), 'users cannot forge job status');
select ok(not has_table_privilege('authenticated', 'public.evidence_items', 'insert'), 'users cannot forge evidence');
select ok(not has_table_privilege('authenticated', 'public.organisation_members', 'insert'), 'users cannot self-assign roles');
select ok(not has_function_privilege('authenticated', 'public.claim_next_investigation_job(text)', 'execute'), 'users cannot claim jobs');
select ok(not has_function_privilege('authenticated', 'public.complete_investigation_job(uuid,text,text,jsonb)', 'execute'), 'users cannot complete jobs');
select ok(has_function_privilege('authenticated', 'public.enqueue_investigation_job(uuid,uuid,text,text)', 'execute'), 'users may call governed enqueue');
select ok(has_function_privilege('service_role', 'public.claim_next_investigation_job(text)', 'execute'), 'worker may claim jobs');
select ok(not has_function_privilege('authenticated', 'public.recover_stale_investigation_jobs()', 'execute'), 'users cannot recover leases');

select * from finish();
rollback;
