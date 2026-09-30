import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';

// Real PostgreSQL SQL/RLS execution, synthetic auth claims, one session.
// This does not replace hosted JWT/storage or multi-session concurrency tests.
test('migrations, tenant RLS and bounded idempotent job admission', async () => {
  const db = new PGlite({ extensions: { pgcrypto } });
  const id = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
  const login = async n => {
    await db.exec('reset role; set role authenticated');
    await db.query("select set_config('request.jwt.claim.sub', $1, false)", [id(n)]);
  };
  const enqueue = (c, a, key = 'fixture-request-0001', kind = 'domain_passive') =>
    db.query('select * from public.enqueue_investigation_job($1,$2,$3,$4)', [id(c), id(a), kind, key]);
  try {
    await db.exec(`create role anon; create role authenticated; create role service_role bypassrls;
      create schema auth; create table auth.users (id uuid primary key);
      create function auth.uid() returns uuid language sql stable as
        $$ select nullif(current_setting('request.jwt.claim.sub', true),'')::uuid $$;
      create function auth.jwt() returns jsonb language sql stable as $$ select '{"aal":"aal2"}'::jsonb $$;
      grant usage on schema auth to authenticated, service_role;
      grant execute on all functions in schema auth to authenticated, service_role;`);
    const directory = new URL('../supabase/migrations/', import.meta.url);
    for (const file of (await readdir(directory)).filter(f => f.endsWith('.sql')).sort()) {
      await db.exec(await readFile(new URL(file, directory), 'utf8'));
    }
    for (const n of [1, 2, 3]) await db.query('insert into auth.users values ($1)', [id(n)]);
    for (const [org, user] of [[10, 1], [20, 2]]) {
      await db.query('insert into organisations(id,created_by,name) values ($1,$2,$3)', [id(org), id(user), `Tenant ${org}`]);
    }
    await db.query("insert into organisation_members(organisation_id,user_id,role) values ($1,$2,'viewer')", [id(10), id(3)]);
    for (const [c, org, user] of [[11, 10, 1], [12, 10, 1], [21, 20, 2]]) {
      await db.query("insert into cases(id,organisation_id,created_by,title,purpose) values ($1,$2,$3,'Fixture case','Synthetic authorized test')", [id(c),id(org),id(user)]);
    }
    for (const [a, org, user] of [[15,10,1],[16,10,1],[25,20,2]]) {
      await db.query("insert into assets(id,organisation_id,created_by,label,target_type,target_value,ownership_basis) values ($1,$2,$3,'Fixture','domain',$4,'owned_asset')", [id(a),id(org),id(user),`fixture-${a}.example`]);
    }
    await db.query("insert into review_tasks(id,organisation_id,case_id,created_by,kind,title) values ($1,$2,$3,$4,'evidence','Fixture review')", [id(30),id(10),id(11),id(1)]);
    const decide = (decision = 'accepted', rationale = 'Reviewed synthetic evidence') => db.query(
      'select * from decide_review_task($1,$2,$3)', [id(30),decision,rationale]);
    await login(2);
    await assert.rejects(decide(), e => e.code === '42501');
    await login(3);
    await assert.rejects(decide(), e => e.code === '42501');
    await login(1);
    const decision = (await decide()).rows[0];
    assert.deepEqual((await decide()).rows[0], decision);
    await assert.rejects(decide('rejected'), e => e.code === '23505');
    await assert.rejects(decide('accepted', 'Different synthetic rationale'), e => e.code === '23505');
    assert.equal((await db.query("select * from audit_events where action='review.decided'")).rows.length, 1);
    assert.equal((await db.query('select * from cases')).rows.length, 2);
    await assert.rejects(enqueue(21,25), e => e.code === '42501');
    await assert.rejects(enqueue(11,25), e => e.code === '42501');
    await login(3);
    await assert.rejects(enqueue(11,15), e => e.code === '42501');
    await login(1);
    const first = (await enqueue(11,15)).rows[0];
    assert.equal((await enqueue(11,15)).rows[0].id, first.id, 'identical replay returns the original job');
    await assert.rejects(enqueue(11,16), e => e.code === '23505');
    await assert.rejects(enqueue(11,15,'fixture-request-0001','ip_passive'), e => e.code === '23505');
    const otherCase = (await enqueue(12,15)).rows[0];
    assert.notEqual(otherCase.id, first.id, 'same key in a different case is independent');
    for (let n = 0; n < 18; n++) await enqueue(11,15,`fixture-budget-${String(n).padStart(4,'0')}`);
    await assert.rejects(enqueue(11,15,'fixture-over-limit'), e => e.code === '23514');
    assert.equal((await enqueue(11,15)).rows[0].id, first.id, 'replay works even at the admission limit');
    assert.equal((await db.query("select * from audit_events where action='job.enqueued'")).rows.length, 20);
    await login(2);
    assert.equal((await db.query('select * from investigation_jobs')).rows.length, 0);
    assert.notEqual((await enqueue(21,25)).rows[0].id, first.id);
    await db.exec('reset role; set role anon');
    await assert.rejects(enqueue(11,15), e => e.code === '42501');
  } finally { await db.close(); }
});
