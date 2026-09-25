# Isolated worker

The worker is the execution plane. Vercel handles authenticated control-plane
requests only; it never runs reconnaissance binaries.

Required worker-only values: `SUPABASE_URL`, `SUPABASE_SECRET_KEY` and
`TRACEATLAS_WORKER_ID`. Run one job with `traceatlas-worker once` or serve with
`traceatlas-worker serve`.

Do not publish a worker port, mount the Docker socket, run as root or pass a key
on the command line. Use outbound-only network policy and a read-only container
filesystem except for the evidence volume. Identity targets, private addresses
and arbitrary commands are unsupported.
