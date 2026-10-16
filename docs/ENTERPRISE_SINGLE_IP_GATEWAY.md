# TraceAtlas authenticated single-IP local gateway

## Scope and rollout status: CODED, not deployed or enterprise-certified

TraceAtlas contains distinct components: a single-user local Employee/SQLite console; a static browser frontend plus a Vercel/Supabase authenticated API; an isolated private worker; and local Ollama. This change does not claim the cloud API or every integration works locally, and it does not turn the single-user employee into a multi-tenant server.

The one-IP Caddy ingress binds only to 127.0.0.1:8780. It is protected by gateway Basic authentication; the upstream local employee on 127.0.0.1:8765 additionally enforces a unique internal token, existing CSRF protection, and exact browser Origin. Gateway authentication is not a substitute for user/tenant authorization.

| Gateway path | Feature | Qualification |
| --- | --- | --- |
| / | Existing static frontend | UI only; hosted features require separate control plane |
| /hub/ | Authenticated service directory | Links to available local routes and explains their limits |
| /employee/ | Authenticated existing local Employee console | Local single-user case/evidence/OSINT |
| /directory/ | Existing static source catalogue | Catalogue, not activated connectors |
| /academy/ | Existing static academy | Educational pages |
| /gateway/healthz | Liveness response | Not workload readiness |
| /api/* | Returns HTTP 503 | Hosted APIs intentionally NOT mounted |

There is NO gateway route to Ollama 11434, SQLite data, provider credentials or unapproved tools.

## Setup and run

On Linux/macOS install Python 3.10+, Caddy 2.8+, TraceAtlas and optionally Ollama. Run caddy hash-password in a secure terminal. It prompts for a password and returns a bcrypt hash. Never commit a password, hash, case database, .env, or gateway token. Put the hash in a private environment/secret manager.

    export TRACEATLAS_GATEWAY_PASSWORD_HASH='BCRYPT_HASH_FROM_CADDY'
    export TRACEATLAS_WORKFORCE_ENABLED=1
    export TRACEATLAS_WORKSPACE="$PWD/cases"
    bash deploy/gateway/start-local.sh

The start script generates a random internal console token unless one was supplied, validates Caddy configuration, starts the console on localhost, and keeps Caddy in the foreground. All of these must run on the same host network namespace. It sets the browser gateway origin to exactly http://127.0.0.1:8780.

Service hub: http://127.0.0.1:8780/hub/
Browser address: http://127.0.0.1:8780/employee/
Gateway Basic-auth username: analyst. Supply the plaintext password you chose when generating the bcrypt hash, not the hash.

## Remote access using an encrypted tunnel

From the operator's separate workstation:

    ssh -N -L 8780:127.0.0.1:8780 USER@YOUR_SERVER

Then open http://127.0.0.1:8780/employee/ on that workstation and authenticate. SSH encrypts the tunnel while the gateway and console remain loopback-only. Bare public-IP HTTP/port forwarding (0.0.0.0) is NOT supported. Plain HTTP Basic auth is unsafe over unencrypted non-loopback networks. For multiple users or public access, implement HTTPS, identity/SSO, RLS tenant isolation and authenticated worker service boundaries separately.

## Tests, recovery and limitations

    PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_enterprise_local_gateway.py' -v
    PYTHONPATH=src python3 -m unittest discover -s tests -q
    python3 scripts/check_secrets.py
    python3 scripts/gateway_smoke.py  # only after gateway is running; prompts for password

Caddy config validation is built into the launcher because it must receive a real bcrypt hash and secret environment. Validate the live reverse proxy separately before use. The gateway heartbeat is not proof of full deployment.

Use TRACEATLAS_WORKFORCE_KILL_SWITCH=1 to halt new authorized work, and restart the gateway for configuration changes. Maintain case backups and test restoration, record incident response and retention, check full CI, run actual local Ollama/provider testing and an external security review before enterprise release. The underlying console remains SINGLE-USER. Existing cloud /api callers will get 503 on the local gateway unless a separate authenticated hosted control plane is deployed; do not silently proxy cloud services using a worker secret.
