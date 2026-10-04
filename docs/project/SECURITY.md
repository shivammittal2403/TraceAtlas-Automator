# Security policy

Only the latest `main` revision and latest tagged release receive security
fixes. Report vulnerabilities privately through GitHub Security Advisories. Do
not put credentials, personal data, private targets or exploit details in a
public issue, and do not access another organisation's data while testing.

## Trust boundaries

- Vercel receives a Supabase publishable key only; RLS remains mandatory.
- Supabase secret/service-role keys belong only on the isolated worker.
- Cloud jobs accept only enrolled domain, public IP, public URL and hash assets.
- Person, email and username investigations remain local and consent-gated.
- Worker records are untrusted input; database strings never become commands.
- AI/model output is advisory and cannot authorize tools.

Every change must pass tests, compilation, launcher/JavaScript validation,
secret scanning and supply-chain artifact generation. Tagged builds produce a
wheel, CycloneDX SBOM and SHA-256 manifest.
