"""Read-only, self-contained health and portfolio snapshots; no remote scripts."""
from html import escape


def render_dashboard(report, records, health):
    labels = {'registered': 'REGISTERED SOURCES', 'governed': 'GOVERNED SOURCES', 'documented': 'DOCUMENTED SOURCES',
              'implemented': 'IMPLEMENTED CONNECTORS', 'integration_tested': 'TESTED CONNECTORS',
              'live_tested': 'LIVE-TESTED SOURCES', 'live_verified': 'LIVE-VERIFIED SOURCES',
              'production_qualified': 'PRODUCTION-QUALIFIED SOURCES',
              'degraded': 'DEGRADED SOURCES', 'failed': 'FAILED SOURCES'}
    def text(value):
        return escape('UNKNOWN' if value is None else str(value), quote=True)
    cards = ''.join('<article><b>'+text(report['counts'].get(key))+'</b><span>'+label+'</span></article>'
                    for key, label in labels.items())
    coverage = ''.join('<tr><td>'+text(key)+'</td><td>'+text(value['reviewed'])+'</td><td>'+
                       text(value['target'])+'</td><td>'+text(value['gap'])+'</td></tr>'
                       for key, value in report['family_coverage'].items())
    health_by_id = {row['source_id']: row for row in health['sources']}
    rows = ''
    for row in records:
        observed = health_by_id.get(row['source_id'], {})
        values = [row['source_id'], row['official_name'], row['source_family'],
                  'REGISTERED' if row['registered'] else 'RESEARCH ONLY',
                  observed.get('health', 'UNKNOWN'), row['qualification_status'],
                  observed.get('last_observed_at'), row.get('blocked_reason')]
        rows += '<tr>'+''.join('<td>'+text(value)+'</td>' for value in values)+'</tr>'
    return '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>TraceAtlas Source Fabric</title><style>
:root{font-family:system-ui,sans-serif;color:#dde5f2;background:#0e1625}body{max-width:1500px;margin:auto;padding:28px}
h1{font-size:28px}p{color:#aebed4;line-height:1.6}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}
article{background:#19263c;border:1px solid #324662;border-radius:10px;padding:20px}article b{font-size:32px;display:block}
article span{font-size:12px;color:#bdd0eb}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:10px;text-align:left;border-bottom:1px solid #324662}
th{background:#19263c}.table{overflow:auto}section{margin-top:32px}code{color:#91cff8}
</style><h1>TraceAtlas Source Fabric</h1>
<p>Read-only snapshot of recorded source metadata and observed health. Health and maturity are separate.
Unknown measurements remain UNKNOWN. Candidate names, aliases, parsers and fixture tests do not establish integrations.</p>
<div class="cards">'''+cards+'''</div><section><h2>Acceptance targets</h2><p>Portfolio targets satisfied: '''+text(report['targets_satisfied'])+'''.
Required portfolio: 650 governed records, 600 mapped sources, 450 usable connectors, 300 integration-tested,
200 live-verified and 125 production-qualified. These are targets.</p></section>
<section><h2>Reviewed family coverage</h2><div class="table"><table><thead><tr><th>Family</th><th>Reviewed records</th><th>Target</th><th>Gap</th></tr></thead><tbody>'''+coverage+'''</tbody></table></div></section>
<section><h2>Source health and maturity</h2><div class="table"><table><thead><tr><th>Source ID</th><th>Official name</th><th>Family</th><th>Registration</th><th>Health</th><th>Maturity</th><th>Last observed</th><th>Recorded obstacle</th></tr></thead><tbody>'''+rows+'''</tbody></table></div></section>
<p>Regenerate with <code>traceatlas source-fabric portfolio --html dashboard.html</code> after new receipts or live executions.
This snapshot performs no network probes and grants no collection authority.</p></html>'''
