from __future__ import annotations

import json
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, ElementTree

from ..db import CaseDB
from .correlation import correlate


def _html_graph(scan: dict, events: list[dict], edges: list[dict]) -> str:
    payload = json.dumps({"scan": scan, "events": events, "edges": edges},
                         ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>TraceAtlas offline graph</title><style>
body{margin:0;background:#0b1020;color:#e8eefc;font:14px system-ui;display:grid;grid-template-columns:260px 1fr 340px;height:100vh}
aside{padding:18px;border-right:1px solid #263354;overflow:auto}aside:last-child{border:0;border-left:1px solid #263354}
canvas{width:100%;height:100%;display:block}button,input{margin:6px 0}button{background:#3867d6;color:white;border:0;padding:9px 12px;border-radius:5px}
label{display:block;margin:5px 0}.muted{color:#9fb0d0}pre{white-space:pre-wrap;word-break:break-word;font-size:12px}.swatch{display:inline-block;width:10px;height:10px;margin-right:6px}
</style></head><body><aside><h2>TraceAtlas graph</h2><p class="muted" id="meta"></p>
<label>Minimum confidence <output id="cv">0</output>%</label><input id="confidence" type="range" min="0" max="100" value="0">
<h3>Event types</h3><div id="types"></div><button id="png">Export PNG</button><p class="muted">Offline read-only export. Node placement is a deterministic circular overview, not analytical evidence.</p></aside>
<main><canvas id="graph"></canvas></main><aside><h3>Selected event</h3><pre id="details">Click a node.</pre></aside>
<script>const graph=""" + payload + """;
const canvas=document.getElementById('graph'),ctx=canvas.getContext('2d'),details=document.getElementById('details');
const colors=['#5b8ff9','#61dDAa','#65789b','#f6bd16','#7262fd','#78d3f8','#9661bc','#f6903d','#e86452','#6dc8ec'];
const types=[...new Set(graph.events.map(e=>e.event_type))].sort(),palette=Object.fromEntries(types.map((t,i)=>[t,colors[i%colors.length]]));
const enabled=new Set(types); document.getElementById('meta').textContent=`Scan ${graph.scan.id} · ${graph.events.length} events · ${graph.edges.length} edges`;
for(const t of types){const l=document.createElement('label'),c=document.createElement('input'),s=document.createElement('span');c.type='checkbox';c.checked=true;c.onchange=()=>{c.checked?enabled.add(t):enabled.delete(t);draw()};s.className='swatch';s.style.background=palette[t];l.append(c,s,document.createTextNode(t));document.getElementById('types').append(l)}
function resize(){const d=devicePixelRatio||1,r=canvas.getBoundingClientRect();canvas.width=r.width*d;canvas.height=r.height*d;ctx.setTransform(d,0,0,d,0,0);draw()}
function visible(){const min=+document.getElementById('confidence').value;return graph.events.filter(e=>enabled.has(e.event_type)&&e.confidence>=min)}
let positions=new Map();function draw(){const w=canvas.clientWidth,h=canvas.clientHeight,nodes=visible(),ids=new Set(nodes.map(n=>n.id));ctx.clearRect(0,0,w,h);positions=new Map();const radius=Math.max(80,Math.min(w,h)*.38),cx=w/2,cy=h/2;
nodes.forEach((n,i)=>positions.set(n.id,{x:cx+radius*Math.cos(2*Math.PI*i/Math.max(1,nodes.length)),y:cy+radius*Math.sin(2*Math.PI*i/Math.max(1,nodes.length)),n}));ctx.strokeStyle='#34466f';ctx.lineWidth=1;
for(const e of graph.edges){if(!ids.has(e.parent_id)||!ids.has(e.child_id))continue;const a=positions.get(e.parent_id),b=positions.get(e.child_id);ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke()}
ctx.font='11px system-ui';for(const p of positions.values()){const size=5+p.n.confidence/18;ctx.beginPath();ctx.fillStyle=palette[p.n.event_type];ctx.arc(p.x,p.y,size,0,Math.PI*2);ctx.fill();ctx.strokeStyle={critical:'#ff3344',high:'#ff7a33',medium:'#f6bd16',low:'#5b8ff9',info:'#9aa7bf'}[p.n.risk]||'#9aa7bf';ctx.lineWidth=2;ctx.stroke();ctx.fillStyle='#e8eefc';ctx.fillText(p.n.event_type,p.x+size+3,p.y+3)}}
document.getElementById('confidence').oninput=e=>{document.getElementById('cv').value=e.target.value;draw()};canvas.onclick=e=>{const r=canvas.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;let hit=null,best=20;for(const p of positions.values()){const d=Math.hypot(p.x-x,p.y-y);if(d<best){hit=p.n;best=d}}details.textContent=hit?JSON.stringify(hit,null,2):'Click a node.'};
document.getElementById('png').onclick=()=>{const a=document.createElement('a');a.download=`traceatlas-${graph.scan.id}.png`;a.href=canvas.toDataURL('image/png');a.click()};addEventListener('resize',resize);resize();
</script></body></html>"""


def export_scan(db: CaseDB, scan_id: str, output: Path, fmt: str) -> Path:
    scan = db.spider_scan(scan_id)
    if not scan:
        raise ValueError(f"Unknown spider scan: {scan_id}")
    events, edges = db.spider_events(scan_id), db.spider_edges(scan_id)
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        output.write_text(json.dumps({
            "scan": scan, "events": events, "edges": edges,
            "correlations": correlate(events, edges),
        }, indent=2, ensure_ascii=False), encoding="utf-8")
    elif fmt == "gexf":
        root = Element("gexf", xmlns="http://www.gexf.net/1.3", version="1.3")
        graph = SubElement(root, "graph", mode="static", defaultedgetype="directed")
        nodes = SubElement(graph, "nodes")
        for event in events:
            SubElement(nodes, "node", id=event["id"],
                       label=f"{event['event_type']}: {str(event['data'])[:120]}")
        xml_edges = SubElement(graph, "edges")
        for index, edge in enumerate(edges):
            SubElement(xml_edges, "edge", id=str(index), source=edge["parent_id"],
                       target=edge["child_id"], label=edge["module"])
        ElementTree(root).write(output, encoding="utf-8", xml_declaration=True)
    elif fmt == "html":
        output.write_text(_html_graph(scan, events, edges), encoding="utf-8")
    else:
        raise ValueError("Format must be json, gexf or html")
    return output
