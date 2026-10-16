"use strict";
const API_BASE = location.pathname.startsWith("/employee/") ? "/employee" : "";
const $ = name => document.getElementById(name);
let csrf = "";
let docs = [];
let permissions = [];
let isBusy = false;
function say(node, value, tag="p") { const e=document.createElement(tag);e.textContent=String(value);node.append(e);return e; }
function fail(error) { $("error").textContent=error.message||String(error); }
async function api(path, value) {
  const opts = value === undefined ? {} : {method:"POST",headers:{"Content-Type":"application/json","X-TraceAtlas-CSRF":csrf},body:JSON.stringify(value)};
  const resp = await fetch(API_BASE+path,opts);
  const data = await resp.json();
  if (!resp.ok) throw Error(data.error||("HTTP "+resp.status));
  return data;
}
function authorized() { if(!$("authorize").checked) throw Error("Analyst authorization is required"); if(!$("case").value) throw Error("Select an existing case first"); }
async function refresh() {
  const c=$("case").value; if(!c) return;
  const data=await api("/api/agent/documents?case="+encodeURIComponent(c));
  docs=data.documents;
  $("doc-count").textContent=docs.length;
  $("edge-count").textContent=data.graph_edges;
  const host=$("documents");host.replaceChildren();
  const select=$("edge-doc");select.replaceChildren();
  for (const d of docs) {
    const row=document.createElement("div");row.className="record";
    say(row,d.title,"strong");say(row,d.document_id+" • "+d.sha256.slice(0,14),"small");host.append(row);
    const option=document.createElement("option");option.value=d.document_id;option.textContent=d.title;select.append(option);
  }
  if(!docs.length) say(host,"No documents in this case yet.");
}
async function init() {
  csrf=(await api("/api/session")).csrf_token;
  const [cases,manifest,ollama]=await Promise.all([api("/api/cases"),api("/api/agent/tools"),api("/api/ollama/status")]);
  const cs=$("case");cs.replaceChildren();
  for(const c of cases.cases){
    const opt=document.createElement("option");opt.value=c.id;opt.textContent=c.title+" ("+c.id+")";cs.append(opt);
  }
  $("model-status").textContent=ollama.available?"Ollama online: "+ollama.models.join(", "):"Ollama offline. Evidence-only fallback is available.";
  const tools=$("tools");tools.replaceChildren();
  for(const t of manifest.tools){
    const row=document.createElement("label");row.className="tool";
    const cb=document.createElement("input");cb.type="checkbox";cb.value=t.name;cb.checked=true;cb.addEventListener("change",countTools);
    const content=document.createElement("span");say(content,t.name,"strong");say(content,t.description,"small");row.append(cb,content);tools.append(row);
  }
  countTools();cs.addEventListener("change",()=>refresh().catch(fail));await refresh();
}
function countTools(){ permissions=Array.from(document.querySelectorAll("#tools input:checked")).map(x=>x.value);$("tool-count").textContent=permissions.length; }
async function safe(task){
  if(isBusy)return;
  isBusy=true;$("error").textContent="";
  try{await task();}catch(e){fail(e)}finally{isBusy=false}
}
$("add-document").onclick=()=>safe(async()=>{
  authorized();
  const x=await api("/api/agent/document",{case_id:$("case").value,title:$("document-title").value,text:$("document-text").value,authorized:true});
  $("state").textContent="Stored document "+x.document_id;
  $("document-text").value="";await refresh();
});
$("add-edge").onclick=()=>safe(async()=>{
  authorized();
  const x=await api("/api/agent/edge",{case_id:$("case").value,document_id:$("edge-doc").value,subject:$("subject").value,predicate:$("predicate").value,object:$("object").value,authorized:true});
  $("state").textContent="Linked evidence relation "+x.edge_id;await refresh();
});
$("execute").onclick=()=>safe(async()=>{
  authorized();countTools();
  if(!permissions.length)throw Error("Select at least one approved tool");
  $("execute").disabled=true;$("state").textContent="Running local Ollama workflow…";$("answer").textContent="";$("events").replaceChildren();
  try {
    const result=await api("/api/agent/run",{case_id:$("case").value,authorized:true,objective:$("objective").value,model:$("model").value,max_steps:Number($("steps").value),allowed_tools:permissions});
    $("state").textContent=result.status+" • "+result.run_id;
    $("answer").textContent=result.answer+"\n\nCitations: "+(result.citations.join(", ")||"No citations");
    for(const e of result.events){
      const node=document.createElement("div");node.className="record";
      say(node,e.tool+" • "+e.status,"strong");
      if(e.arguments)say(node,JSON.stringify(e.arguments),"small");
      if(e.result)say(node,e.result.slice(0,1400),"small");
      $("events").append(node);
    }
    if(!result.events.length) say($("events"),"No model-selected calls were made.");
  }finally{$("execute").disabled=false;}
});
init().catch(fail);