"""Live web console (Plan 2): a dependency-free local dashboard that streams the run over SSE.

`owlforge run … --web` starts this alongside the normal stream and prints a localhost URL. The page
renders the same narrated events as a scrollable, selectable, filterable timeline with a findings
panel (hygiene folded) and an attack-surface list — the Strix-style rich view the TUI can't give
(copy/paste, screenshots, share). Built on http.server; the Emitter pushes each NarratedLine here.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# narrator Rich styles -> a small CSS color class set the page understands
_COLOR = {"bold green": "green", "green": "green", "bold red": "red", "red": "red",
          "yellow": "amber", "bold yellow": "amber", "cyan": "blue", "bold cyan": "blue",
          "blue": "blue", "bold blue": "blue", "magenta": "violet", "dim": "muted",
          "white": "fg", "bold white": "fg"}

_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>owlforge console</title>
<style>
:root{--bg:#0e1116;--panel:#161b22;--panel2:#1b212b;--fg:#e6edf3;--muted:#8b949e;--line:#2a313c;
--amber:#e0a82e;--green:#3fb950;--red:#f85149;--blue:#58a6ff;--violet:#bc8cff;color-scheme:dark;
--mono:"SFMono-Regular",ui-monospace,Menlo,Consolas,monospace;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
@media(prefers-color-scheme:light){:root{--bg:#f3f1ea;--panel:#fbfaf6;--panel2:#f1eee5;--fg:#1a1d22;
--muted:#6a7078;--line:#ddd8cc;--amber:#9a6b00;--green:#1a7f37;--red:#cf222e;--blue:#0a66c2;
--violet:#8250df;color-scheme:light}}
*{box-sizing:border-box}html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);font-size:13.5px;
display:flex;flex-direction:column}
header{display:flex;align-items:center;gap:14px;padding:10px 16px;border-bottom:1px solid var(--line);
background:var(--panel2);flex-wrap:wrap}
header .mk{font-family:var(--mono);color:var(--amber);font-weight:600}
header .t{color:var(--muted);font-family:var(--mono);font-size:12px}
header .phase{margin-left:auto;font-family:var(--mono);font-size:12px;color:var(--fg)}
header .phase b{color:var(--amber)}
.counts{font-family:var(--mono);font-size:12px}
.counts .v{color:var(--green)}.counts .c{color:var(--amber)}
main{flex:1;display:grid;grid-template-columns:1.6fr 1fr;min-height:0}
@media(max-width:820px){main{grid-template-columns:1fr}}
#timeline{overflow:auto;padding:12px 14px;border-right:1px solid var(--line)}
#side{overflow:auto;padding:12px 14px;display:flex;flex-direction:column;gap:18px}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:8px 14px;
border-bottom:1px solid var(--line);background:var(--panel)}
.toolbar input[type=search]{background:var(--bg);border:1px solid var(--line);color:var(--fg);
border-radius:6px;padding:5px 9px;font-family:var(--mono);font-size:12px;min-width:140px}
.toolbar label{font-size:12px;color:var(--muted);display:inline-flex;gap:5px;align-items:center}
.toolbar button{background:var(--panel2);border:1px solid var(--line);color:var(--fg);
border-radius:6px;padding:5px 10px;font-size:12px;cursor:pointer}
.row{font-family:var(--mono);font-size:12.5px;line-height:1.5;padding:2px 0;white-space:pre-wrap;
word-break:break-word}
.row .tag{font-weight:600;margin-right:6px}
.c-green{color:var(--green)}.c-red{color:var(--red)}.c-amber{color:var(--amber)}
.c-blue{color:var(--blue)}.c-violet{color:var(--violet)}.c-muted{color:var(--muted)}.c-fg{color:var(--fg)}
.row.think{opacity:.82;font-style:italic}
.row.finding{background:color-mix(in srgb,var(--amber) 9%,transparent);border-radius:5px;
padding:3px 7px;margin:3px 0}
.h2{font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;
color:var(--muted);margin:0 0 8px}
.find{font-family:var(--mono);font-size:12px;padding:5px 7px;border:1px solid var(--line);
border-radius:6px;margin-bottom:6px;display:flex;gap:7px;align-items:baseline}
.sev{width:8px;height:8px;border-radius:2px;flex:none;margin-top:4px}
.find .st{margin-left:auto;font-size:10.5px;color:var(--muted)}
#hygiene{color:var(--muted);font-family:var(--mono);font-size:12px;cursor:pointer}
#hygiene .n{color:var(--amber)}
#surface{font-family:var(--mono);font-size:11.5px;color:var(--muted);line-height:1.7;
white-space:pre-wrap}
.empty{color:var(--muted);font-size:12px}
</style></head>
<body>
<header>
  <span class="mk">,___, owlforge</span>
  <span class="t" id="meta"></span>
  <span class="phase">phase <b id="phase">starting</b></span>
  <span class="counts"><span class="v" id="nval">0</span> validated /
    <span class="c" id="ncand">0</span> candidate</span>
</header>
<div class="toolbar">
  <input type="search" id="q" placeholder="filter timeline…">
  <label><input type="checkbox" id="onlyf"> only findings</label>
  <label><input type="checkbox" id="hidehy" checked> hide hygiene</label>
  <button id="copy">copy timeline</button>
  <span class="t" id="conn" style="color:var(--muted);font-family:var(--mono);font-size:11px">● live</span>
</div>
<main>
  <div id="timeline"><div class="empty">waiting for events…</div></div>
  <div id="side">
    <div><div class="h2">Findings</div><div id="findings"><div class="empty">none yet</div></div>
      <div id="hygiene" hidden>▸ Security hygiene (<span class="n">0</span>) — grouped</div></div>
    <div><div class="h2">Attack surface</div><div id="surface" class="empty">mapping…</div></div>
  </div>
</main>
<script>
const META=__META__;
document.getElementById('meta').textContent=META.target+'  ·  '+META.model;
const tl=document.getElementById('timeline'),fd=document.getElementById('findings'),
  sv=document.getElementById('surface'),hy=document.getElementById('hygiene');
let nval=0,ncand=0,nhy=0,hygieneShown=false,rows=[];
const q=document.getElementById('q'),onlyf=document.getElementById('onlyf'),
  hidehy=document.getElementById('hidehy');
function applyFilters(){
  const term=q.value.toLowerCase(), of=onlyf.checked, hh=hidehy.checked;
  for(const r of rows){
    let show=true;
    if(of && !r.el.classList.contains('finding')) show=false;
    if(hh && r.ev.hygiene) show=false;
    if(term && !(r.ev.body+' '+r.ev.tag).toLowerCase().includes(term)) show=false;
    r.el.hidden=!show;
  }
}
[q,onlyf,hidehy].forEach(e=>e.addEventListener('input',applyFilters));
function phaseFor(ev){ return null; }
function add(ev){
  if(tl.querySelector('.empty')) tl.innerHTML='';
  if(ev.t==='status' && /phase/i.test(ev.body)){}
  // finding?
  if(ev.kind==='finding'){
    if(ev.hygiene){ nhy++; hy.hidden=false; hy.querySelector('.n').textContent=nhy; }
    else{
      const val=/confirm/i.test(ev.tag); val?nval++:ncand++;
      document.getElementById('nval').textContent=nval;
      document.getElementById('ncand').textContent=ncand;
      if(fd.querySelector('.empty')) fd.innerHTML='';
      const d=document.createElement('div'); d.className='find';
      const sev=val?'var(--green)':'var(--amber)';
      d.innerHTML='<span class="sev" style="background:'+sev+'"></span><span>'+esc(ev.body)+
        '</span><span class="st">'+(val?'validated':'candidate')+'</span>';
      fd.appendChild(d);
    }
  }
  // surface hint from http tool lines
  if(ev.kind==='http' && /\/(identity|community|workshop|api)\//.test(ev.body)){
    if(sv.classList.contains('empty')){sv.classList.remove('empty');sv.textContent='';}
    const seg=(ev.body.match(/\/[a-z0-9_]+\//i)||[''])[0];
    if(seg && !sv.textContent.includes(seg)) sv.textContent+=seg+'\n';
  }
  const row=document.createElement('div');
  let cls='row c-'+(ev.color||'fg'); if(ev.kind==='think')cls+=' think';
  if(ev.kind==='finding'&&!ev.hygiene)cls+=' finding'; row.className=cls;
  row.innerHTML='<span class="tag">'+esc(ev.tag)+'</span>'+esc(ev.body);
  tl.appendChild(row); rows.push({el:row,ev});
  if(rows.length>4000){rows[0].el.remove();rows.shift();}
  const near=tl.scrollHeight-tl.scrollTop-tl.clientHeight<120;
  applyFilters();
  if(near) tl.scrollTop=tl.scrollHeight;
  const ph=PHASE(ev.body); if(ph) document.getElementById('phase').textContent=ph;
}
function PHASE(b){const l=(b||'').toLowerCase();
  const map=[['report','reporting'],['validation','validation'],['access-control','deterministic passes'],
    ['bola','deterministic passes'],['oast','deterministic passes'],['planning the attack','hunt'],
    ['probing','hunt'],['crawled','recon'],['recon','recon'],['logged in','auth'],['operating with','auth']];
  for(const[k,v]of map) if(l.includes(k)) return v; return null;}
hy.addEventListener('click',()=>{hygieneShown=!hygieneShown; hidehy.checked=!hygieneShown; applyFilters();});
document.getElementById('copy').addEventListener('click',async()=>{
  const txt=rows.filter(r=>!r.el.hidden).map(r=>r.ev.tag+' '+r.ev.body).join('\n');
  try{await navigator.clipboard.writeText(txt);document.getElementById('copy').textContent='copied ✓';
    setTimeout(()=>document.getElementById('copy').textContent='copy timeline',1200);}catch(e){
    const r=document.createRange();r.selectNodeContents(tl);const s=getSelection();s.removeAllRanges();s.addRange(r);}
});
function esc(s){return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
const es=new EventSource('/events');
es.onmessage=e=>{try{add(JSON.parse(e.data));}catch(x){}};
es.onerror=()=>{document.getElementById('conn').textContent='● reconnecting';
  document.getElementById('conn').style.color='var(--amber)';};
es.onopen=()=>{document.getElementById('conn').textContent='● live';
  document.getElementById('conn').style.color='var(--muted)';};
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        console = self.server.console
        if self.path.split("?")[0] == "/":
            body = console.page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = console.subscribe()
            try:
                for ev in console.history():
                    self._send(ev)
                while True:
                    try:
                        ev = q.get(timeout=15)
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        continue
                    if ev is None:
                        break
                    self._send(ev)
            except (BrokenPipeError, ConnectionResetError, ValueError):
                pass
            finally:
                console.unsubscribe(q)
            return
        self.send_response(404)
        self.end_headers()

    def _send(self, ev):
        self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode())
        self.wfile.flush()


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, console):
        super().__init__(addr, _Handler)
        self.console = console

    def handle_error(self, request, client_address):
        # a browser closing an SSE stream resets the socket; that is normal, not an error worth
        # dumping a traceback into the scan output.
        import sys
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError,
                            TimeoutError, OSError)):
            return
        super().handle_error(request, client_address)


class WebConsole:
    def __init__(self, assessment_id: str, target: str, model: str, port: int = 0,
                 host: str = "127.0.0.1") -> None:
        meta = {"aid": assessment_id, "target": target, "model": model}
        self.page = _PAGE.replace("__META__", json.dumps(meta))
        self._ring: list[dict] = []
        self._subs: list[queue.Queue] = []
        self._lock = threading.Lock()
        self._server = _Server((host, port), self)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def history(self) -> list[dict]:
        with self._lock:
            return list(self._ring)

    def push(self, type_: str, message: str, line) -> None:
        ev = {"t": type_, "tag": line.tag.strip(), "body": line.body, "kind": line.kind,
              "hygiene": bool(line.hygiene), "color": _COLOR.get(line.tag_style, "fg"),
              "ts": time.time()}
        with self._lock:
            self._ring.append(ev)
            if len(self._ring) > 2000:
                self._ring = self._ring[-2000:]
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(ev)
            except Exception:
                pass

    def stop(self) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(None)
            except Exception:
                pass
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass
