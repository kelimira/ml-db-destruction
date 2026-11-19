"""Self-contained split-view HTML for the story demo (log left, live charts right). No dependencies."""

from __future__ import annotations

import json


def write_html(story, path: str) -> None:
    data = dict(days=story.days, events=story.events, acts=story.acts)
    # "</" would let SQL text close the script tag; the page only ever uses textContent.
    blob = json.dumps(data).replace("</", "<\\/")
    with open(path, "w", encoding="utf-8") as f:
        f.write(TEMPLATE.replace("__DATA__", blob))


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dbguard learning story</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--ink:#1c2330;--mute:#677086;--line:#dde1e8;
--ok:#2f9e63;--warn:#e29a1b;--bad:#d64545;--blue:#3b73d9;--purple:#8250c8;--shade:#3b73d91a}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--panel:#1a1f28;--ink:#e6e9ef;--mute:#8d96a8;--line:#2b3240;
--ok:#4cc38a;--warn:#f0b13e;--bad:#f06a6a;--blue:#6b9cff;--purple:#b08cf0;--shade:#6b9cff22}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,sans-serif}
header{padding:14px 16px 6px}
h1{margin:0;font-size:18px}
.sub{color:var(--mute);font-size:13px}
.bar{display:flex;gap:10px;align-items:center;padding:8px 16px;flex-wrap:wrap}
button{background:var(--blue);color:#fff;border:0;border-radius:6px;padding:6px 14px;font:inherit;cursor:pointer}
input[type=range]{flex:1;min-width:160px}
.kpis{display:flex;gap:10px;padding:0 16px 10px;flex-wrap:wrap}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:6px 12px;min-width:110px}
.kpi b{display:block;font-size:20px}.kpi span{color:var(--mute);font-size:12px}
main{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.1fr);gap:12px;padding:0 16px 16px}
@media (max-width:900px){main{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px}
.panel h2{margin:0 0 6px;font-size:13px;color:var(--mute);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
#log{height:620px;overflow:auto;font:12px/1.5 ui-monospace,Menlo,monospace}
#log div{padding:2px 6px;border-left:3px solid transparent;white-space:pre-wrap;word-break:break-word}
#log .act{margin-top:10px;font-weight:700;font-family:system-ui;background:var(--shade);border-left-color:var(--blue)}
#log .day{color:var(--mute)}
#log .warn{border-left-color:var(--warn)}#log .blocked{border-left-color:var(--bad);background:#d6454512}
#log .approve,#log .ok{border-left-color:var(--ok)}#log .mode{border-left-color:var(--blue);font-weight:700}
svg{width:100%;height:auto;display:block}
svg text{fill:var(--mute);font:11px system-ui}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--mute);margin:4px 0 12px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px;vertical-align:-1px}
</style></head><body>
<header><h1>dbguard: learning what is normal, catching what is not</h1>
<div class="sub">45 simulated days of one app's database traffic. Press play, or drag the slider.</div></header>
<div class="bar"><button id="play">Play</button><input id="day" type="range" min="1" value="1">
<span id="dlabel"></span></div>
<div class="kpis">
<div class="kpi"><b id="k-mode">-</b><span>mode</span></div>
<div class="kpi"><b id="k-stmts">0</b><span>statements seen</span></div>
<div class="kpi"><b id="k-alerts">0</b><span>alerts raised</span></div>
<div class="kpi"><b id="k-block">0</b><span>statements blocked</span></div></div>
<main>
<section class="panel"><h2>What happened</h2><div id="log"></div></section>
<section>
<div class="panel"><h2>Risk score of two statements over time</h2>
<div class="legend"><span><i style="background:var(--blue)"></i>known 34-row nightly cleanup</span>
<span><i style="background:var(--purple)"></i>120-row weekly archive</span></div>
<svg id="c1" viewBox="0 0 640 260"></svg></div>
<div class="panel" style="margin-top:12px"><h2>Rows touched vs what it learned is normal</h2>
<div class="legend"><span><i style="background:var(--blue)"></i>normal range: session cleanup</span>
<span><i style="background:var(--purple)"></i>normal range: orders updates</span>
<span><i style="background:var(--ok)"></i>allowed</span><span><i style="background:var(--warn)"></i>warned</span>
<span><i style="background:var(--bad)"></i>blocked</span></div>
<svg id="c2" viewBox="0 0 640 260"></svg></div>
</section></main>
<script id="d" type="application/json">__DATA__</script>
<script>
const D2=JSON.parse(document.getElementById('d').textContent);
const days=D2.days,events=D2.events,acts=D2.acts,N=days.length;
const css=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const NS='http://www.w3.org/2000/svg';
function el(p,t,a,txt){const e=document.createElementNS(NS,t);for(const k in a)e.setAttribute(k,a[k]);if(txt!=null)e.textContent=txt;p.appendChild(e);return e}
const W=640,H=260,L=44,R=12,T=10,B=26;
const X=d=>L+(d-1)/(N-1)*(W-L-R);
function frame(svg,ylab){svg.textContent='';
 for(const d of [1,8,15,21,28,35,42,45])el(svg,'text',{x:X(d),y:H-8,'text-anchor':'middle'},'d'+d);
 return svg}
function shade(svg,cur){const m=days.findIndex(x=>x.mode==='enforcing');
 const end=m<0?N:m; // learning span
 el(svg,'rect',{x:X(1),y:T,width:Math.max(0,X(Math.min(end,cur))-X(1)),height:H-T-B,fill:css('--shade')});
 el(svg,'text',{x:X(1)+4,y:T+12},'learning mode')}
function cursor(svg,cur){el(svg,'line',{x1:X(cur),x2:X(cur),y1:T,y2:H-B,stroke:css('--mute'),'stroke-dasharray':'3 3'})}
function dot(svg,x,y,kind,tip){const c={ok:css('--ok'),warn:css('--warn'),blocked:css('--bad'),approve:css('--ok')}[kind]||css('--mute');
 const g=el(svg,'g',{});
 if(kind==='blocked'){el(g,'path',{d:`M${x-5} ${y-5}L${x+5} ${y+5}M${x+5} ${y-5}L${x-5} ${y+5}`,stroke:c,'stroke-width':2.5})}
 else el(g,'circle',{cx:x,cy:y,r:kind==='warn'?5.5:4,fill:c,stroke:css('--panel'),'stroke-width':1.5});
 el(g,'title',{},tip)}
function chart1(cur){const s=frame(document.getElementById('c1'));
 const Y=v=>T+(1-v)*(H-T-B);
 shade(s,cur);
 for(const v of [0,.4,.7,1]){el(s,'line',{x1:L,x2:W-R,y1:Y(v),y2:Y(v),stroke:css('--line')});el(s,'text',{x:L-6,y:Y(v)+4,'text-anchor':'end'},v)}
 el(s,'text',{x:W-R-2,y:Y(.4)-3,'text-anchor':'end',fill:css('--warn')},'warn');
 el(s,'text',{x:W-R-2,y:Y(.7)-3,'text-anchor':'end',fill:css('--bad')},'destructive');
 for(const [k,col] of [['cleanup','--blue'],['archive','--purple']]){
  const pts=days.slice(0,cur).map(d=>`${X(d.day)},${Y(d[k])}`).join(' ');
  el(s,'polyline',{points:pts,fill:'none',stroke:css(col),'stroke-width':2.5})}
 for(const e of events)if(e.day<=cur&&e.score!=null&&e.kind!=='ok')dot(s,X(e.day),Y(e.score),e.kind,e.text);
 cursor(s,cur)}
function chart2(cur){const s=frame(document.getElementById('c2'));
 const lo=0,hi=Math.log10(10000);
 const Y=v=>T+(1-(Math.log10(Math.max(v,1))-lo)/(hi-lo))*(H-T-B);
 shade(s,cur);
 for(const v of [1,10,100,1000,10000]){el(s,'line',{x1:L,x2:W-R,y1:Y(v),y2:Y(v),stroke:css('--line')});el(s,'text',{x:L-6,y:Y(v)+4,'text-anchor':'end'},v)}
 for(const [k,col] of [['sessions','--blue'],['orders','--purple']]){
  const up=[],dn=[];
  for(const d of days.slice(0,cur))if(d.band[k]){up.push([X(d.day),Y(d.band[k][1])]);dn.push([X(d.day),Y(Math.max(d.band[k][0],1))])}
  if(up.length>1){const pts=up.concat(dn.reverse()).map(p=>p.join(',')).join(' ');
   el(s,'polygon',{points:pts,fill:css(col),'fill-opacity':.22,stroke:css(col)})}}
 for(const e of events)if(e.day<=cur&&e.rows!=null&&e.rows>0)dot(s,X(e.day),Y(e.rows),e.kind,e.text);
 cursor(s,cur)}
const logEl=document.getElementById('log');let shown=0;
function renderLog(cur){
 if(cur<shown){logEl.textContent='';shown=0}
 for(let d=shown+1;d<=cur;d++){
  for(const a of acts)if(a.day===d){const x=document.createElement('div');x.className='act';x.textContent=a.title;logEl.appendChild(x)}
  const r=days[d-1];const x=document.createElement('div');x.className='day';
  x.textContent=`Day ${d}  ${r.mode}  ${r.stmts} stmts  ${r.alerts} alerts`;logEl.appendChild(x);
  for(const e of events)if(e.day===d){const y=document.createElement('div');y.className=e.kind;y.textContent=e.text;logEl.appendChild(y)}}
 shown=cur;logEl.scrollTop=logEl.scrollHeight}
function render(cur){const r=days[cur-1];
 document.getElementById('dlabel').textContent=`Day ${cur} / ${N}`;
 document.getElementById('k-mode').textContent=r.mode;
 document.getElementById('k-stmts').textContent=r.stmts;
 document.getElementById('k-alerts').textContent=r.alerts;
 document.getElementById('k-block').textContent=events.filter(e=>e.day<=cur&&e.kind==='blocked').length;
 renderLog(cur);chart1(cur);chart2(cur)}
const sl=document.getElementById('day');sl.max=N;
sl.oninput=()=>{stop();render(+sl.value)};
let timer=null;const pb=document.getElementById('play');
function stop(){clearInterval(timer);timer=null;pb.textContent='Play'}
pb.onclick=()=>{if(timer){stop();return}
 if(+sl.value>=N)sl.value=1;pb.textContent='Pause';
 timer=setInterval(()=>{if(+sl.value>=N){stop();return}sl.value=+sl.value+1;render(+sl.value)},450)};
render(1);
</script></body></html>
"""
