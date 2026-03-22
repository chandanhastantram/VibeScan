"""
CodeSentinel — Local Web Dashboard Server
Starts a local HTTP server serving the scan history dashboard.
Zero extra dependencies — uses only stdlib (http.server, json, threading).

Usage:
    python -m vibecodereviewer serve
    python -m vibecodereviewer serve --port 8080
    python -m vibecodereviewer serve --db /path/to/custom.db
"""

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import urlparse, parse_qs

from .storage import ScanStore


# ── Inline dashboard HTML ─────────────────────────────────────────────────────
# Single-file, self-contained. Chart.js via cdnjs (stdlib-friendly).

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CodeSentinel Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#0d0d0e;--bg2:#141416;--bg3:#1a1a1d;--bg4:#212124;
    --border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.13);
    --text:#e2e0d9;--text2:#9b9990;--text3:#58574f;
    --red:#E24B4A;--orange:#EF9F27;--yellow:#D4B84A;--blue:#4A9EE8;--green:#4AC88C;--gray:#888780;
    --red-bg:rgba(226,75,74,0.10);--orange-bg:rgba(239,159,39,0.10);
    --yellow-bg:rgba(212,184,74,0.10);--blue-bg:rgba(74,158,232,0.10);
    --green-bg:rgba(74,200,140,0.10);
    --mono:'IBM Plex Mono',monospace;--sans:'IBM Plex Sans',sans-serif;
  }
  html{font-family:var(--sans);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6}
  a{color:inherit;text-decoration:none}

  /* ── Layout ── */
  .layout{display:grid;grid-template-columns:220px 1fr;min-height:100vh}
  .sidebar{background:var(--bg2);border-right:0.5px solid var(--border);padding:24px 0;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}
  .main{padding:32px;overflow-x:hidden}

  /* ── Sidebar ── */
  .logo{font-family:var(--mono);font-size:11px;color:var(--text3);letter-spacing:0.12em;text-transform:uppercase;padding:0 20px;margin-bottom:28px}
  .logo span{color:var(--green);font-size:14px;margin-right:4px}
  .nav-section{font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:0.1em;color:var(--text3);padding:0 20px;margin:16px 0 6px}
  .nav-item{display:flex;align-items:center;gap:10px;padding:8px 20px;font-size:13px;color:var(--text2);cursor:pointer;transition:background 0.1s,color 0.1s;border-radius:0}
  .nav-item:hover{background:var(--bg3);color:var(--text)}
  .nav-item.active{background:var(--bg3);color:var(--text);border-right:2px solid var(--green)}
  .nav-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
  .target-list{margin-top:4px}
  .target-item{padding:6px 20px 6px 36px;font-size:12px;font-family:var(--mono);color:var(--text3);cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .target-item:hover{color:var(--text2)}
  .target-item.active{color:var(--blue)}
  .sidebar-footer{margin-top:auto;padding:16px 20px;border-top:0.5px solid var(--border)}
  .sidebar-footer p{font-size:11px;color:var(--text3);font-family:var(--mono)}

  /* ── Header ── */
  .page-header{margin-bottom:28px}
  .page-title{font-size:20px;font-weight:500;margin-bottom:4px}
  .page-sub{font-size:13px;color:var(--text2)}

  /* ── Stat cards ── */
  .stats-row{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:28px}
  .stat-card{background:var(--bg2);border:0.5px solid var(--border);border-radius:10px;padding:16px;cursor:pointer;transition:border-color 0.15s,transform 0.15s}
  .stat-card:hover{border-color:var(--border2);transform:translateY(-1px)}
  .stat-num{font-size:26px;font-weight:500;font-family:var(--mono);line-height:1;margin-bottom:4px}
  .stat-lbl{font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:var(--text3)}

  /* ── Trend chart ── */
  .chart-card{background:var(--bg2);border:0.5px solid var(--border);border-radius:10px;padding:20px;margin-bottom:24px}
  .chart-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
  .chart-title{font-size:13px;font-weight:500}
  .chart-controls{display:flex;gap:8px}
  .ctrl-btn{padding:4px 10px;border-radius:16px;font-size:11px;font-family:var(--mono);border:0.5px solid var(--border2);background:transparent;color:var(--text2);cursor:pointer;transition:all 0.1s}
  .ctrl-btn:hover{color:var(--text);border-color:var(--border2)}
  .ctrl-btn.active{background:var(--bg4);color:var(--text);border-color:var(--border2)}
  .legend{display:flex;gap:16px;margin-bottom:12px;flex-wrap:wrap}
  .legend-item{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--text2);cursor:pointer}
  .legend-dot{width:8px;height:8px;border-radius:2px;flex-shrink:0}

  /* ── Scan history table ── */
  .table-card{background:var(--bg2);border:0.5px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:24px}
  .table-header{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:0.5px solid var(--border)}
  .table-title{font-size:13px;font-weight:500}
  .search-input{background:var(--bg3);border:0.5px solid var(--border);border-radius:6px;padding:5px 10px;font-family:var(--mono);font-size:11px;color:var(--text);outline:none;width:200px}
  .search-input::placeholder{color:var(--text3)}
  .search-input:focus{border-color:var(--border2)}
  table{width:100%;border-collapse:collapse}
  th{font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:var(--text3);font-weight:500;padding:10px 18px;text-align:left;border-bottom:0.5px solid var(--border)}
  td{padding:11px 18px;font-size:12px;border-bottom:0.5px solid var(--border)}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:var(--bg3)}
  .sev-pill{display:inline-block;font-family:var(--mono);font-size:9px;font-weight:500;padding:1px 6px;border-radius:3px;letter-spacing:0.04em}
  .mono{font-family:var(--mono);color:var(--text2)}
  .row-action{opacity:0;transition:opacity 0.1s}
  tr:hover .row-action{opacity:1}
  .btn-sm{padding:4px 10px;border-radius:5px;font-size:11px;font-family:var(--mono);border:0.5px solid var(--border2);background:transparent;color:var(--text2);cursor:pointer;transition:all 0.1s}
  .btn-sm:hover{color:var(--text);border-color:var(--blue);background:var(--blue-bg)}
  .btn-del:hover{color:var(--red);border-color:var(--red);background:var(--red-bg)}

  /* ── Findings drawer ── */
  .drawer-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:100}
  .drawer-overlay.open{display:block}
  .drawer{position:fixed;right:0;top:0;bottom:0;width:700px;background:var(--bg2);border-left:0.5px solid var(--border);overflow-y:auto;z-index:101;transform:translateX(100%);transition:transform 0.2s}
  .drawer.open{transform:translateX(0)}
  .drawer-head{padding:20px 24px;border-bottom:0.5px solid var(--border);position:sticky;top:0;background:var(--bg2);z-index:1;display:flex;align-items:flex-start;gap:12px}
  .drawer-close{padding:4px 10px;border-radius:5px;font-size:12px;font-family:var(--mono);border:0.5px solid var(--border2);background:transparent;color:var(--text2);cursor:pointer;margin-left:auto;flex-shrink:0}
  .drawer-body{padding:20px 24px}
  .finding-item{background:var(--bg3);border:0.5px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:8px}
  .fi-header{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer}
  .fi-title{font-weight:500;font-size:13px;flex:1}
  .fi-loc{font-family:var(--mono);font-size:10px;color:var(--text3);white-space:nowrap}
  .fi-chev{color:var(--text3);font-size:11px;transition:transform 0.2s;flex-shrink:0}
  .finding-item.open .fi-chev{transform:rotate(90deg)}
  .fi-body{display:none;padding:0 14px 14px;border-top:0.5px solid var(--border)}
  .finding-item.open .fi-body{display:block}
  .fi-tags{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0 8px}
  .fi-tag{font-family:var(--mono);font-size:10px;padding:2px 7px;border-radius:3px;background:var(--bg4);border:0.5px solid var(--border);color:var(--text2)}
  .fi-desc{font-size:12px;color:var(--text2);margin-bottom:8px;line-height:1.6}
  .fi-code{background:var(--bg4);border:0.5px solid var(--border);border-radius:5px;padding:8px 10px;font-family:var(--mono);font-size:11px;overflow-x:auto;white-space:pre;margin-bottom:8px}
  .fi-fix{background:rgba(74,200,140,0.05);border:0.5px solid rgba(74,200,140,0.2);border-radius:5px;padding:8px 10px;font-size:12px;color:#7ddaad;line-height:1.5}
  .fi-fix-lbl{font-size:10px;font-family:var(--mono);color:var(--green);margin-bottom:4px;text-transform:uppercase;letter-spacing:0.06em}

  /* ── Empty / loading ── */
  .empty{text-align:center;padding:60px 20px;color:var(--text3)}
  .empty p{font-size:13px;margin-top:8px}
  .loading{text-align:center;padding:40px;color:var(--text3);font-family:var(--mono);font-size:12px}

  /* ── Utility ── */
  .flex{display:flex;align-items:center;gap:8px}
  .ml-auto{margin-left:auto}
</style>
</head>
<body>

<div class="layout">

  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="logo"><span>&#9635;</span> CodeSentinel</div>
    <div class="nav-section">Views</div>
    <div class="nav-item active" onclick="showView('dashboard')">
      <span class="nav-dot" style="background:var(--green)"></span> Dashboard
    </div>
    <div class="nav-item" onclick="showView('history')">
      <span class="nav-dot" style="background:var(--blue)"></span> Scan History
    </div>
    <div class="nav-section">Projects</div>
    <div class="target-list" id="target-list">
      <div style="padding:6px 20px;font-size:11px;color:var(--text3)">Loading...</div>
    </div>
    <div class="sidebar-footer">
      <p id="db-path">DB: loading...</p>
      <p id="db-stats" style="margin-top:4px"></p>
    </div>
  </aside>

  <!-- Main content -->
  <main class="main">

    <!-- Dashboard view -->
    <div id="view-dashboard">
      <div class="page-header">
        <div class="page-title">Security Overview</div>
        <div class="page-sub" id="overview-sub">Loading scan data...</div>
      </div>

      <div class="stats-row" id="stats-row">
        <div class="stat-card" onclick="filterBySev('CRITICAL')">
          <div class="stat-num" style="color:var(--red)" id="s-critical">&mdash;</div>
          <div class="stat-lbl">Critical (all time)</div>
        </div>
        <div class="stat-card" onclick="filterBySev('HIGH')">
          <div class="stat-num" style="color:var(--orange)" id="s-high">&mdash;</div>
          <div class="stat-lbl">High (all time)</div>
        </div>
        <div class="stat-card">
          <div class="stat-num" style="color:var(--text)" id="s-scans">&mdash;</div>
          <div class="stat-lbl">Total scans</div>
        </div>
        <div class="stat-card">
          <div class="stat-num" style="color:var(--blue)" id="s-projects">&mdash;</div>
          <div class="stat-lbl">Projects</div>
        </div>
        <div class="stat-card">
          <div class="stat-num" style="color:var(--text2);font-size:14px;line-height:1.8" id="s-last">&mdash;</div>
          <div class="stat-lbl">Last scan</div>
        </div>
      </div>

      <div class="chart-card">
        <div class="chart-header">
          <div class="chart-title">Findings trend</div>
          <div class="chart-controls">
            <button class="ctrl-btn active" onclick="setDays(7,this)">7d</button>
            <button class="ctrl-btn" onclick="setDays(30,this)">30d</button>
            <button class="ctrl-btn" onclick="setDays(90,this)">90d</button>
          </div>
        </div>
        <div class="legend" id="chart-legend"></div>
        <div style="position:relative;height:240px"><canvas id="trend-chart"></canvas></div>
      </div>

      <!-- Latest scans (last 8) -->
      <div class="table-card">
        <div class="table-header">
          <div class="table-title">Recent scans</div>
        </div>
        <table>
          <thead><tr>
            <th>Project</th><th>Date</th><th>Critical</th><th>High</th><th>Total</th><th>Duration</th><th></th>
          </tr></thead>
          <tbody id="recent-tbody"><tr><td colspan="7" class="loading">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>

    <!-- History view -->
    <div id="view-history" style="display:none">
      <div class="page-header">
        <div class="flex">
          <div>
            <div class="page-title">Scan History</div>
            <div class="page-sub" id="history-sub">All recorded scans</div>
          </div>
        </div>
      </div>

      <div class="table-card">
        <div class="table-header">
          <div class="table-title" id="history-count">All scans</div>
          <input class="search-input" type="text" placeholder="Filter by project path..." id="history-search" oninput="filterHistory()">
        </div>
        <table>
          <thead><tr>
            <th>ID</th><th>Project</th><th>Date</th><th>Critical</th><th>High</th><th>Med</th><th>Low</th><th>Files</th><th>Duration</th><th></th>
          </tr></thead>
          <tbody id="history-tbody"><tr><td colspan="10" class="loading">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>

  </main>
</div>

<!-- Findings drawer -->
<div class="drawer-overlay" id="overlay" onclick="closeDrawer()"></div>
<div class="drawer" id="drawer">
  <div class="drawer-head">
    <div>
      <div style="font-size:13px;font-weight:500" id="drawer-title">Scan findings</div>
      <div style="font-size:11px;color:var(--text3);font-family:var(--mono);margin-top:2px" id="drawer-meta"></div>
    </div>
    <button class="drawer-close" onclick="closeDrawer()">&#10005; Close</button>
  </div>
  <div class="drawer-body" id="drawer-body"></div>
</div>

<script>
const SEV_COL = {CRITICAL:'var(--red)',HIGH:'var(--orange)',MEDIUM:'var(--yellow)',LOW:'var(--blue)',INFO:'var(--gray)'};
const SEV_BG  = {CRITICAL:'var(--red-bg)',HIGH:'var(--orange-bg)',MEDIUM:'var(--yellow-bg)',LOW:'var(--blue-bg)',INFO:'var(--gray-bg)'};
const SEV_ORD = {CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1};

let allScans = [];
let trendChart = null;
let currentDays = 7;
let currentTarget = null;

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

function fmt(ts){
  if(!ts) return '\u2014';
  const d=new Date(ts.replace(' ','T'));
  return d.toLocaleDateString()+' '+d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
}

function shortPath(p){
  if(!p) return '\u2014';
  const parts=p.replace(/\\\\/g,'/').split('/');
  return parts.length>2?'\u2026/'+parts.slice(-2).join('/'):p;
}

// ── Load data ─────────────────────────────────────────────────────────────────

async function loadAll(){
  const [scans, stats, targets, trend] = await Promise.all([
    fetch('/api/scans').then(r=>r.json()),
    fetch('/api/stats').then(r=>r.json()),
    fetch('/api/targets').then(r=>r.json()),
    fetch(`/api/trends?days=${currentDays}`).then(r=>r.json()),
  ]);
  allScans = scans;
  renderStats(stats);
  renderTargets(targets);
  renderRecent(scans.slice(0,8));
  renderHistory(scans);
  renderTrend(trend);
  document.getElementById('db-stats').textContent=`${stats.total_scans||0} scans \u00b7 ${stats.total_findings||0} findings`;
}

async function loadTrend(){
  const url=currentTarget?`/api/trends?days=${currentDays}&target=${encodeURIComponent(currentTarget)}`:`/api/trends?days=${currentDays}`;
  const trend=await fetch(url).then(r=>r.json());
  renderTrend(trend);
}

// ── Render stats ──────────────────────────────────────────────────────────────

function renderStats(s){
  document.getElementById('s-critical').textContent=s.total_critical??'0';
  document.getElementById('s-high').textContent=(s.total_findings??0)-(s.total_critical??0);
  document.getElementById('s-scans').textContent=s.total_scans??'0';
  document.getElementById('s-projects').textContent=s.total_projects??'0';
  document.getElementById('s-last').textContent=s.last_scan?s.last_scan.slice(0,10):'\u2014';
  document.getElementById('overview-sub').textContent=`${s.total_scans||0} scans across ${s.total_projects||0} project(s)`;
  document.getElementById('db-path').textContent=`DB: ${s.db_path||'~/.codesentinel/history.db'}`;
}

// ── Render targets sidebar ─────────────────────────────────────────────────────

function renderTargets(targets){
  const el=document.getElementById('target-list');
  if(!targets.length){el.innerHTML='<div style="padding:6px 20px;font-size:11px;color:var(--text3)">No projects yet</div>';return;}
  el.innerHTML=targets.map(t=>`
    <div class="target-item${currentTarget===t?' active':''}" onclick="selectTarget('${esc(t)}')" title="${esc(t)}">${shortPath(t)}</div>
  `).join('');
}

function selectTarget(path){
  currentTarget=currentTarget===path?null:path;
  document.querySelectorAll('.target-item').forEach(el=>{
    el.classList.toggle('active',el.getAttribute('title')===currentTarget);
  });
  const filtered=currentTarget?allScans.filter(s=>s.target_path===currentTarget):allScans;
  renderRecent(filtered.slice(0,8));
  renderHistory(filtered);
  loadTrend();
}

// ── Render recent table ───────────────────────────────────────────────────────

function renderRecent(scans){
  const tbody=document.getElementById('recent-tbody');
  if(!scans.length){tbody.innerHTML='<tr><td colspan="7" class="empty"><p>No scans yet. Run <code>codesentinel scan .</code> to get started.</p></td></tr>';return;}
  tbody.innerHTML=scans.map(s=>`
    <tr>
      <td class="mono">${shortPath(s.target_path)}</td>
      <td class="mono" style="color:var(--text3)">${fmt(s.scanned_at)}</td>
      <td><span style="color:${s.critical>0?'var(--red)':'var(--text3)'};font-family:var(--mono);font-size:12px">${s.critical}</span></td>
      <td><span style="color:${s.high>0?'var(--orange)':'var(--text3)'};font-family:var(--mono);font-size:12px">${s.high}</span></td>
      <td class="mono">${s.total}</td>
      <td class="mono" style="color:var(--text3)">${s.scan_duration.toFixed(2)}s</td>
      <td><button class="btn-sm row-action" onclick="openDrawer(${s.id})">View findings</button></td>
    </tr>
  `).join('');
}

// ── Render history table ──────────────────────────────────────────────────────

function renderHistory(scans){
  document.getElementById('history-count').textContent=`${scans.length} scan${scans.length!==1?'s':''}`;
  document.getElementById('history-sub').textContent=`${scans.length} recorded scan${scans.length!==1?'s':''}`;
  const tbody=document.getElementById('history-tbody');
  if(!scans.length){tbody.innerHTML='<tr><td colspan="10" class="empty"><p>No scans match your filter.</p></td></tr>';return;}
  tbody.innerHTML=scans.map(s=>`
    <tr>
      <td class="mono" style="color:var(--text3)">#${s.id}</td>
      <td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(s.target_path)}">${shortPath(s.target_path)}</td>
      <td class="mono" style="color:var(--text3)">${fmt(s.scanned_at)}</td>
      <td style="color:${s.critical>0?'var(--red)':'var(--text3)'};font-family:var(--mono);font-size:12px">${s.critical}</td>
      <td style="color:${s.high>0?'var(--orange)':'var(--text3)'};font-family:var(--mono);font-size:12px">${s.high}</td>
      <td style="color:${s.medium>0?'var(--yellow)':'var(--text3)'};font-family:var(--mono);font-size:12px">${s.medium}</td>
      <td class="mono" style="color:var(--text3)">${s.low}</td>
      <td class="mono" style="color:var(--text3)">${s.files_scanned}</td>
      <td class="mono" style="color:var(--text3)">${s.scan_duration.toFixed(2)}s</td>
      <td style="display:flex;gap:6px">
        <button class="btn-sm row-action" onclick="openDrawer(${s.id})">View</button>
        <button class="btn-sm btn-del row-action" onclick="deleteScan(${s.id},this)">Del</button>
      </td>
    </tr>
  `).join('');
}

function filterHistory(){
  const q=document.getElementById('history-search').value.toLowerCase();
  const filtered=q?allScans.filter(s=>(s.target_path||'').toLowerCase().includes(q)):allScans;
  renderHistory(filtered);
}

// ── Trend chart ───────────────────────────────────────────────────────────────

function renderTrend(data){
  const labels=data.map(d=>d.date);
  const sev=['critical','high','medium','low'];
  const cols={critical:'#E24B4A',high:'#EF9F27',medium:'#D4B84A',low:'#4A9EE8'};

  document.getElementById('chart-legend').innerHTML=sev.map(s=>`
    <div class="legend-item" onclick="toggleSeries('${s}')">
      <span class="legend-dot" id="ldot-${s}" style="background:${cols[s]}"></span>
      ${s.charAt(0).toUpperCase()+s.slice(1)}
    </div>
  `).join('');

  if(trendChart) trendChart.destroy();
  const ctx=document.getElementById('trend-chart').getContext('2d');
  trendChart=new Chart(ctx,{
    type:'line',
    data:{
      labels,
      datasets:sev.map(s=>({
        label:s,
        data:data.map(d=>d[s]||0),
        borderColor:cols[s],
        backgroundColor:cols[s]+'22',
        borderWidth:1.5,
        pointRadius:3,
        tension:0.3,
        fill:false,
      }))
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{mode:'index',intersect:false}},
      scales:{
        x:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#58574f',font:{size:10}}},
        y:{beginAtZero:true,grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'#58574f',font:{size:10},stepSize:1}},
      }
    }
  });
}

function toggleSeries(name){
  if(!trendChart) return;
  const ds=trendChart.data.datasets.find(d=>d.label===name);
  if(!ds) return;
  ds.hidden=!ds.hidden;
  document.getElementById('ldot-'+name).style.opacity=ds.hidden?0.3:1;
  trendChart.update();
}

function setDays(d,btn){
  currentDays=d;
  document.querySelectorAll('.ctrl-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  loadTrend();
}

// ── Drawer (findings detail) ──────────────────────────────────────────────────

async function openDrawer(scanId){
  const data=await fetch(`/api/scan/${scanId}`).then(r=>r.json());
  document.getElementById('drawer-title').textContent=shortPath(data.target_path)+' \u2014 Scan #'+scanId;
  document.getElementById('drawer-meta').textContent=fmt(data.scanned_at)+' \u00b7 '+data.total+' findings \u00b7 '+data.files_scanned+' files';
  const findings=(data.findings||[]).sort((a,b)=>(SEV_ORD[b.severity]||0)-(SEV_ORD[a.severity]||0));
  document.getElementById('drawer-body').innerHTML=findings.length?findings.map((f,i)=>{
    const rel=(f.file||'').replace(/\\\\/g,'/').split('/').slice(-2).join('/');
    const cwe=f.cwe_id?`<span class="fi-tag"><a href="https://cwe.mitre.org/data/definitions/${f.cwe_id.replace('CWE-','')}.html" target="_blank">${esc(f.cwe_id)}</a></span>`:'';
    return `<div class="finding-item${f.severity==='CRITICAL'?' open':''}" id="df${i}">
      <div class="fi-header" onclick="document.getElementById('df${i}').classList.toggle('open')">
        <span class="sev-pill" style="color:${SEV_COL[f.severity]};background:${SEV_BG[f.severity]}">${f.severity}</span>
        <span class="fi-title">${esc(f.title)}</span>
        <span class="fi-loc">${esc(rel)}:${f.line}</span>
        <span class="fi-chev">&#9654;</span>
      </div>
      <div class="fi-body">
        <div class="fi-tags">${cwe}<span class="fi-tag">${esc(f.scanner)}</span><span class="fi-tag">line ${f.line}</span></div>
        ${f.description?`<p class="fi-desc">${esc(f.description)}</p>`:''}
        ${f.code_snippet?`<div class="fi-code">${esc(f.code_snippet)}</div>`:''}
        ${f.fix?`<div class="fi-fix"><div class="fi-fix-lbl">Recommended fix</div>${esc(f.fix)}</div>`:''}
      </div>
    </div>`;
  }).join(''):'<div class="empty"><p>No findings in this scan.</p></div>';
  document.getElementById('drawer').classList.add('open');
  document.getElementById('overlay').classList.add('open');
}

function closeDrawer(){
  document.getElementById('drawer').classList.remove('open');
  document.getElementById('overlay').classList.remove('open');
}

// ── Delete scan ───────────────────────────────────────────────────────────────

async function deleteScan(id, btn){
  if(!confirm(`Delete scan #${id}?`)) return;
  await fetch(`/api/scan/${id}`,{method:'DELETE'});
  allScans=allScans.filter(s=>s.id!==id);
  renderRecent(allScans.slice(0,8));
  renderHistory(allScans);
  loadTrend();
}

// ── View switching ────────────────────────────────────────────────────────────

function showView(v){
  document.getElementById('view-dashboard').style.display=v==='dashboard'?'block':'none';
  document.getElementById('view-history').style.display=v==='history'?'block':'none';
  document.querySelectorAll('.nav-item').forEach(el=>{
    el.classList.toggle('active',el.getAttribute('onclick').includes(v));
  });
}

function filterBySev(sev){
  showView('history');
  document.getElementById('history-search').value='';
  const filtered=allScans.filter(s=>s[sev.toLowerCase()]>0);
  renderHistory(filtered);
}

// ── Init ──────────────────────────────────────────────────────────────────────
loadAll();
</script>

</body>
</html>
"""


# ── HTTP Request Handler ──────────────────────────────────────────────────────

class DashboardHandler(BaseHTTPRequestHandler):
    """Routes API calls and serves the dashboard HTML."""

    store: ScanStore = None  # injected by server factory

    def log_message(self, fmt, *args):
        pass  # silence default Apache-style log spam

    def _json(self, data, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body: str, status: int = 200):
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"
        qs     = parse_qs(parsed.query)

        if path == "/":
            self._html(_DASHBOARD_HTML)

        elif path == "/api/scans":
            target = qs.get("target", [None])[0]
            self._json(self.store.list_scans(target_path=target))

        elif path == "/api/targets":
            self._json(self.store.list_targets())

        elif path == "/api/stats":
            s = self.store.stats()
            s["db_path"] = self.store.db_path
            self._json(s)

        elif path == "/api/trends":
            target = qs.get("target", [None])[0]
            days   = int(qs.get("days", ["30"])[0])
            self._json(self.store.trend_data(target_path=target, days=days))

        elif path.startswith("/api/scan/"):
            try:
                scan_id = int(path.split("/")[-1])
            except ValueError:
                self._json({"error": "invalid id"}, 400)
                return
            scan = self.store.get_scan(scan_id)
            if scan:
                self._json(scan)
            else:
                self._json({"error": "not found"}, 404)
        else:
            self._json({"error": "not found"}, 404)

    def do_DELETE(self):
        path = self.path.rstrip("/")
        if path.startswith("/api/scan/"):
            try:
                scan_id = int(path.split("/")[-1])
            except ValueError:
                self._json({"error": "invalid id"}, 400)
                return
            ok = self.store.delete_scan(scan_id)
            self._json({"deleted": ok})
        else:
            self._json({"error": "not found"}, 404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()


# ── Server factory ────────────────────────────────────────────────────────────

def make_handler(store: ScanStore):
    """Return a handler class with the store injected."""
    class BoundHandler(DashboardHandler):
        pass
    BoundHandler.store = store
    return BoundHandler


def start_server(
    port: int = 8080,
    db_path: Optional[str] = None,
    open_browser: bool = True,
) -> None:
    """Start the dashboard server. Blocks until Ctrl-C."""
    store = ScanStore(db_path)
    handler = make_handler(store)
    server  = HTTPServer(("127.0.0.1", port), handler)
    url     = f"http://localhost:{port}"

    print(f"\n  \033[92m\u2714\033[0m  CodeSentinel Dashboard  \u2192  \033[96m{url}\033[0m")
    print(f"  \033[2m   Database: {store.db_path}\033[0m")
    print(f"  \033[2m   Press Ctrl-C to stop\033[0m\n")

    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down dashboard server.\n")
        server.server_close()
