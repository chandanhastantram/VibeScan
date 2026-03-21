"""
VibeCodeReviewer — HTML Report Generator
Produces an interactive, self-contained single-file HTML report.
Add this to report.py and extend write_report() with fmt="html".
"""

import json
import os
from datetime import datetime
from .models import ScanResult, Severity


# ── Severity helpers ──────────────────────────────────────────────────────────

def _sev_color_hex(label: str) -> str:
    return {
        "CRITICAL": "#E24B4A",
        "HIGH":     "#EF9F27",
        "MEDIUM":   "#F0C040",
        "LOW":      "#378ADD",
        "INFO":     "#888780",
    }.get(label, "#888780")


def _sev_bg(label: str) -> str:
    return {
        "CRITICAL": "#FCEBEB",
        "HIGH":     "#FAEEDA",
        "MEDIUM":   "#FEFAE8",
        "LOW":      "#E6F1FB",
        "INFO":     "#F1EFE8",
    }.get(label, "#F1EFE8")


def generate_html(result: ScanResult) -> str:
    """Generate a self-contained interactive HTML report from a ScanResult."""

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Build findings JSON for JS ────────────────────────────────────────────
    findings_json = json.dumps([f.to_dict() for f in result.sorted_findings()])

    summary = {
        "critical": result.critical_count,
        "high":     result.high_count,
        "medium":   result.medium_count,
        "low":      result.low_count,
        "info":     result.info_count,
        "total":    result.total,
    }

    if result.critical_count > 0:
        verdict       = "REQUEST CHANGES"
        verdict_class = "verdict-critical"
        verdict_desc  = "Critical vulnerabilities must be resolved before deployment."
    elif result.high_count > 0:
        verdict       = "NEEDS REVIEW"
        verdict_class = "verdict-high"
        verdict_desc  = "High-severity issues should be addressed before production."
    elif result.total > 0:
        verdict       = "MINOR ISSUES"
        verdict_class = "verdict-medium"
        verdict_desc  = "Low-risk findings — review before merging."
    else:
        verdict       = "APPROVED"
        verdict_class = "verdict-clean"
        verdict_desc  = "No security vulnerabilities detected."

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VibeCodeReviewer Report — {os.path.basename(result.target_path)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root {{
    --bg:        #0e0e0f;
    --bg2:       #161618;
    --bg3:       #1e1e21;
    --border:    rgba(255,255,255,0.08);
    --border2:   rgba(255,255,255,0.14);
    --text:      #e8e6df;
    --text2:     #9e9c94;
    --text3:     #5e5d58;
    --red:       #E24B4A;
    --orange:    #EF9F27;
    --yellow:    #E8C840;
    --blue:      #4A9EE8;
    --gray:      #888780;
    --red-bg:    rgba(226,75,74,0.12);
    --orange-bg: rgba(239,159,39,0.12);
    --yellow-bg: rgba(232,200,64,0.10);
    --blue-bg:   rgba(74,158,232,0.12);
    --gray-bg:   rgba(136,135,128,0.10);
    --mono:      'IBM Plex Mono', monospace;
    --sans:      'IBM Plex Sans', sans-serif;
    --radius:    8px;
  }}

  html {{ font-family: var(--sans); background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.6; }}

  /* ── Layout ── */
  .page    {{ max-width: 1100px; margin: 0 auto; padding: 40px 24px 80px; }}
  .grid2   {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .grid3   {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }}

  /* ── Header ── */
  .header {{ margin-bottom: 40px; }}
  .logo   {{ font-family: var(--mono); font-size: 11px; color: var(--text3); letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 10px; }}
  h1      {{ font-size: 26px; font-weight: 600; color: var(--text); line-height: 1.2; margin-bottom: 6px; }}
  .meta   {{ font-size: 12px; color: var(--text2); font-family: var(--mono); }}
  .meta span {{ margin-right: 20px; }}

  /* ── Verdict ── */
  .verdict {{
    display: inline-flex; align-items: center; gap: 10px;
    padding: 10px 18px; border-radius: var(--radius);
    font-family: var(--mono); font-size: 13px; font-weight: 500;
    border: 1px solid; margin: 20px 0 32px;
  }}
  .verdict-critical {{ background: var(--red-bg);    border-color: var(--red);    color: var(--red);    }}
  .verdict-high     {{ background: var(--orange-bg); border-color: var(--orange); color: var(--orange); }}
  .verdict-medium   {{ background: var(--yellow-bg); border-color: var(--yellow); color: var(--yellow); }}
  .verdict-clean    {{ background: rgba(74,200,140,0.1); border-color: #4AC88C; color: #4AC88C; }}
  .verdict-dot      {{ width: 8px; height: 8px; border-radius: 50%; background: currentColor; }}

  /* ── Stat cards ── */
  .stat-card {{
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 16px 14px; text-align: center;
    transition: border-color 0.15s, transform 0.15s;
    cursor: pointer;
  }}
  .stat-card:hover {{ border-color: var(--border2); transform: translateY(-1px); }}
  .stat-card.active {{ border-color: var(--c, var(--border2)); }}
  .stat-num  {{ font-size: 28px; font-weight: 600; font-family: var(--mono); line-height: 1; margin-bottom: 4px; }}
  .stat-lbl  {{ font-size: 11px; color: var(--text3); text-transform: uppercase; letter-spacing: 0.08em; }}

  /* ── Toolbar ── */
  .toolbar {{ display: flex; align-items: center; gap: 12px; margin: 32px 0 16px; flex-wrap: wrap; }}
  .search  {{
    flex: 1; min-width: 200px; background: var(--bg2); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 8px 12px; font-family: var(--mono);
    font-size: 13px; color: var(--text); outline: none;
    transition: border-color 0.15s;
  }}
  .search:focus  {{ border-color: var(--border2); }}
  .search::placeholder {{ color: var(--text3); }}

  .filter-btn {{
    padding: 6px 14px; border-radius: 20px; font-size: 12px; font-family: var(--mono);
    border: 1px solid var(--border); background: transparent; color: var(--text2);
    cursor: pointer; transition: all 0.15s; white-space: nowrap;
  }}
  .filter-btn:hover  {{ border-color: var(--border2); color: var(--text); }}
  .filter-btn.active {{ border-color: var(--c); background: color-mix(in srgb, var(--c) 12%, transparent); color: var(--c); }}

  .sort-select {{
    background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 7px 10px; font-size: 12px; font-family: var(--mono); color: var(--text2);
    outline: none; cursor: pointer;
  }}
  .result-count {{ font-size: 12px; color: var(--text3); font-family: var(--mono); margin-left: auto; white-space: nowrap; }}

  /* ── Findings ── */
  .findings-list {{ display: flex; flex-direction: column; gap: 8px; }}

  .finding {{
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden;
    transition: border-color 0.15s;
  }}
  .finding:hover {{ border-color: var(--border2); }}
  .finding-header {{
    display: flex; align-items: center; gap: 12px; padding: 14px 16px;
    cursor: pointer; user-select: none;
  }}
  .sev-badge {{
    font-family: var(--mono); font-size: 10px; font-weight: 500;
    padding: 3px 8px; border-radius: 4px; letter-spacing: 0.06em;
    flex-shrink: 0;
  }}
  .finding-title  {{ font-weight: 500; font-size: 14px; flex: 1; }}
  .finding-loc    {{ font-family: var(--mono); font-size: 11px; color: var(--text3); white-space: nowrap; }}
  .chevron        {{ color: var(--text3); font-size: 12px; transition: transform 0.2s; margin-left: 4px; }}
  .finding.open .chevron {{ transform: rotate(90deg); }}

  .finding-body {{ display: none; padding: 0 16px 16px; border-top: 1px solid var(--border); }}
  .finding.open .finding-body {{ display: block; }}

  .info-row {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0 10px; }}
  .tag {{
    font-family: var(--mono); font-size: 11px; padding: 3px 8px;
    border-radius: 4px; background: var(--bg3); border: 1px solid var(--border);
    color: var(--text2);
  }}
  .tag a {{ color: inherit; text-decoration: none; }}
  .tag a:hover {{ color: var(--text); }}

  .desc {{ font-size: 13px; color: var(--text2); margin-bottom: 12px; line-height: 1.6; }}

  .code-block {{
    background: var(--bg3); border: 1px solid var(--border); border-radius: 6px;
    padding: 12px 14px; font-family: var(--mono); font-size: 12px;
    color: var(--text); overflow-x: auto; margin-bottom: 12px;
    white-space: pre;
  }}
  .fix-block {{
    background: rgba(74,200,140,0.06); border: 1px solid rgba(74,200,140,0.2);
    border-radius: 6px; padding: 12px 14px; font-size: 13px;
    color: #7ddaad; line-height: 1.5;
  }}
  .fix-label {{ font-size: 11px; font-family: var(--mono); color: #4AC88C; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.06em; }}

  /* ── Empty state ── */
  .empty {{ text-align: center; padding: 60px 20px; color: var(--text3); }}
  .empty .icon {{ font-size: 32px; margin-bottom: 12px; }}
  .empty p {{ font-size: 13px; }}

  /* ── Footer ── */
  .footer {{ margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }}
  .footer-text {{ font-size: 11px; color: var(--text3); font-family: var(--mono); }}

  /* ── Section label ── */
  .section-label {{ font-size: 11px; font-family: var(--mono); color: var(--text3); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 12px; }}

  /* ── Scan info bar ── */
  .info-bar {{
    background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 14px 18px; display: flex; gap: 32px; flex-wrap: wrap; margin-bottom: 24px;
  }}
  .info-item {{ display: flex; flex-direction: column; gap: 2px; }}
  .info-item-lbl {{ font-size: 10px; font-family: var(--mono); color: var(--text3); text-transform: uppercase; letter-spacing: 0.08em; }}
  .info-item-val {{ font-size: 14px; font-family: var(--mono); color: var(--text); font-weight: 500; }}
</style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div class="header">
    <div class="logo">🛡 VibeCodeReviewer • Security Report</div>
    <h1>{os.path.basename(result.target_path)}</h1>
    <div class="meta">
      <span>Generated: {now}</span>
      <span>Target: {result.target_path}</span>
    </div>
    <div class="verdict {verdict_class}">
      <span class="verdict-dot"></span>
      {verdict} — {verdict_desc}
    </div>
  </div>

  <!-- Scan info -->
  <div class="info-bar">
    <div class="info-item">
      <span class="info-item-lbl">Files scanned</span>
      <span class="info-item-val">{result.files_scanned}</span>
    </div>
    <div class="info-item">
      <span class="info-item-lbl">Files skipped</span>
      <span class="info-item-val">{result.files_skipped}</span>
    </div>
    <div class="info-item">
      <span class="info-item-lbl">Scan duration</span>
      <span class="info-item-val">{result.scan_duration:.2f}s</span>
    </div>
    <div class="info-item">
      <span class="info-item-lbl">Total findings</span>
      <span class="info-item-val">{result.total}</span>
    </div>
  </div>

  <!-- Summary cards -->
  <div class="section-label">Severity breakdown</div>
  <div class="grid3" id="stat-cards">
    <div class="stat-card" style="--c: var(--red)"    data-filter="CRITICAL" onclick="toggleFilter('CRITICAL', this)">
      <div class="stat-num" style="color:var(--red)">{result.critical_count}</div>
      <div class="stat-lbl">Critical</div>
    </div>
    <div class="stat-card" style="--c: var(--orange)" data-filter="HIGH"     onclick="toggleFilter('HIGH', this)">
      <div class="stat-num" style="color:var(--orange)">{result.high_count}</div>
      <div class="stat-lbl">High</div>
    </div>
    <div class="stat-card" style="--c: var(--yellow)" data-filter="MEDIUM"   onclick="toggleFilter('MEDIUM', this)">
      <div class="stat-num" style="color:var(--yellow)">{result.medium_count}</div>
      <div class="stat-lbl">Medium</div>
    </div>
    <div class="stat-card" style="--c: var(--blue)"   data-filter="LOW"      onclick="toggleFilter('LOW', this)">
      <div class="stat-num" style="color:var(--blue)">{result.low_count}</div>
      <div class="stat-lbl">Low</div>
    </div>
    <div class="stat-card" style="--c: var(--gray)"   data-filter="INFO"     onclick="toggleFilter('INFO', this)">
      <div class="stat-num" style="color:var(--gray)">{result.info_count}</div>
      <div class="stat-lbl">Info</div>
    </div>
  </div>

  <!-- Toolbar -->
  <div class="toolbar">
    <input class="search" id="search" type="text" placeholder="Search findings, files, CWEs..." oninput="applyFilters()">
    <div style="display:flex;gap:8px;flex-wrap:wrap" id="sev-pills">
      <button class="filter-btn active" style="--c:var(--text)" data-filter="ALL" onclick="setFilter('ALL',this)">All</button>
      <button class="filter-btn" style="--c:var(--red)"    data-filter="CRITICAL" onclick="setFilter('CRITICAL',this)">Critical</button>
      <button class="filter-btn" style="--c:var(--orange)" data-filter="HIGH"     onclick="setFilter('HIGH',this)">High</button>
      <button class="filter-btn" style="--c:var(--yellow)" data-filter="MEDIUM"   onclick="setFilter('MEDIUM',this)">Medium</button>
      <button class="filter-btn" style="--c:var(--blue)"   data-filter="LOW"      onclick="setFilter('LOW',this)">Low</button>
      <button class="filter-btn" style="--c:var(--gray)"   data-filter="INFO"     onclick="setFilter('INFO',this)">Info</button>
    </div>
    <select class="sort-select" id="sort-select" onchange="applyFilters()">
      <option value="severity">Sort: Severity</option>
      <option value="file">Sort: File</option>
      <option value="scanner">Sort: Scanner</option>
    </select>
    <span class="result-count" id="result-count"></span>
  </div>

  <!-- Findings -->
  <div class="findings-list" id="findings-list"></div>

  <!-- Empty state -->
  <div class="empty" id="empty-state" style="display:none">
    <div class="icon">🔍</div>
    <p>No findings match your current filters.</p>
  </div>

  <!-- Footer -->
  <div class="footer">
    <span class="footer-text">VibeCodeReviewer v1.0.0 • {now}</span>
    <span class="footer-text">
      <a href="https://cwe.mitre.org" target="_blank" style="color:var(--text3);text-decoration:none">CWE Reference</a>
    </span>
  </div>

</div>

<script>
const SEV_COLORS = {{
  CRITICAL: 'var(--red)',   HIGH:   'var(--orange)',
  MEDIUM:   'var(--yellow)',LOW:    'var(--blue)',
  INFO:     'var(--gray)',
}};
const SEV_BG = {{
  CRITICAL: 'var(--red-bg)',   HIGH:   'var(--orange-bg)',
  MEDIUM:   'var(--yellow-bg)',LOW:    'var(--blue-bg)',
  INFO:     'var(--gray-bg)',
}};
const SEV_ORDER = {{ CRITICAL:5, HIGH:4, MEDIUM:3, LOW:2, INFO:1 }};

const ALL_FINDINGS = {findings_json};

let activeFilter = 'ALL';

function toggleFilter(sev, card) {{
  if (activeFilter === sev) {{
    activeFilter = 'ALL';
    card.classList.remove('active');
    document.querySelectorAll('#sev-pills .filter-btn').forEach(b => {{
      b.classList.toggle('active', b.dataset.filter === 'ALL');
    }});
  }} else {{
    activeFilter = sev;
    document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('active'));
    card.classList.add('active');
    document.querySelectorAll('#sev-pills .filter-btn').forEach(b => {{
      b.classList.toggle('active', b.dataset.filter === sev);
    }});
  }}
  applyFilters();
}}

function setFilter(sev, btn) {{
  activeFilter = sev;
  document.querySelectorAll('#sev-pills .filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.stat-card').forEach(c => {{
    c.classList.toggle('active', c.dataset.filter === sev);
  }});
  applyFilters();
}}

function applyFilters() {{
  const q     = document.getElementById('search').value.toLowerCase();
  const sort  = document.getElementById('sort-select').value;

  let filtered = ALL_FINDINGS.filter(f => {{
    const matchSev  = activeFilter === 'ALL' || f.severity === activeFilter;
    const matchText = !q || [f.title, f.file, f.description, f.cwe_id, f.scanner]
                              .filter(Boolean).some(s => s.toLowerCase().includes(q));
    return matchSev && matchText;
  }});

  filtered.sort((a, b) => {{
    if (sort === 'severity') return (SEV_ORDER[b.severity]||0) - (SEV_ORDER[a.severity]||0);
    if (sort === 'file')     return (a.file||'').localeCompare(b.file||'');
    if (sort === 'scanner')  return (a.scanner||'').localeCompare(b.scanner||'');
    return 0;
  }});

  renderFindings(filtered);
  document.getElementById('result-count').textContent =
    filtered.length === ALL_FINDINGS.length
      ? `${{ALL_FINDINGS.length}} findings`
      : `${{filtered.length}} / ${{ALL_FINDINGS.length}} findings`;
}}

function esc(s) {{
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

function renderFindings(findings) {{
  const list = document.getElementById('findings-list');
  const empty = document.getElementById('empty-state');

  if (!findings.length) {{
    list.innerHTML = '';
    empty.style.display = 'block';
    return;
  }}
  empty.style.display = 'none';

  list.innerHTML = findings.map((f, i) => {{
    const col  = SEV_COLORS[f.severity] || 'var(--gray)';
    const bg   = SEV_BG[f.severity]    || 'var(--gray-bg)';
    const rel  = f.file.replace(/\\\\/g, '/').split('/').slice(-2).join('/');
    const cweLink = f.cwe_id
      ? `<span class="tag"><a href="https://cwe.mitre.org/data/definitions/${{f.cwe_id.replace('CWE-','')}}.html" target="_blank">${{esc(f.cwe_id)}}</a></span>`
      : '';

    return `
    <div class="finding" id="finding-${{i}}">
      <div class="finding-header" onclick="toggleFinding(${{i}})">
        <span class="sev-badge" style="color:${{col}};background:${{bg}}">${{esc(f.severity)}}</span>
        <span class="finding-title">${{esc(f.title)}}</span>
        <span class="finding-loc">${{esc(rel)}}:${{f.line}}</span>
        <span class="chevron">▶</span>
      </div>
      <div class="finding-body">
        <div class="info-row">
          ${{cweLink}}
          <span class="tag">${{esc(f.scanner)}}</span>
          <span class="tag">line ${{f.line}}</span>
          ${{f.file ? `<span class="tag" title="${{esc(f.file)}}">${{esc(rel)}}</span>` : ''}}
        </div>
        ${{f.description ? `<p class="desc">${{esc(f.description)}}</p>` : ''}}
        ${{f.code_snippet ? `<div class="code-block">${{esc(f.code_snippet)}}</div>` : ''}}
        ${{f.fix ? `
          <div class="fix-block">
            <div class="fix-label">Recommended fix</div>
            ${{esc(f.fix)}}
          </div>` : ''}}
      </div>
    </div>`;
  }}).join('');
}}

function toggleFinding(i) {{
  document.getElementById('finding-' + i).classList.toggle('open');
}}

// Init
applyFilters();

// Auto-expand critical findings
ALL_FINDINGS.forEach((f, i) => {{
  if (f.severity === 'CRITICAL') {{
    setTimeout(() => {{
      const el = document.getElementById('finding-' + i);
      if (el) el.classList.add('open');
    }}, 100);
  }}
}});
</script>
</body>
</html>"""

    return html


def write_html(result: ScanResult, output_path: str) -> None:
    """Write the interactive HTML report to a file."""
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(generate_html(result))