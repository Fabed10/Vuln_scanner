"""
Génération du rapport HTML 
Produit un fichier HTML autonome (CSS + JS inclus) dans results/.
"""

import os
import base64
from datetime import datetime
from reporting.rapport_pdf import generate_pdf_report

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")


def _severity_class(score: int) -> tuple[str, str]:
    """Retourne (label, classe CSS) selon le score de risque."""
    if score >= 70:
        return "CRITIQUE", "critical"
    elif score >= 40:
        return "ÉLEVÉ", "high"
    elif score >= 20:
        return "MODÉRÉ", "medium"
    else:
        return "FAIBLE", "low"


def _cve_severity_class(sev: str) -> str:
    s = (sev or "").upper()
    return {"CRITICAL": "sev-critical", "HIGH": "sev-high",
            "MEDIUM": "sev-medium", "LOW": "sev-low"}.get(s, "sev-unknown")


def _risk_score(cves: list[dict]) -> int:
    score = 0
    for c in cves:
        sev = (c.get("severity") or "").upper()
        score += {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}.get(sev, 0)
        if c.get("exploit"):   score += 8
        if c.get("cisa_kev"): score += 5
    return min(score, 100)


def _build_machine_card(rank: int, ip: str, ports: list[dict], score: int, os_info: dict = None) -> str:
    label, cls = _severity_class(score)
    os_info   = os_info or {}
    os_name   = os_info.get("os", "Inconnu")
    os_method = os_info.get("method", "N/A")
    if "windows" in os_name.lower():                              os_icon = "🪟"
    elif any(x in os_name.lower() for x in ["linux","unix","debian","ubuntu","kali"]): os_icon = "🐧"
    elif any(x in os_name.lower() for x in ["cisco","network","juniper"]): os_icon = "🔌"
    elif "android" in os_name.lower():                            os_icon = "📱"
    else:                                                          os_icon = "💻"
    total_cves = sum(len(p.get("cves", [])) for p in ports)
    exploits   = sum(1 for p in ports for c in p.get("cves", []) if c.get("exploit"))

    ports_html = ""
    for p in ports:
        cves_html = ""
        for cve in p.get("cves", []):
            sev_cls  = _cve_severity_class(cve.get("severity", ""))
            cvss_val = cve.get("cvss", "N/A")
            cvss_ver = cve.get("cvss_version", "")
            cvss_lbl = "CVSS : N/A"
            try:
                cvss_f   = float(cvss_val)
                cvss_lbl = f"CVSS {cvss_ver} : {cvss_f:.1f}" if cvss_ver and cvss_ver != "N/A" else f"CVSS : {cvss_f:.1f}"
            except (TypeError, ValueError):
                cvss_lbl = "CVSS : N/A"

            flags = ""
            if cve.get("exploit"):   flags += '<span class="badge badge-exploit">EXPLOIT</span>'
            if cve.get("cisa_kev"): flags += '<span class="badge badge-kev">CISA-KEV</span>'
            if not cve.get("patch"): flags += '<span class="badge badge-nopatch">NO-PATCH</span>'

            desc = (cve.get("description") or "")[:120]
            if len(cve.get("description") or "") > 120:
                desc += "…"

            # Vecteurs CVSS
            vec      = cve.get("vecteurs", {}) or {}
            vec_str  = vec.get("vector", "")
            vec_html = ""
            if vec and vec_str and vec_str != "N/A":
                def _vc(val):
                    v = str(val).upper()
                    if v in ("HIGH","COMPLETE","CHANGED"):   return "impact-high"
                    if v in ("LOW","PARTIAL"):               return "impact-low"
                    if v in ("NONE","UNCHANGED"):            return "impact-none"
                    return ""

                rows = [
                    ("Attack Vector",      vec.get("attackVector","N/A")),
                    ("Attack Complexity",  vec.get("attackComplexity","N/A")),
                    ("Privileges Req.",    vec.get("privilegesReq","N/A")),
                    ("User Interaction",   vec.get("userInteraction","N/A")),
                    ("Scope",              vec.get("scope","N/A")),
                    ("Confidentiality",    vec.get("confidentiality","N/A")),
                    ("Integrity",          vec.get("integrity","N/A")),
                    ("Availability",       vec.get("availability","N/A")),
                ]
                rows_html = "".join(
                    f'<div class="vec-row"><span class="vec-key">{k}</span>'
                    f'<span class="vec-val {_vc(v)}">{v}</span></div>'
                    for k, v in rows if v and v != "N/A"
                )
                imp_score  = vec.get("impactScore", "N/A")
                exp_score  = vec.get("exploitScore", "N/A")
                try:    imp_score = f"{float(imp_score):.1f}"
                except: pass
                try:    exp_score = f"{float(exp_score):.1f}"
                except: pass

                vec_html = f"""
                <div class="cve-vectors" id="vec-{cve.get('id','').replace('-','_')}">
                  <div class="vec-string">{vec_str}</div>
                  <div class="vec-scores">
                    <div class="vec-score-item">Impact Score : <span>{imp_score}</span></div>
                    <div class="vec-score-item">Exploitability : <span>{exp_score}</span></div>
                  </div>
                  <div class="vectors-grid">{rows_html}</div>
                </div>"""

            cves_html += f"""
            <div class="cve-item">
              <div class="cve-header">
                <span class="cve-id">{cve.get('id','N/A')}</span>
                <span class="cve-sev {sev_cls}">{cve.get('severity','?')}</span>
                <span class="cve-score">{cvss_lbl}</span>
                {flags}
                {"<button class=\"vec-toggle\" onclick=\"toggleVec(event,&apos;vec-" + cve.get('id','').replace('-','_') + "&apos;)\">vecteurs ▾</button>" if vec_html else ""}
              </div>
              <div class="cve-desc">{desc}</div>
              {vec_html}
            </div>"""

        cve_count = len(p.get("cves", []))
        cve_badge = f'<span class="port-cve-count">{cve_count} CVE{"s" if cve_count != 1 else ""}</span>' if cve_count else ''

        ports_html += f"""
        <div class="port-block">
          <div class="port-header">
            <span class="port-num">:{p['port']}</span>
            <span class="port-banner">{p.get('banner','') or 'Pas de bannière'}</span>
            {cve_badge}
          </div>
          {cves_html}
        </div>"""

    return f"""
    <div class="machine-card" data-score="{score}" data-priority="{rank}">
      <div class="card-header {cls}">
        <div class="card-rank">#{rank}</div>
        <div class="card-ip-wrap">
          <div class="card-ip">{ip}</div>
          <div class="card-os">{os_icon} <span class="os-badge">{os_name}</span><span class="os-method">({os_method})</span></div>
        </div>
        <div class="card-label">{label}</div>
        <div class="card-score-ring">
          <svg viewBox="0 0 36 36" class="ring-svg">
            <path class="ring-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/>
            <path class="ring-fill {cls}" stroke-dasharray="{score}, 100"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/>
          </svg>
          <div class="ring-text">{score}</div>
        </div>
      </div>
      <div class="card-stats">
        <div class="stat"><span class="stat-val">{len(ports)}</span><span class="stat-lbl">Ports ouverts</span></div>
        <div class="stat"><span class="stat-val">{total_cves}</span><span class="stat-lbl">CVEs</span></div>
        <div class="stat"><span class="stat-val {'stat-danger' if exploits else ''}">{exploits}</span><span class="stat-lbl">Exploits</span></div>
      </div>
      <div class="card-ports">
        {ports_html}
      </div>
    </div>"""


def generate_html_report(network: str, results: dict[str, list[dict]], os_map: dict = None,
                          scan_time: str = None) -> str:
    """
    results : { "192.168.1.5": [ {port, banner, cves:[...]}, ... ], ... }
    Retourne le chemin du fichier HTML généré.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    ts = scan_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fname = f"rapport_{network.replace('/', '_').replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    path  = os.path.join(RESULTS_DIR, fname)

    # Calculer scores et trier
    scored = []
    for ip, ports in results.items():
        all_cves = [c for p in ports for c in p.get("cves", [])]
        score = _risk_score(all_cves)
        scored.append((ip, ports, score))
    scored.sort(key=lambda x: x[2], reverse=True)

    # Stats globales
    total_machines = len(scored)
    total_ports    = sum(len(p) for _, p, _ in scored)
    total_cves     = sum(len(c) for _, ports, _ in scored for p in ports for c in [p.get("cves", [])])
    total_exploits = sum(1 for _, ports, _ in scored for p in ports for c in p.get("cves", []) if c.get("exploit"))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for _, _, score in scored:
        _, cls = _severity_class(score)
        counts[cls] = counts.get(cls, 0) + 1

    # Cartes machines
    cards_html = ""
    for rank, (ip, ports, score) in enumerate(scored, 1):
        cards_html += _build_machine_card(rank, ip, ports, score, (os_map or {}).get(ip))

    # ── Génération PDF embarqué (bouton téléchargement) ──────────────────────
    try:
        pdf_path  = generate_pdf_report(network, results, os_map or {}, ts)
        with open(pdf_path, "rb") as _f:
            pdf_b64 = base64.b64encode(_f.read()).decode("utf-8")
        pdf_fname = f"rapport_{network.replace('/', '_').replace('.', '_')}.pdf"
        pdf_btn = (
            f'<a class="pdf-btn" href="data:application/pdf;base64,{pdf_b64}" '
            f'download="{pdf_fname}">&#160;&#128196;&#160;T&eacute;l&eacute;charger le rapport PDF</a>'
        )
    except Exception as e:
        pdf_btn = f'<span class="pdf-btn-err">PDF indisponible : {e}</span>'

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport Vulnérabilités — {network}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:        #0a0c10;
    --bg2:       #0f1218;
    --bg3:       #161b24;
    --border:    #1e2530;
    --text:      #c9d1d9;
    --muted:     #6e7681;
    --accent:    #58a6ff;

    --critical:  #ff4444;
    --high:      #ff8800;
    --medium:    #f0c000;
    --low:       #3fb950;
    --unknown:   #484f58;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Syne', sans-serif;
    min-height: 100vh;
    overflow-x: hidden;
  }}

  /* ── Grid background ── */
  body::before {{
    content: '';
    position: fixed; inset: 0; z-index: 0;
    background-image:
      linear-gradient(rgba(88,166,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(88,166,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
  }}

  /* ── Header ── */
  header {{
    position: relative; z-index: 1;
    background: linear-gradient(135deg, #0d1117 0%, #161b24 100%);
    border-bottom: 1px solid var(--border);
    padding: 2rem 3rem;
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 1rem;
  }}
  .header-title {{
    display: flex; align-items: center; gap: 1rem;
  }}
  .header-icon {{
    width: 48px; height: 48px;
    background: linear-gradient(135deg, var(--accent), #1f6feb);
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.4rem;
  }}
  h1 {{
    font-size: 1.6rem; font-weight: 800;
    background: linear-gradient(90deg, var(--accent), #79c0ff);
    -webkit-background-clip: text; background-clip: text;
    -webkit-text-fill-color: transparent; color: transparent;
  }}
  .header-meta {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem; color: var(--muted);
    text-align: right; line-height: 1.8;
  }}
  .header-meta span {{ color: var(--accent); }}

  /* ── Main layout ── */
  main {{ position: relative; z-index: 1; padding: 2rem 3rem; max-width: 1600px; margin: 0 auto; }}

  /* ── KPI cards ── */
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem; margin-bottom: 2rem;
  }}
  .kpi {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    position: relative; overflow: hidden;
    animation: fadeUp 0.5s ease both;
  }}
  .kpi::before {{
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: var(--accent-kpi, var(--accent));
  }}
  .kpi-val {{
    font-size: 2.2rem; font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    color: var(--accent-kpi, var(--accent));
    line-height: 1;
  }}
  .kpi-lbl {{
    font-size: 0.72rem; color: var(--muted);
    text-transform: uppercase; letter-spacing: 0.1em;
    margin-top: 0.4rem;
  }}

  /* ── Priority legend ── */
  .priority-bar {{
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.25rem 1.5rem;
    display: flex; align-items: center; gap: 2rem;
    flex-wrap: wrap; margin-bottom: 2rem;
    animation: fadeUp 0.5s 0.1s ease both;
  }}
  .priority-bar h2 {{
    font-size: 0.8rem; text-transform: uppercase;
    letter-spacing: 0.12em; color: var(--muted); white-space: nowrap;
  }}
  .legend-items {{ display: flex; gap: 1.5rem; flex-wrap: wrap; }}
  .legend-item {{
    display: flex; align-items: center; gap: 0.5rem;
    font-size: 0.82rem; font-family: 'JetBrains Mono', monospace;
  }}
  .legend-dot {{
    width: 10px; height: 10px; border-radius: 50%;
  }}



  /* ── Filters ── */
  .filters {{
    display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1.5rem;
  }}
  .filter-btn {{
    background: var(--bg3); border: 1px solid var(--border);
    color: var(--muted); border-radius: 8px;
    padding: 0.4rem 1rem; font-family: 'Syne', sans-serif;
    font-size: 0.78rem; cursor: pointer; transition: all 0.2s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    background: var(--accent); border-color: var(--accent);
    color: #fff;
  }}

  /* ── Machine cards ── */
  .machines-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(480px, 1fr));
    gap: 1.25rem;
  }}
  .machine-card {{
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 14px; overflow: hidden;
    animation: fadeUp 0.4s ease both;
    transition: transform 0.2s, box-shadow 0.2s;
  }}
  .machine-card:hover {{
    transform: translateY(-2px);
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  }}

  .card-header {{
    display: grid;
    grid-template-columns: 40px 1fr auto auto;
    align-items: center; gap: 1rem;
    padding: 1rem 1.25rem;
    border-bottom: 1px solid var(--border);
  }}
  .card-header.critical {{ background: linear-gradient(135deg, rgba(255,68,68,0.15), rgba(255,68,68,0.05)); border-left: 3px solid var(--critical); }}
  .card-header.high     {{ background: linear-gradient(135deg, rgba(255,136,0,0.15), rgba(255,136,0,0.05)); border-left: 3px solid var(--high); }}
  .card-header.medium   {{ background: linear-gradient(135deg, rgba(240,192,0,0.15), rgba(240,192,0,0.05)); border-left: 3px solid var(--medium); }}
  .card-header.low      {{ background: linear-gradient(135deg, rgba(63,185,80,0.15), rgba(63,185,80,0.05)); border-left: 3px solid var(--low); }}

  .card-rank {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem; font-weight: 700;
    color: var(--muted); text-align: center;
  }}
  .card-ip {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 1rem; font-weight: 700; color: var(--text);
  }}
  .card-ip-wrap {{ display: flex; flex-direction: column; gap: 0.2rem; }}
  .card-os {{
    display: flex; align-items: center; gap: 0.4rem;
    font-family: 'JetBrains Mono', monospace; font-size: 0.62rem;
  }}
  .os-badge {{
    background: rgba(88,166,255,0.12); color: var(--accent);
    border: 1px solid rgba(88,166,255,0.25);
    padding: 0.1rem 0.45rem; border-radius: 4px;
    font-size: 0.60rem; font-weight: 700;
  }}
  .os-method {{ color: var(--muted); font-size: 0.58rem; }}
  .card-label {{
    font-size: 0.65rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.1em;
    padding: 0.2rem 0.6rem; border-radius: 6px;
  }}
  .critical .card-label {{ background: rgba(255,68,68,0.2);  color: var(--critical); }}
  .high     .card-label {{ background: rgba(255,136,0,0.2);  color: var(--high); }}
  .medium   .card-label {{ background: rgba(240,192,0,0.2);  color: var(--medium); }}
  .low      .card-label {{ background: rgba(63,185,80,0.2);  color: var(--low); }}

  /* Score ring */
  .card-score-ring {{ width: 40px; height: 40px; position: relative; }}
  .ring-svg {{ transform: rotate(-90deg); }}
  .ring-bg   {{ fill: none; stroke: var(--border); stroke-width: 3; }}
  .ring-fill {{ fill: none; stroke-width: 3; stroke-linecap: round; transition: stroke-dasharray 1s ease; }}
  .ring-fill.critical {{ stroke: var(--critical); }}
  .ring-fill.high     {{ stroke: var(--high); }}
  .ring-fill.medium   {{ stroke: var(--medium); }}
  .ring-fill.low      {{ stroke: var(--low); }}
  .ring-text {{
    position: absolute; inset: 0;
    display: flex; align-items: center; justify-content: center;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.6rem; font-weight: 700;
  }}

  /* Stats row */
  .card-stats {{
    display: flex; border-bottom: 1px solid var(--border);
  }}
  .stat {{
    flex: 1; padding: 0.75rem; text-align: center;
    border-right: 1px solid var(--border);
  }}
  .stat:last-child {{ border-right: none; }}
  .stat-val {{
    display: block; font-family: 'JetBrains Mono', monospace;
    font-size: 1.3rem; font-weight: 700; color: var(--accent);
  }}
  .stat-val.stat-danger {{ color: var(--critical); }}
  .stat-lbl {{
    display: block; font-size: 0.65rem;
    color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em;
  }}

  /* Ports */
  .card-ports {{ padding: 0.75rem 1.25rem; max-height: 400px; overflow-y: auto; }}
  .card-ports::-webkit-scrollbar {{ width: 4px; }}
  .card-ports::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 2px; }}

  .port-block {{ margin-bottom: 0.75rem; }}
  .port-header {{
    display: flex; align-items: center; gap: 0.75rem;
    padding: 0.4rem 0.6rem;
    background: var(--bg3); border-radius: 6px;
    margin-bottom: 0.4rem;
  }}
  .port-num {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem; font-weight: 700; color: var(--accent);
  }}
  .port-banner {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem; color: var(--text); flex: 1;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }}
  .port-cve-count {{
    font-size: 0.62rem; background: rgba(88,166,255,0.15);
    color: var(--accent); padding: 0.15rem 0.5rem;
    border-radius: 4px; white-space: nowrap;
  }}

  /* CVE items */
  .cve-item {{
    padding: 0.5rem 0.6rem;
    border-left: 2px solid var(--border);
    margin-left: 0.5rem; margin-bottom: 0.35rem;
  }}
  .cve-header {{ display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }}
  .cve-id {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem; font-weight: 700; color: var(--text);
  }}
  .cve-sev {{
    font-size: 0.6rem; font-weight: 700; padding: 0.15rem 0.45rem;
    border-radius: 4px; text-transform: uppercase;
  }}
  .sev-critical {{ background: rgba(255,68,68,0.2);  color: var(--critical); }}
  .sev-high     {{ background: rgba(255,136,0,0.2);  color: var(--high); }}
  .sev-medium   {{ background: rgba(240,192,0,0.2);  color: var(--medium); }}
  .sev-low      {{ background: rgba(63,185,80,0.2);  color: var(--low); }}
  .sev-unknown  {{ background: rgba(72,79,88,0.3);   color: var(--muted); }}

  .cve-score {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem; color: var(--muted);
  }}
  .badge {{
    font-size: 0.55rem; font-weight: 700;
    padding: 0.1rem 0.4rem; border-radius: 3px;
    text-transform: uppercase; letter-spacing: 0.05em;
  }}
  .badge-exploit  {{ background: rgba(255,68,68,0.25); color: var(--critical); }}
  .badge-kev      {{ background: rgba(255,68,68,0.15); color: #ff8888; }}
  .badge-nopatch  {{ background: rgba(240,192,0,0.2);  color: var(--medium); }}

  /* Vecteurs CVSS */
  .cve-vectors {{
    display: none;
    margin-top: 0.5rem;
    padding: 0.6rem 0.8rem;
    background: rgba(88,166,255,0.04);
    border: 1px solid rgba(88,166,255,0.1);
    border-radius: 6px;
  }}
  .vectors-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 0.3rem 1rem;
  }}
  .vec-row {{
    display: flex; justify-content: space-between; align-items: center;
    font-family: 'JetBrains Mono', monospace; font-size: 0.62rem;
  }}
  .vec-key {{ color: var(--muted); }}
  .vec-val {{ color: var(--text); font-weight: 600; }}
  .vec-val.impact-high   {{ color: var(--critical); }}
  .vec-val.impact-low    {{ color: var(--low); }}
  .vec-val.impact-none   {{ color: var(--muted); }}
  .vec-string {{
    font-family: 'JetBrains Mono', monospace; font-size: 0.6rem;
    color: var(--accent); margin-bottom: 0.4rem;
    word-break: break-all;
  }}
  .vec-scores {{
    display: flex; gap: 1rem; margin-bottom: 0.5rem;
    font-family: 'JetBrains Mono', monospace; font-size: 0.65rem;
  }}
  .vec-score-item {{ color: var(--muted); }}
  .vec-score-item span {{ color: var(--accent); font-weight: 700; }}
  .vec-toggle {{
    font-size: 0.58rem; color: var(--accent);
    cursor: pointer; margin-left: 0.5rem;
    background: rgba(88,166,255,0.1);
    border: none; border-radius: 3px;
    padding: 0.1rem 0.4rem; font-family: 'JetBrains Mono', monospace;
  }}
  .cve-desc {{
    font-size: 0.7rem; color: var(--muted);
    margin-top: 0.3rem; line-height: 1.5;
    font-family: 'JetBrains Mono', monospace;
  }}

  /* ── Bouton PDF ── */
  .pdf-btn {{
    display: inline-flex; align-items: center; gap: 0.5rem;
    background: linear-gradient(135deg, #e63946, #c1121f);
    color: #fff; text-decoration: none;
    padding: 0.55rem 1.25rem; border-radius: 8px;
    font-family: 'Syne', sans-serif; font-size: 0.82rem; font-weight: 700;
    letter-spacing: 0.04em;
    border: 1px solid rgba(255,255,255,0.15);
    box-shadow: 0 2px 8px rgba(198,18,31,0.35);
    transition: all 0.2s; white-space: nowrap;
  }}
  .pdf-btn:hover {{
    background: linear-gradient(135deg, #c1121f, #a4000f);
    box-shadow: 0 4px 16px rgba(198,18,31,0.5);
    transform: translateY(-1px);
  }}
  .pdf-btn-err {{
    font-size: 0.75rem; color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
  }}

  /* ── Footer ── */
  footer {{
    position: relative; z-index: 1;
    text-align: center; padding: 2rem;
    font-size: 0.72rem; color: var(--muted);
    border-top: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
  }}

  /* ── Animations ── */
  @keyframes fadeUp {{
    from {{ opacity: 0; transform: translateY(16px); }}
    to   {{ opacity: 1; transform: translateY(0); }}
  }}

  /* ── No results ── */
  .no-results {{
    text-align: center; padding: 3rem;
    color: var(--muted); font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
  }}
</style>
</head>
<body>

<header>
  <div class="header-title">
    <div class="header-icon"><img src="data:image/png;base64,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" width="48" height="48" style="border-radius:10px;"></div>
    <div>
      <h1>Vulnerability Scanner</h1>
      <div style="font-size:0.75rem;color:var(--muted);margin-top:0.2rem">Rapport d'analyse réseau</div>
    </div>
  </div>
  <div class="header-meta">
    Réseau cible : <span>{network}</span><br>
    Date du scan : <span>{ts}</span><br>
    Machines analysées : <span>{total_machines}</span>
  </div>
  <div style="display:flex;align-items:center;">
    {pdf_btn}
  </div>
</header>

<main>

  <!-- KPIs -->
  <div class="kpi-grid">
    <div class="kpi" style="--accent-kpi: var(--accent)">
      <div class="kpi-val">{total_machines}</div>
      <div class="kpi-lbl">Machines découvertes</div>
    </div>
    <div class="kpi" style="--accent-kpi: var(--accent)">
      <div class="kpi-val">{total_ports}</div>
      <div class="kpi-lbl">Ports ouverts</div>
    </div>
    <div class="kpi" style="--accent-kpi: var(--medium)">
      <div class="kpi-val">{total_cves}</div>
      <div class="kpi-lbl">CVEs identifiées</div>
    </div>
    <div class="kpi" style="--accent-kpi: var(--critical)">
      <div class="kpi-val">{total_exploits}</div>
      <div class="kpi-lbl">Exploits connus</div>
    </div>
    <div class="kpi" style="--accent-kpi: var(--critical)">
      <div class="kpi-val">{counts['critical']}</div>
      <div class="kpi-lbl">Machines CRITIQUES</div>
    </div>
    <div class="kpi" style="--accent-kpi: var(--high)">
      <div class="kpi-val">{counts['high']}</div>
      <div class="kpi-lbl">Machines ÉLEVÉES</div>
    </div>
    <div class="kpi" style="--accent-kpi: var(--medium)">
      <div class="kpi-val">{counts['medium']}</div>
      <div class="kpi-lbl">Machines MODÉRÉES</div>
    </div>
    <div class="kpi" style="--accent-kpi: var(--low)">
      <div class="kpi-val">{counts['low']}</div>
      <div class="kpi-lbl">Machines FAIBLES</div>
    </div>
  </div>

  <!-- Légende priorité -->
  <div class="priority-bar">
    <h2>Ordre d'intervention</h2>
    <div class="legend-items">
      <div class="legend-item"><div class="legend-dot" style="background:var(--critical)"></div> CRITIQUE  ≥ 70  — Intervention immédiate</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--high)"></div>     ÉLEVÉ     ≥ 40  — Sous 48h</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--medium)"></div>   MODÉRÉ    ≥ 20  — Planifier</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--low)"></div>      FAIBLE    &lt; 20  — Surveillance</div>
    </div>
  </div>



  <!-- Filtres -->
  <div class="filters">
    <button class="filter-btn active" onclick="filterCards('all')">Toutes</button>
    <button class="filter-btn" onclick="filterCards('critical')" style="--c:var(--critical)">🔴 Critique</button>
    <button class="filter-btn" onclick="filterCards('high')"     style="--c:var(--high)">🟠 Élevé</button>
    <button class="filter-btn" onclick="filterCards('medium')"   style="--c:var(--medium)">🟡 Modéré</button>
    <button class="filter-btn" onclick="filterCards('low')"      style="--c:var(--low)">🟢 Faible</button>
  </div>

  <!-- Machines -->
  <div class="machines-grid" id="machinesGrid">
    {cards_html if cards_html else '<div class="no-results">Aucune machine détectée.</div>'}
  </div>

</main>

<footer>
  Généré par Vulnerability Scanner — {ts} — Usage autorisé uniquement sur des réseaux dont vous avez l'autorisation.
</footer>

<script>


  // ── Toggle vecteurs ──
  function toggleVec(e, id) {{
    e.stopPropagation();
    const el  = document.getElementById(id);
    const btn = e.target;
    if (!el) return;
    const hidden = el.style.display === '' || el.style.display === 'none';
    el.style.display = hidden ? 'grid' : 'none';
    btn.textContent  = hidden ? 'vecteurs ▴' : 'vecteurs ▾';
  }}

  // ── Filtres ──
  function filterCards(cls) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('.machine-card').forEach(card => {{
      if (cls === 'all') {{ card.style.display = ''; return; }}
      const header = card.querySelector('.card-header');
      card.style.display = header.classList.contains(cls) ? '' : 'none';
    }});
  }}

  // ── Animations décalées ──
  document.querySelectorAll('.machine-card').forEach((card, i) => {{
    card.style.animationDelay = (i * 0.05) + 's';
  }});
</script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return path
