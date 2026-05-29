"""
Génération du rapport PDF — Vulnerability Scanner
Design : en-tête avec logo/outil, titre, barre de criticité,
         description, résumé exécutif, tableau CVEs par machine.
"""

import os
import base64
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


# ── Palette couleurs (identique au HTML) ──────────────────────────────────────
C_CRITICAL = colors.HexColor("#ff4444")
C_HIGH     = colors.HexColor("#ff8800")
C_MEDIUM   = colors.HexColor("#f0c000")
C_LOW      = colors.HexColor("#3fb950")
C_BLUE     = colors.HexColor("#1a3a6b")
C_HEADER   = colors.HexColor("#1e2530")
C_TEXT     = colors.HexColor("#1a1a2e")
C_MUTED    = colors.HexColor("#6e7681")
C_WHITE    = colors.white
C_LIGHT    = colors.HexColor("#f4f6fa")
C_BORDER   = colors.HexColor("#c0c8d8")

W, H = A4   # 595.27 x 841.89 pt


# ── Styles ────────────────────────────────────────────────────────────────────
def _styles():
    return {
        "title": ParagraphStyle(
            "title", fontName="Helvetica-Bold", fontSize=22,
            textColor=C_BLUE, alignment=TA_CENTER, spaceAfter=8,
        ),
        "section": ParagraphStyle(
            "section", fontName="Helvetica-Bold", fontSize=13,
            textColor=C_BLUE, spaceBefore=14, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body", fontName="Helvetica", fontSize=9,
            textColor=C_TEXT, spaceAfter=4, leading=14,
        ),
        "body_bold": ParagraphStyle(
            "body_bold", fontName="Helvetica-Bold", fontSize=9,
            textColor=C_TEXT, spaceAfter=4, leading=14,
        ),
        "small": ParagraphStyle(
            "small", fontName="Helvetica", fontSize=8,
            textColor=C_MUTED, spaceAfter=2,
        ),
        "th": ParagraphStyle(
            "th", fontName="Helvetica-Bold", fontSize=8,
            textColor=C_WHITE, alignment=TA_CENTER,
        ),
        "td": ParagraphStyle(
            "td", fontName="Helvetica", fontSize=8,
            textColor=C_TEXT, alignment=TA_CENTER,
        ),
        "td_left": ParagraphStyle(
            "td_left", fontName="Helvetica", fontSize=8,
            textColor=C_TEXT, alignment=TA_LEFT,
        ),
        "meta": ParagraphStyle(
            "meta", fontName="Helvetica", fontSize=9,
            textColor=C_TEXT, spaceAfter=3, leading=14,
        ),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────
def _sev_color(sev: str):
    s = (sev or "").upper()
    return {
        "CRITICAL": C_CRITICAL,
        "HIGH":     C_HIGH,
        "MEDIUM":   C_MEDIUM,
        "LOW":      C_LOW,
    }.get(s, C_MUTED)


def _score_color(score: int):
    if score >= 70: return C_CRITICAL
    if score >= 40: return C_HIGH
    if score >= 20: return C_MEDIUM
    return C_LOW


def _score_label(score: int):
    if score >= 70: return "CRITIQUE"
    if score >= 40: return "ÉLEVÉ"
    if score >= 20: return "MODÉRÉ"
    return "FAIBLE"


def _risk_score(cves):
    score = 0
    for c in cves:
        sev = (c.get("severity") or "").upper()
        score += {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}.get(sev, 0)
        if c.get("exploit"):   score += 8
        if c.get("cisa_kev"): score += 5
    return min(score, 100)


# ── Blocs réutilisables ───────────────────────────────────────────────────────
def _header_table(network: str, ts: str, st):
    """En-tête : logo | nom outil  (identique à la photo)"""
    logo_cell = Paragraph("<b>VULNERABILITY<br/>SCANNER</b>", ParagraphStyle(
        "logo", fontName="Helvetica-Bold", fontSize=11,
        textColor=C_BLUE, alignment=TA_CENTER,
    ))
    tool_cell = Paragraph(
        "<b>NOM DE L'OUTIL</b><br/>(Vulnerability Scanner — NVD/CVE)",
        ParagraphStyle("tool", fontName="Helvetica", fontSize=9,
                       textColor=C_TEXT, alignment=TA_CENTER)
    )
    tbl = Table([[logo_cell, tool_cell]], colWidths=[7.5*cm, 9.5*cm])
    tbl.setStyle(TableStyle([
        ("BOX",         (0, 0), (-1, -1), 1.2, C_HEADER),
        ("INNERGRID",   (0, 0), (-1, -1), 1.2, C_HEADER),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_LIGHT]),
        ("TOPPADDING",  (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return tbl


def _severity_bar(st):
    """Barre colorée FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE"""
    cells = [
        Paragraph("<b>FAIBLE</b>",   ParagraphStyle("sb", fontName="Helvetica-Bold", fontSize=11, textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph("<b>MOYEN</b>",    ParagraphStyle("sb", fontName="Helvetica-Bold", fontSize=11, textColor=C_TEXT,  alignment=TA_CENTER)),
        Paragraph("<b>ÉLEVÉ</b>",    ParagraphStyle("sb", fontName="Helvetica-Bold", fontSize=11, textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph("<b>CRITIQUE</b>", ParagraphStyle("sb", fontName="Helvetica-Bold", fontSize=11, textColor=C_WHITE, alignment=TA_CENTER)),
    ]
    tbl = Table([cells], colWidths=[4.25*cm]*4)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), C_LOW),
        ("BACKGROUND",    (1, 0), (1, 0), C_MEDIUM),
        ("BACKGROUND",    (2, 0), (2, 0), C_HIGH),
        ("BACKGROUND",    (3, 0), (3, 0), C_CRITICAL),
        ("TOPPADDING",    (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return tbl


def _cve_table(all_cves_rows: list, st):
    """Tableau global CVE : CVE | Description | IP/Machine | CVSS | Criticité"""
    header = [
        Paragraph("CVE",          st["th"]),
        Paragraph("Description",  st["th"]),
        Paragraph("IP / Machine", st["th"]),
        Paragraph("CVSS",         st["th"]),
        Paragraph("Criticité",    st["th"]),
    ]
    rows = [header]
    row_colors = []

    for i, row in enumerate(all_cves_rows):
        cve_id, desc, ip, cvss, sev = row
        sev_color = _sev_color(sev)
        sev_label = (sev or "?").upper()

        # Cellule criticité colorée
        sev_cell = Paragraph(
            f"<b>{sev_label}</b>",
            ParagraphStyle("sevcell", fontName="Helvetica-Bold", fontSize=8,
                           textColor=C_WHITE, alignment=TA_CENTER)
        )

        rows.append([
            Paragraph(cve_id or "N/A",  st["td"]),
            Paragraph((desc or "")[:60] + ("…" if len(desc or "") > 60 else ""), st["td_left"]),
            Paragraph(ip or "",          st["td"]),
            Paragraph(str(cvss) if cvss else "N/A", st["td"]),
            sev_cell,
        ])
        row_colors.append(sev_color)

    col_w = [3.2*cm, 6.8*cm, 3.2*cm, 1.8*cm, 2.2*cm]
    tbl = Table(rows, colWidths=col_w, repeatRows=1)

    style = [
        # En-tête
        ("BACKGROUND",    (0, 0), (-1, 0), C_BLUE),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("ALIGN",         (0, 0), (-1, 0), "CENTER"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 7),
        ("TOPPADDING",    (0, 0), (-1, 0), 7),
        # Corps
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 1), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("BOX",           (0, 0), (-1, -1), 1.0, C_HEADER),
    ]

    # Colorier la colonne criticité ligne par ligne
    for i, sev_color in enumerate(row_colors):
        style.append(("BACKGROUND", (4, i+1), (4, i+1), sev_color))

    tbl.setStyle(TableStyle(style))
    return tbl


def _machine_summary_table(scored: list, st):
    """Tableau résumé par machine : IP | OS | Score | Criticité | Ports | CVEs | Exploits"""
    header = [
        Paragraph("IP / Machine", st["th"]),
        Paragraph("Score",        st["th"]),
        Paragraph("Criticité",    st["th"]),
        Paragraph("Ports ouverts",st["th"]),
        Paragraph("CVEs",         st["th"]),
        Paragraph("Exploits",     st["th"]),
    ]
    rows = [header]
    for ip, ports, score in scored:
        all_cves = [c for p in ports for c in p.get("cves", [])]
        exploits = sum(1 for c in all_cves if c.get("exploit"))
        label = _score_label(score)
        sc = _score_color(score)
        sev_cell = Paragraph(f"<b>{label}</b>",
                             ParagraphStyle("sc2", fontName="Helvetica-Bold",
                                            fontSize=8, textColor=C_WHITE,
                                            alignment=TA_CENTER))
        rows.append([
            Paragraph(ip,            st["td"]),
            Paragraph(str(score),    st["td"]),
            sev_cell,
            Paragraph(str(len(ports)),st["td"]),
            Paragraph(str(len(all_cves)), st["td"]),
            Paragraph(str(exploits), st["td"]),
        ])

    col_w = [4*cm, 2*cm, 3.2*cm, 3*cm, 2.2*cm, 2.8*cm]
    tbl = Table(rows, colWidths=col_w, repeatRows=1)

    style_cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0), C_BLUE),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN",         (0, 0), (-1, 0), "CENTER"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 7),
        ("TOPPADDING",    (0, 0), (-1, 0), 7),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 1), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("BOX",           (0, 0), (-1, -1), 1.0, C_HEADER),
    ]
    for i, (_, _, score) in enumerate(scored):
        style_cmds.append(("BACKGROUND", (2, i+1), (2, i+1), _score_color(score)))
    tbl.setStyle(TableStyle(style_cmds))
    return tbl


# ── Générateur principal ──────────────────────────────────────────────────────
def generate_pdf_report(network: str, results: dict, os_map: dict = None,
                        scan_time: str = None, output_path: str = None) -> str:
    """
    Génère le rapport PDF.
    Retourne le chemin du fichier PDF créé.
    """
    os_map = os_map or {}
    ts = scan_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Calcul scores
    scored = []
    for ip, ports in results.items():
        all_cves = [c for p in ports for c in p.get("cves", [])]
        score = _risk_score(all_cves)
        scored.append((ip, ports, score))
    scored.sort(key=lambda x: x[2], reverse=True)

    # Chemin de sortie
    if output_path is None:
        results_dir = os.path.join(os.path.dirname(__file__), "..", "results")
        os.makedirs(results_dir, exist_ok=True)
        fname = f"rapport_{network.replace('/', '_').replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        output_path = os.path.join(results_dir, fname)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm,  bottomMargin=2*cm,
        title=f"Rapport Vulnérabilités — {network}",
        author="Vulnerability Scanner",
    )

    st = _styles()
    story = []

    # ── 1. En-tête logo/outil ─────────────────────────────────────────────────
    story.append(_header_table(network, ts, st))
    story.append(Spacer(1, 0.5*cm))

    # ── Date ─────────────────────────────────────────────────────────────────
    story.append(Paragraph(f"<b>Date du scan :</b> {ts}", st["meta"]))
    story.append(Spacer(1, 0.3*cm))

    # ── Titre principal ───────────────────────────────────────────────────────
    story.append(Paragraph("SCAN DE VULNÉRABILITÉ", st["title"]))
    story.append(Spacer(1, 0.4*cm))

    # ── Barre de criticité ────────────────────────────────────────────────────
    story.append(_severity_bar(st))
    story.append(Spacer(1, 0.6*cm))

    # ── Section 1 : Description ───────────────────────────────────────────────
    story.append(Paragraph("1. Description", st["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=6))

    type_scan = "Hôte unique" if "/" not in network and "-" not in network else "Réseau CIDR"
    story.append(Paragraph(f"<b>Type de scan :</b> {type_scan}", st["body"]))
    story.append(Paragraph(f"<b>IP de scan :</b> {network}", st["body"]))
    story.append(Paragraph(
        "<b>Responsable sécurité :</b> ..........................................",
        st["body"]
    ))
    story.append(Spacer(1, 0.4*cm))

    # ── Section 2 : Résumé Exécutif ───────────────────────────────────────────
    total_machines = len(scored)
    total_ports    = sum(len(p) for _, p, _ in scored)
    total_cves     = sum(len(c) for _, ports, _ in scored
                         for p in ports for c in [p.get("cves", [])])
    total_exploits = sum(1 for _, ports, _ in scored
                         for p in ports for c in p.get("cves", []) if c.get("exploit"))
    counts = {"CRITIQUE": 0, "ÉLEVÉ": 0, "MODÉRÉ": 0, "FAIBLE": 0}
    for _, _, score in scored:
        counts[_score_label(score)] += 1

    story.append(Paragraph("2. Résumé Exécutif", st["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=6))
    story.append(Paragraph(
        "Ce rapport présente les résultats du scan de vulnérabilité effectué sur les "
        "équipements ciblés. Les vulnérabilités détectées sont classées selon leur "
        "niveau de criticité.", st["body"]
    ))
    story.append(Spacer(1, 0.25*cm))

    # Mini tableau de stats
    stats_data = [
        [Paragraph("<b>Machines</b>", st["th"]),
         Paragraph("<b>Ports ouverts</b>", st["th"]),
         Paragraph("<b>CVEs</b>", st["th"]),
         Paragraph("<b>Exploits</b>", st["th"]),
         Paragraph("<b>Critique</b>", st["th"]),
         Paragraph("<b>Élevé</b>", st["th"])],
        [Paragraph(str(total_machines), st["td"]),
         Paragraph(str(total_ports), st["td"]),
         Paragraph(str(total_cves), st["td"]),
         Paragraph(str(total_exploits), st["td"]),
         Paragraph(str(counts["CRITIQUE"]), st["td"]),
         Paragraph(str(counts["ÉLEVÉ"]), st["td"])],
    ]
    stats_tbl = Table(stats_data, colWidths=[2.83*cm]*6)
    stats_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_BLUE),
        ("BACKGROUND",    (0, 1), (-1, 1), C_LIGHT),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("BOX",           (0, 0), (-1, -1), 1.0, C_HEADER),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE",      (0, 1), (-1, 1), 11),
        ("FONTNAME",      (0, 1), (-1, 1), "Helvetica-Bold"),
        ("TEXTCOLOR",     (4, 1), (4, 1), C_CRITICAL),
        ("TEXTCOLOR",     (5, 1), (5, 1), C_HIGH),
    ]))
    story.append(stats_tbl)
    story.append(Spacer(1, 0.5*cm))

    # ── Section 3 : Résumé par machine ───────────────────────────────────────
    story.append(Paragraph("3. Résumé par Machine", st["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=6))
    story.append(_machine_summary_table(scored, st))
    story.append(Spacer(1, 0.5*cm))

    # ── Section 4 : Classification des Résultats (CVEs) ──────────────────────
    story.append(Paragraph("4. Classification des Résultats", st["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=6))

    # Collecter toutes les CVEs
    all_cve_rows = []
    for ip, ports, score in scored:
        for p in ports:
            for cve in p.get("cves", []):
                try:
                    cvss_val = float(cve.get("cvss") or 0)
                    cvss_str = f"{cvss_val:.1f}"
                except (TypeError, ValueError):
                    cvss_str = "N/A"
                all_cve_rows.append((
                    cve.get("id", "N/A"),
                    cve.get("description", ""),
                    ip,
                    cvss_str,
                    cve.get("severity", "?"),
                ))

    # Trier par CVSS décroissant
    def _cvss_sort(row):
        try: return float(row[3])
        except: return 0.0
    all_cve_rows.sort(key=_cvss_sort, reverse=True)

    if all_cve_rows:
        story.append(_cve_table(all_cve_rows, st))
    else:
        story.append(Paragraph("Aucune CVE identifiée.", st["body"]))
    story.append(Spacer(1, 0.5*cm))

    # ── Section 5 : Détail par machine ────────────────────────────────────────
    story.append(Paragraph("5. Détail par Machine", st["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=6))

    for ip, ports, score in scored:
        label = _score_label(score)
        sc    = _score_color(score)
        os_info = os_map.get(ip, {})
        os_name = os_info.get("os", "Inconnu")

        # Titre machine
        machine_title = Paragraph(
            f"<b>{ip}</b> — {os_name} — Score : {score}/100 — <font color='{'#ff4444' if score>=70 else '#ff8800' if score>=40 else '#f0c000' if score>=20 else '#3fb950'}'>{label}</font>",
            ParagraphStyle("machtitle", fontName="Helvetica-Bold", fontSize=10,
                           textColor=C_BLUE, spaceBefore=10, spaceAfter=4)
        )
        story.append(machine_title)

        for p in ports:
            port_num = p.get("port", "?")
            banner   = p.get("banner", "") or "Pas de bannière"
            cves     = p.get("cves", [])

            story.append(Paragraph(
                f"<b>Port {port_num}</b> — {banner}",
                ParagraphStyle("portline", fontName="Helvetica", fontSize=9,
                               textColor=C_TEXT, leftIndent=10, spaceAfter=3)
            ))

            if cves:
                port_rows = [[
                    Paragraph("CVE ID",     st["th"]),
                    Paragraph("Sévérité",   st["th"]),
                    Paragraph("CVSS",       st["th"]),
                    Paragraph("Description",st["th"]),
                    Paragraph("Exploit",    st["th"]),
                ]]
                for cve in cves:
                    try:    cvss_f = f"{float(cve.get('cvss') or 0):.1f}"
                    except: cvss_f = "N/A"
                    exploit_flag = "⚠ OUI" if cve.get("exploit") else "non"
                    sev = cve.get("severity", "?")
                    sev_cell = Paragraph(
                        f"<b>{sev.upper()}</b>",
                        ParagraphStyle("sev2", fontName="Helvetica-Bold",
                                       fontSize=7, textColor=C_WHITE,
                                       alignment=TA_CENTER)
                    )
                    port_rows.append([
                        Paragraph(cve.get("id","N/A"), st["td"]),
                        sev_cell,
                        Paragraph(cvss_f, st["td"]),
                        Paragraph((cve.get("description","")[:55] or "") + "…", st["td_left"]),
                        Paragraph(exploit_flag, st["td"]),
                    ])

                port_tbl = Table(port_rows, colWidths=[2.8*cm, 2*cm, 1.5*cm, 7.5*cm, 1.4*cm])
                port_style = [
                    ("BACKGROUND",    (0, 0), (-1, 0), C_HEADER),
                    ("FONTSIZE",      (0, 0), (-1, -1), 7),
                    ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING",    (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
                    ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
                    ("BOX",           (0, 0), (-1, -1), 0.8, C_HEADER),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 4),
                    ("LEFTPADDING",   (3, 0), (3, -1), 6),
                ]
                for i, cve in enumerate(cves):
                    port_style.append(
                        ("BACKGROUND", (1, i+1), (1, i+1), _sev_color(cve.get("severity", "")))
                    )
                port_tbl.setStyle(TableStyle(port_style))
                story.append(KeepTogether([
                    Spacer(1, 0.1*cm),
                    port_tbl,
                    Spacer(1, 0.2*cm),
                ]))

        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=C_BORDER, spaceAfter=4))

    # ── Pied de page (footer dans le doc) ─────────────────────────────────────
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        f"Généré par Vulnerability Scanner — {ts} — "
        "Usage autorisé uniquement sur des réseaux dont vous avez l'autorisation.",
        ParagraphStyle("footer", fontName="Helvetica", fontSize=7,
                       textColor=C_MUTED, alignment=TA_CENTER)
    ))

    doc.build(story)
    return output_path
