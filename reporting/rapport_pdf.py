"""
Génération du rapport PDF de vulnérabilités.
Design professionnel : en-tête entreprise, barre de criticité,
sections Description / Résumé Exécutif / Classification des Résultats.
"""

import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.platypus import KeepTogether
from reportlab.platypus import Image as RLImage

# ── Couleurs ──────────────────────────────────────────────────────────────────
C_CRITIQUE  = colors.HexColor("#CC0000")
C_ELEVE     = colors.HexColor("#E07000")
C_MOYEN     = colors.HexColor("#D4A000")
C_FAIBLE    = colors.HexColor("#2E7D00")
C_HEADER_BG = colors.HexColor("#1A237E")   # bleu marine en-tête tableau
C_ROW_ALT   = colors.HexColor("#F5F5F5")
C_BORDER    = colors.HexColor("#CCCCCC")
C_BLUE_TITLE= colors.HexColor("#1A237E")
C_WHITE     = colors.white
C_BLACK     = colors.black

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
LOGO_PATH = os.path.join(os.path.dirname(__file__), "..", "utils", "Logo.png")

if os.path.exists(LOGO_PATH):
    logo_cell = RLImage(LOGO_PATH, width=45*mm, height=20*mm, kind='proportional')
else:
    logo_cell = Paragraph("<b>Logo</b>", ParagraphStyle(
        "hdr", fontName="Helvetica-Bold", fontSize=11,
        alignment=TA_CENTER, textColor=C_BLACK))


# ── Styles ────────────────────────────────────────────────────────────────────
def _build_styles():
    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "title",
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=C_BLUE_TITLE,
            alignment=TA_CENTER,
            spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            fontName="Helvetica",
            fontSize=10,
            textColor=colors.HexColor("#444444"),
            alignment=TA_CENTER,
            spaceAfter=14,
        ),
        "date": ParagraphStyle(
            "date",
            fontName="Helvetica",
            fontSize=10,
            textColor=C_BLACK,
            spaceAfter=4,
        ),
        "section": ParagraphStyle(
            "section",
            fontName="Helvetica-Bold",
            fontSize=13,
            textColor=C_BLUE_TITLE,
            spaceBefore=14,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body",
            fontName="Helvetica",
            fontSize=10,
            textColor=C_BLACK,
            spaceAfter=4,
            leading=15,
        ),
        "body_bold": ParagraphStyle(
            "body_bold",
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=C_BLACK,
            spaceAfter=4,
        ),
        "footer": ParagraphStyle(
            "footer",
            fontName="Helvetica",
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER,
        ),
        "cell": ParagraphStyle(
            "cell",
            fontName="Helvetica",
            fontSize=9,
            textColor=C_BLACK,
            leading=12,
        ),
        "cell_bold": ParagraphStyle(
            "cell_bold",
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=C_WHITE,
            leading=12,
            alignment=TA_CENTER,
        ),
    }
    return styles


# ── Helpers ───────────────────────────────────────────────────────────────────
def _sev_color(sev: str):
    s = (sev or "").upper()
    return {
        "CRITICAL": C_CRITIQUE,
        "HIGH":     C_ELEVE,
        "MEDIUM":   C_MOYEN,
        "LOW":      C_FAIBLE,
    }.get(s, colors.grey)


def _sev_label_fr(sev: str) -> str:
    return {
        "CRITICAL": "CRITIQUE",
        "HIGH":     "ÉLEVÉ",
        "MEDIUM":   "MOYEN",
        "LOW":      "FAIBLE",
    }.get((sev or "").upper(), sev or "?")


def _risk_label(score: int) -> tuple:
    """Retourne (label_fr, couleur) selon le score de risque."""
    if score >= 70:   return "CRITIQUE", C_CRITIQUE
    elif score >= 40: return "ÉLEVÉ",    C_ELEVE
    elif score >= 20: return "MOYEN",    C_MOYEN
    else:             return "FAIBLE",   C_FAIBLE


def _risk_score(cves: list) -> int:
    score = 0
    for c in cves:
        sev = (c.get("severity") or "").upper()
        score += {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}.get(sev, 0)
        if c.get("exploit"):   score += 8
        if c.get("cisa_kev"): score += 5
    return min(score, 100)


# ── Blocs de contenu ──────────────────────────────────────────────────────────
def _header_table(network: str, scan_time: str, styles: dict):
    """En-tête : logo entreprise | nom outil  +  date + titre."""
    W = 170 * mm

    # Tableau en-tête entreprise / outil
    header_data = [[
        logo_cell,
        Paragraph(
            "<b>Vulnerability Scanner</b><br/>",
            ParagraphStyle("hdr2", fontName="Helvetica-Bold", fontSize=11,
                        alignment=TA_CENTER, textColor=C_BLACK)),
]]
    hdr_tbl = Table(header_data, colWidths=[W / 2, W / 2])
    hdr_tbl.setStyle(TableStyle([
        ("BOX",         (0, 0), (-1, -1), 1.2, C_BLACK),
        ("INNERGRID",   (0, 0), (-1, -1), 1.2, C_BLACK),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0,0), (-1, -1), 10),
    ]))

    # Date
    date_para = Paragraph(
        f"<b>Date du scan :</b>  {scan_time}",
        styles["date"]
    )

    # Titre principal
    titre = Paragraph("SCAN DE VULNÉRABILITÉ", styles["title"])
    cible = Paragraph(f"Cible : {network}", styles["subtitle"])
    return [
        hdr_tbl, 
        Spacer(1, 8 * mm), 
        date_para, 
        Spacer(1, 4 * mm), 
        titre, 
        Spacer(1, 6 * mm),  # <-- Cet espace de 6mm va séparer le titre et la cible
        cible
    ]


def _severity_bar():
    """Barre colorée FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE."""
    W = 170 * mm
    data = [[
        Paragraph("<b>FAIBLE</b>",   ParagraphStyle("sb", fontName="Helvetica-Bold", fontSize=12, textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph("<b>MOYEN</b>",    ParagraphStyle("sb", fontName="Helvetica-Bold", fontSize=12, textColor=C_BLACK, alignment=TA_CENTER)),
        Paragraph("<b>ÉLEVÉ</b>",    ParagraphStyle("sb", fontName="Helvetica-Bold", fontSize=12, textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph("<b>CRITIQUE</b>", ParagraphStyle("sb", fontName="Helvetica-Bold", fontSize=12, textColor=C_WHITE, alignment=TA_CENTER)),
    ]]
    tbl = Table(data, colWidths=[W / 4] * 4)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), C_FAIBLE),
        ("BACKGROUND",    (1, 0), (1, 0), C_MOYEN),
        ("BACKGROUND",    (2, 0), (2, 0), C_ELEVE),
        ("BACKGROUND",    (3, 0), (3, 0), C_CRITIQUE),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return tbl


def _section_description(network: str, scan_time: str,
                          total_machines: int, styles: dict):
    """Section 1 — Description."""
    items = [
        Paragraph("1. Description", styles["section"]),
        HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6),
        Paragraph(
            f"<b>Type de scan :</b>  "
            f"{'Réseau CIDR' if '/' in network else 'Hôte unique'}",
            styles["body"]
        ),
        Paragraph(f"<b>IP / Réseau de scan :</b>  {network}", styles["body"]),
        Paragraph(
            f"<b>Machines analysées :</b>  {total_machines}",
            styles["body"]
        ),
        Paragraph(
            "<b>Responsable sécurité :</b>  "
            "............................................",
            styles["body"]
        ),
    ]
    return items


def _section_resume(counts: dict, total_cves: int,
                    total_exploits: int, styles: dict):
    """Section 2 — Résumé Exécutif."""
    items = [
        Spacer(1, 4*mm),
        Paragraph("2. Résumé Exécutif", styles["section"]),
        HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6),
        Paragraph(
            "Ce rapport présente les résultats du scan de vulnérabilité "
            "effectué sur les équipements ciblés. Les vulnérabilités détectées "
            "sont classées selon leur niveau de criticité.",
            styles["body"]
        ),
        Spacer(1, 3*mm),
    ]

    # Tableau résumé statistiques
    W = 170 * mm
    stat_data = [
        [
            Paragraph("<b>CVEs totales</b>", ParagraphStyle("sh", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
            Paragraph("<b>Exploits connus</b>", ParagraphStyle("sh", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
            Paragraph("<b>CRITIQUE</b>", ParagraphStyle("sh", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
            Paragraph("<b>ÉLEVÉ</b>", ParagraphStyle("sh", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
            Paragraph("<b>MOYEN</b>", ParagraphStyle("sh", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
            Paragraph("<b>FAIBLE</b>", ParagraphStyle("sh", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
        ],
        [
            Paragraph(str(total_cves),             ParagraphStyle("sv", fontName="Helvetica-Bold", fontSize=14, textColor=C_BLUE_TITLE, alignment=TA_CENTER)),
            Paragraph(str(total_exploits),          ParagraphStyle("sv", fontName="Helvetica-Bold", fontSize=14, textColor=C_CRITIQUE,  alignment=TA_CENTER)),
            Paragraph(str(counts.get("critical",0)),ParagraphStyle("sv", fontName="Helvetica-Bold", fontSize=14, textColor=C_CRITIQUE,  alignment=TA_CENTER)),
            Paragraph(str(counts.get("high",0)),    ParagraphStyle("sv", fontName="Helvetica-Bold", fontSize=14, textColor=C_ELEVE,     alignment=TA_CENTER)),
            Paragraph(str(counts.get("medium",0)),  ParagraphStyle("sv", fontName="Helvetica-Bold", fontSize=14, textColor=C_MOYEN,     alignment=TA_CENTER)),
            Paragraph(str(counts.get("low",0)),     ParagraphStyle("sv", fontName="Helvetica-Bold", fontSize=14, textColor=C_FAIBLE,    alignment=TA_CENTER)),
        ],
    ]
    stat_tbl = Table(stat_data, colWidths=[W / 6] * 6)
    stat_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_HEADER_BG),
        ("BOX",           (0, 0), (-1, -1), 0.8, C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    items.append(stat_tbl)
    return items


def _section_classification(results: dict, os_map: dict, styles: dict):
    """Section 3 — Classification des Résultats (tableau CVE)."""
    W = 170 * mm
    col_w = [28*mm, 68*mm, 28*mm, 18*mm, 28*mm]

    header_row = [
        Paragraph("<b>CVE</b>",        ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph("<b>Description</b>",ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph("<b>IP / Machine</b>",ParagraphStyle("th",fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph("<b>CVSS</b>",       ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph("<b>Criticité</b>",  ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
    ]

    rows = [header_row]
    style_cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0), C_HEADER_BG),
        ("BOX",           (0, 0), (-1, -1), 0.8, C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.4, C_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]

    row_idx = 1
    for ip, ports in sorted(results.items()):
        for port_info in ports:
            for cve in port_info.get("cves", []):
                cve_id  = cve.get("id", "N/A")
                desc    = (cve.get("description") or "")[:80]
                if len(cve.get("description") or "") > 80:
                    desc += "…"
                sev     = cve.get("severity", "")
                cvss_v  = cve.get("cvss", "N/A")
                try:    cvss_str = f"{float(cvss_v):.1f}"
                except: cvss_str = "N/A"

                sev_color = _sev_color(sev)
                sev_fr    = _sev_label_fr(sev)

                bg = C_ROW_ALT if row_idx % 2 == 0 else C_WHITE

                rows.append([
                    Paragraph(cve_id,   ParagraphStyle("td", fontName="Helvetica",      fontSize=8, textColor=C_BLACK)),
                    Paragraph(desc,     ParagraphStyle("td", fontName="Helvetica",      fontSize=8, textColor=C_BLACK, leading=11)),
                    Paragraph(ip,       ParagraphStyle("td", fontName="Helvetica-Bold", fontSize=8, textColor=C_BLACK, alignment=TA_CENTER)),
                    Paragraph(cvss_str, ParagraphStyle("td", fontName="Helvetica-Bold", fontSize=9, textColor=C_BLACK, alignment=TA_CENTER)),
                    Paragraph(f"<b>{sev_fr}</b>", ParagraphStyle("td", fontName="Helvetica-Bold", fontSize=8, textColor=C_WHITE, alignment=TA_CENTER)),
                ])
                style_cmds.append(("BACKGROUND", (0, row_idx), (-2, row_idx), bg))
                style_cmds.append(("BACKGROUND", (4, row_idx), (4, row_idx), sev_color))
                row_idx += 1

    if row_idx == 1:
        rows.append([Paragraph("Aucune CVE détectée.", styles["body"]),
                     "", "", "", ""])

    tbl = Table(rows, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle(style_cmds))

    items = [
        Spacer(1, 4*mm),
        Paragraph("3. Classification des Résultats", styles["section"]),
        HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6),
        tbl,
    ]
    return items


def _section_details(results: dict, os_map: dict, styles: dict):
    """Section 4 — Détails par machine."""
    items = [
        Spacer(1, 4*mm),
        Paragraph("4. Détails par Machine", styles["section"]),
        HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6),
    ]

    W = 170 * mm
    for ip, ports in sorted(results.items()):
        all_cves  = [c for p in ports for c in p.get("cves", [])]
        score     = _risk_score(all_cves)
        lbl, clr  = _risk_label(score)
        os_name   = (os_map or {}).get(ip, {}).get("os", "Inconnu")
        open_ports= ", ".join(str(p["port"]) for p in ports) or "—"

        machine_info = [
            [
                Paragraph(f"<b>{ip}</b>", ParagraphStyle("mi", fontName="Helvetica-Bold", fontSize=11, textColor=C_WHITE)),
                Paragraph(f"<b>{lbl}</b>", ParagraphStyle("mi2", fontName="Helvetica-Bold", fontSize=11, textColor=C_WHITE, alignment=TA_RIGHT)),
            ]
        ]
        mi_tbl = Table(machine_info, colWidths=[W * 0.75, W * 0.25])
        mi_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), clr),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ]))

        sub_items = [
            mi_tbl,
            Paragraph(f"<b>OS détecté :</b> {os_name}  |  <b>Score de risque :</b> {score}/100  |  <b>Ports ouverts :</b> {open_ports}", styles["body"]),
        ]

        for port_info in ports:
            banner    = port_info.get("banner") or "Pas de bannière"
            cves      = port_info.get("cves", [])
            cve_count = len(cves)

            sub_items.append(Paragraph(
                f"<b>Port {port_info['port']}</b>  —  {banner}  "
                f"({'<font color=\"red\">' if cve_count else ''}"
                f"{cve_count} CVE{'s' if cve_count != 1 else ''}"
                f"{'</font>' if cve_count else ''})",
                ParagraphStyle("port", fontName="Helvetica", fontSize=9,
                               textColor=C_BLACK, spaceBefore=4, leftIndent=6,
                               borderPad=3)
            ))

            for cve in cves:
                sev_fr  = _sev_label_fr(cve.get("severity", ""))
                sev_clr = _sev_color(cve.get("severity", ""))
                cvss_v  = cve.get("cvss", "N/A")
                try:    cvss_str = f"{float(cvss_v):.1f}"
                except: cvss_str = "N/A"
                desc    = (cve.get("description") or "")[:120]
                flags   = []
                if cve.get("exploit"):   flags.append("EXPLOIT")
                if cve.get("cisa_kev"): flags.append("CISA-KEV")
                flags_str = "  ".join(flags)

                sub_items.append(Paragraph(
                    f"&nbsp;&nbsp;&nbsp;&nbsp;"
                    f"<b>{cve.get('id','N/A')}</b>  "
                    f"[{sev_fr}]  CVSS: {cvss_str}"
                    f"{'  <b>' + flags_str + '</b>' if flags_str else ''}",
                    ParagraphStyle("cve_line", fontName="Helvetica", fontSize=8,
                                   textColor=C_BLACK, leftIndent=14, spaceBefore=2)
                ))
                if desc:
                    sub_items.append(Paragraph(
                        f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{desc}",
                        ParagraphStyle("cve_desc", fontName="Helvetica", fontSize=7,
                                       textColor=colors.HexColor("#555555"),
                                       leftIndent=20, spaceBefore=1)
                    ))

        sub_items.append(Spacer(1, 5*mm))
        items.append(KeepTogether(sub_items[:6]))  # garder le bloc machine groupé
        items.extend(sub_items[6:])

    return items


# ── Fonction principale ───────────────────────────────────────────────────────
def generate_pdf_report(network: str, results: dict,
                        os_map: dict = None, scan_time: str = None) -> str:
    """
    Génère le rapport PDF.
    results : { "192.168.1.5": [ {port, banner, cves:[...]}, ... ], ... }
    Retourne le chemin absolu du fichier PDF généré.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    ts    = scan_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fname = (f"rapport_{network.replace('/', '_').replace('.', '_')}"
             f"_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    path  = os.path.join(RESULTS_DIR, fname)

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        rightMargin=20*mm, leftMargin=20*mm,
        topMargin=18*mm,   bottomMargin=18*mm,
        title=f"Rapport Vulnérabilités — {network}",
        author="Vulnerability Scanner",
    )

    # ── Calculs globaux ──
    scored = []
    for ip, ports in results.items():
        all_cves = [c for p in ports for c in p.get("cves", [])]
        score    = _risk_score(all_cves)
        scored.append((ip, ports, score))
    scored.sort(key=lambda x: x[2], reverse=True)

    total_machines = len(scored)
    total_cves     = sum(len(c) for _, ports, _ in scored
                         for p in ports for c in [p.get("cves", [])])
    total_exploits = sum(1 for _, ports, _ in scored
                         for p in ports for c in p.get("cves", [])
                         if c.get("exploit"))
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for _, _, score in scored:
        lbl, _ = _risk_label(score)
        key = {"CRITIQUE": "critical", "ÉLEVÉ": "high",
               "MOYEN": "medium", "FAIBLE": "low"}.get(lbl, "low")
        counts[key] += 1

    styles = _build_styles()
    story  = []

    # ── En-tête + titre ──
    story.extend(_header_table(network, ts, styles))
    story.append(Spacer(1, 5*mm))
    story.append(_severity_bar())
    story.append(Spacer(1, 6*mm))

    # ── Section 1 — Description ──
    story.extend(_section_description(network, ts, total_machines, styles))

    # ── Section 2 — Résumé Exécutif ──
    story.extend(_section_resume(counts, total_cves, total_exploits, styles))

    # ── Section 3 — Classification ──
    story.extend(_section_classification(results, os_map or {}, styles))

    # ── Section 4 — Détails ──
    story.extend(_section_details(results, os_map or {}, styles))

    # ── Pied de page inline ──
    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Paragraph(
        f"Généré par Vulnerability Scanner — {ts} — "
        "Usage autorisé uniquement sur des réseaux dont vous avez l'autorisation.",
        styles["footer"]
    ))

    doc.build(story)
    return os.path.abspath(path)
