"""
Génération du rapport final 
"""

import os
from datetime import datetime

from utils.colors import (
    Colors, colorize, severity_color,
)
from utils.helpers import timestamp

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")



#  Rapport terminal 


def print_final_report(target: str, scan_results: list[dict]):
    """
    Affiche un récapitulatif complet à la fin du scan.

    """
    total_ports = len(scan_results)
    all_cves    = [c for r in scan_results for c in r.get("cves", [])]
    total_cves  = len(all_cves)

    # Comptage par sévérité
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for c in all_cves:
        sev = (c.get("severity") or "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1

    exploits = sum(1 for c in all_cves if c.get("exploit"))
    kev      = sum(1 for c in all_cves if c.get("cisa_kev"))

    width = 70
    bar   = "═" * width

    print()
    print(colorize(bar, Colors.CYAN, Colors.BOLD))
    print(colorize(f"  RAPPORT FINAL  –  {target}  –  {timestamp()}", Colors.CYAN, Colors.BOLD))
    print(colorize(bar, Colors.CYAN, Colors.BOLD))

    # Statistiques ports
    print(colorize(f"\n  Ports ouverts détectés  : ", Colors.WHITE) +
          colorize(str(total_ports), Colors.GREEN, Colors.BOLD))
    print(colorize(f"  CVEs identifiés         : ", Colors.WHITE) +
          colorize(str(total_cves), Colors.YELLOW, Colors.BOLD))

    # Répartition sévérité
    print()
    print(colorize("  RÉPARTITION PAR SÉVÉRITÉ", Colors.BOLD))
    print(colorize("  " + "─" * 40, Colors.GREY))
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        n   = counts.get(sev, 0)
        col = severity_color(sev)
        bar_fill = "█" * min(n, 30)
        print(f"  {colorize(f'{sev:<10}', col)}  {colorize(bar_fill, col)}  {colorize(str(n), Colors.BOLD)}")

    # Indicateurs de risque
    print()
    print(colorize("  INDICATEURS DE RISQUE", Colors.BOLD))
    print(colorize("  " + "─" * 40, Colors.GREY))
    exp_c = colorize(str(exploits), Colors.RED, Colors.BOLD) if exploits else colorize("0", Colors.GREEN)
    kev_c = colorize(str(kev),      Colors.RED, Colors.BOLD) if kev      else colorize("0", Colors.GREEN)
    print(f"  CVEs avec exploit connu   : {exp_c}")
    print(f"  CVEs dans CISA KEV        : {kev_c}")

    # Score de risque global (simple)
    score = _risk_score(counts, exploits, kev)
    score_col = Colors.RED if score >= 70 else (Colors.YELLOW if score >= 40 else Colors.GREEN)
    print()
    print(colorize("  SCORE DE RISQUE GLOBAL", Colors.BOLD))
    print(colorize("  " + "─" * 40, Colors.GREY))
    bar_s = "█" * (score // 5) + "░" * (20 - score // 5)
    print(f"  [{colorize(bar_s, score_col)}]  {colorize(f'{score}/100', score_col, Colors.BOLD)}")

    # Recommandation
    print()
    print(colorize("  RECOMMANDATION", Colors.BOLD))
    print(colorize("  " + "─" * 40, Colors.GREY))
    if score >= 70:
        print(colorize("  ⚠ RISQUE CRITIQUE – intervention urgente recommandée", Colors.RED, Colors.BOLD))
    elif score >= 40:
        print(colorize("  ⚠ RISQUE MODÉRÉ  – correctifs à appliquer rapidement", Colors.YELLOW))
    else:
        print(colorize("  ✔ RISQUE FAIBLE  – surveillance standard suffisante", Colors.GREEN))

    print()
    print(colorize(bar, Colors.CYAN, Colors.BOLD))
    print()


def _risk_score(counts: dict, exploits: int, kev: int) -> int:
    score = 0
    score += counts.get("CRITICAL", 0) * 10
    score += counts.get("HIGH",     0) * 5
    score += counts.get("MEDIUM",   0) * 2
    score += counts.get("LOW",      0) * 1
    score += exploits * 8
    score += kev * 5
    return min(score, 100)

