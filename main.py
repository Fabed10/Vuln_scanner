import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from core.scanner           import scan_engin
from core.vulnerability     import banner_to_search_term
from core.network_discovery import parse_cidr, discover_hosts, detect_os
from cve.cve_client         import CVEClient
from cve.cve_parser         import parse_cve_list
from cve.config             import NVD_API_KEY
from utils_ports            import parser_ports
from utils.colors           import (
    print_banner, print_info, print_warning, print_error,
    Colors, colorize
)
from reporting.format       import print_port_results, print_cve_block
from reporting.report       import print_final_report
from reporting.html_report  import generate_html_report


#  Statut API
def afficher_statut_api():
    if NVD_API_KEY and NVD_API_KEY.strip():
        print_info("Clé NVD API détectée  →  50 requêtes / 30 secondes")
    else:
        print_warning("Aucune clé NVD  →  cve/config.py")


#  Enrichissement CVE
def enrichir_avec_cve(resultats: list[dict], client: CVEClient) -> list[dict]:
    enrichis = []
    for r in resultats:
        entry = dict(r)
        entry["cves"] = []
        term = banner_to_search_term(r.get("banner", ""))
        if term:
            print_info(f"CVE search : {term}  (port {r['port']})")
            raw = client.search_cves(term, limit=5)
            entry["cves"] = parse_cve_list(raw)
            if entry["cves"]:
                print_cve_block(r["port"], r["banner"], entry["cves"])
            else:
                print_warning(f"  Aucune CVE pour '{term}'")
        enrichis.append(entry)
    return enrichis


#  Scan d'une seule machine
def run_scan_single(target: str, ports) -> list[dict]:
    """Scan + CVE sur une machine. Retourne les résultats enrichis."""
    print_info(f"Scan de {target} …")
    try:
        resultats = scan_engin(target, ports)
    except KeyboardInterrupt:
        print(colorize("\n  [✘] Scan interrompu (Ctrl+C).", Colors.RED))
        sys.exit(0)

    print_port_results(resultats, target)
    if not resultats:
        return []

    client = CVEClient()
    print_info("Analyse CVE via NVD …")
    return enrichir_avec_cve(resultats, client)


#  Scan réseau CIDR
def run_scan_network(cidr: str):
    network = parse_cidr(cidr)
    if network is None:
        print_error(f"CIDR invalide : {cidr}")
        return

    scan_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── 1. Découverte ──
    print()
    print(colorize("═" * 60, Colors.CYAN, Colors.BOLD))
    print(colorize("  PHASE 1 — Découverte réseau", Colors.CYAN, Colors.BOLD))
    print(colorize("═" * 60, Colors.CYAN, Colors.BOLD))

    vivantes = discover_hosts(network)

    if not vivantes:
        print_warning("Aucune machine détectée sur ce réseau.")
        return

    print_info(f"{len(vivantes)} machine(s) en ligne.")

    # Ports à scanner (les plus importants)
    PORTS_RESEAU = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 512, 513, 514, 993, 995,
        1099, 1433, 1521, 1524, 2049, 2121,
        3306, 3389, 3632, 5432, 5900, 5901,
        6000, 6379, 8080, 8443, 8888, 9090, 27017
    ]

    # 2 Scan et CVE par machine 
    all_results: dict[str, list[dict]] = {}
    os_map: dict = {}

    for idx, ip in enumerate(vivantes, 1):
        print()
        print(colorize(f"═" * 60, Colors.BLUE, Colors.BOLD))
        print(colorize(f"  PHASE 2 — Machine {idx}/{len(vivantes)} : {ip}", Colors.BLUE, Colors.BOLD))
        print(colorize(f"═" * 60, Colors.BLUE, Colors.BOLD))

        try:
            enrichis = run_scan_single(ip, PORTS_RESEAU)
            all_results[ip] = enrichis
            # Détection OS
            banners = [r.get("banner","") for r in enrichis if r.get("banner")]
            os_info = detect_os(ip, banners)
            os_map[ip] = os_info
            print_info(f"OS détecté : {os_info['os']}  ({os_info['method']} — {os_info['confidence']})")

        except KeyboardInterrupt:
            print(colorize("\n  [✘] Scan réseau interrompu (Ctrl+C).", Colors.RED))
            break

    if not all_results:
        print_warning("Aucun résultat collecté.")
        return

    # 3 Rapport HTML
    print()
    print(colorize("═" * 60, Colors.MAGENTA, Colors.BOLD))
    print(colorize("  PHASE 3 — Génération du rapport HTML", Colors.MAGENTA, Colors.BOLD))
    print(colorize("═" * 60, Colors.MAGENTA, Colors.BOLD))

    html_path = generate_html_report(cidr, all_results, os_map, scan_start)

    # Rapport terminal résumé
    print()
    for ip, ports in sorted(
        all_results.items(),
        key=lambda x: sum(len(p.get("cves",[])) for p in x[1]),
        reverse=True
    ):
        print_final_report(ip, ports)

    # affichage du chemin HTML 
    print(colorize("═" * 70, Colors.GREEN, Colors.BOLD))
    print(colorize("  [✔] RAPPORT HTML GÉNÉRÉ", Colors.GREEN, Colors.BOLD))
    print(colorize(f"      {os.path.abspath(html_path)}", Colors.CYAN, Colors.BOLD))
    print(colorize("═" * 70, Colors.GREEN, Colors.BOLD))
    print()


#  Menus
def afficher_menu():
    print(colorize("""
  1.  Scan hôte unique complet       (ports 1–65535 sur une IP)
  2.  Scan hôte unique rapide        (ports personnalisés sur une IP)
  3.  Scan réseau                    (ex: 192.168.1.0/24)  
  4.  Quitter
""", Colors.WHITE))


def demander_cible() -> str:
    return input(colorize("  [?] Adresse IP de la cible : ", Colors.CYAN)).strip()


#  Pipeline machine unique

def run_scan_and_report(target: str, ports):
    enrichis = run_scan_single(target, ports)
    if not enrichis:
        return
    print_final_report(target, enrichis)

    # Export HTML pour machine seule aussi
    rep = input(colorize("\n  [?] Générer le rapport HTML ? (o/n) : ", Colors.CYAN)).strip().lower()
    if rep in ("o", "oui", "y", "yes"):
        path = generate_html_report(target, {target: enrichis})
        print_final_report(target, enrichis)
        print(colorize("═" * 70, Colors.GREEN, Colors.BOLD))
        print(colorize("  [✔] RAPPORT HTML GÉNÉRÉ", Colors.GREEN, Colors.BOLD))
        print(colorize(f"      {os.path.abspath(path)}", Colors.CYAN, Colors.BOLD))
        print(colorize("═" * 70, Colors.GREEN, Colors.BOLD))
        print()



#  Point d'entrée
def main():
    print_banner()
    afficher_statut_api()
    afficher_menu()

    choix = input(colorize("  Choisissez une option (1-4) : ", Colors.BOLD)).strip()

    if choix == "1":
        target = demander_cible()
        run_scan_and_report(target, 65535)

    elif choix == "2":
        target = demander_cible()
        print(colorize("""
  Format accepté :
    Liste  → 22, 80, 443
    Range  → 1-1024
    Mixte  → 22, 80, 100-200
""", Colors.GREY))
        saisie = input(colorize("  [?] Ports à scanner : ", Colors.CYAN)).strip()
        ports = parser_ports(saisie)
        if ports is None:
            print_error("Format invalide.")
        else:
            print_info(f"{len(ports)} port(s) sélectionné(s).")
            run_scan_and_report(target, ports)

    elif choix == "3":
        print(colorize("""
  Exemples :
    192.168.1.0/24             -->     CIDR
    192.168.1.20-192.168.1.100 -->     Range IP
""", Colors.GREY))
        cidr = input(colorize("  [?] Réseau cible : ", Colors.CYAN)).strip()
        run_scan_network(cidr)

    elif choix == "4":
        print_info("Au revoir !")
        sys.exit(0)

    else:
        print_error("Option invalide.")

    print(colorize("\n" + "─" * 70 + "\n", Colors.CYAN))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colorize("\n\n  [✘] Interruption (Ctrl+C) — Au revoir !", Colors.RED))
        sys.exit(0)
