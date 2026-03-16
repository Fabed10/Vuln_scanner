"""
Formatage coloré des résultats pour le terminal.
"""

from utils.colors import (
    Colors, colorize, severity_color,
    print_success, print_info, print_warning, 
)

#  Ports / Bannières

def print_port_results(resultats: list[dict], target: str):
    """Affiche les ports ouverts avec leurs bannières."""
    print()
    print(colorize("─" * 70, Colors.CYAN))
    print(colorize(f"  RÉSULTATS DU SCAN  →  {target}", Colors.CYAN, Colors.BOLD))
    print(colorize("─" * 70, Colors.CYAN))

    if not resultats:
        print_warning("Aucun port ouvert trouvé.")
        return

    header = f"{'PORT':<8}  {'PROTOCOLE':<10}  BANNIÈRE"
    print(colorize(header, Colors.BOLD))
    print(colorize("─" * 70, Colors.GREY))

    for r in resultats:
        port    = r["port"]
        banner  = r.get("banner", "")
        proto   = _guess_proto(port)
        port_c  = colorize(f"{port:<8}", Colors.GREEN, Colors.BOLD)
        proto_c = colorize(f"{proto:<10}", Colors.CYAN)
        banner_c = colorize(banner[:50], Colors.WHITE)
        print(f"  {port_c}  {proto_c}  {banner_c}")

    print(colorize("─" * 70, Colors.GREY))
    print_success(f"{len(resultats)} port(s) ouvert(s) détecté(s).")


def _guess_proto(port: int) -> str:
    KNOWN = {
        21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
        80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS",
        445:"SMB", 3306:"MySQL", 3389:"RDP", 5432:"PgSQL",
        8080:"HTTP-Alt", 8443:"HTTPS-Alt",
    }
    return KNOWN.get(port, "TCP")



#  CVEs
def print_cve_block(port: int, banner: str, cves: list[dict]):
    """Affiche le bloc CVE pour un port donné."""
    if not cves:
        return

    print()
    print(colorize(f"  ┌─ Port {port}  ({banner[:40]}) ─── {len(cves)} CVE(s)", Colors.MAGENTA, Colors.BOLD))

    for cve in cves:
        sev   = cve.get("severity", "UNKNOWN")
        col   = severity_color(sev)
        sev_c = colorize(f"[{sev:<8}]", col)

        cvss_val = cve.get("cvss", "N/A")
        try:
            cvss_f = float(cvss_val)
            cvss_c = colorize(f"CVSS:{cvss_f:.1f}", col)
        except (TypeError, ValueError):
            cvss_c = colorize("CVSS:N/A", Colors.GREY)

        cve_id_c = colorize(cve.get("id", "?"), Colors.BOLD)

        # Indicateurs
        flags = []
        if cve.get("exploit"):
            flags.append(colorize("EXPLOIT", Colors.RED, Colors.BOLD))
        if cve.get("cisa_kev"):
            flags.append(colorize("CISA-KEV", Colors.RED))
        if not cve.get("patch"):
            flags.append(colorize("NO-PATCH", Colors.YELLOW))
        flags_str = "  " + "  ".join(flags) if flags else ""

        print(f"  │  {sev_c} {cvss_c}  {cve_id_c}{flags_str}")

        desc = cve.get("description", "")
        if desc and desc != "N/A":
            short = desc[:90] + ("…" if len(desc) > 90 else "")
            print(colorize(f"  │       {short}", Colors.GREY))

    print(colorize("  └" + "─" * 60, Colors.MAGENTA))


def print_no_cve_api():
    print()
    print_warning("API CVE non disponible – analyse CVE ignorée.")
    print_info("Lance l'API avec :  python cve-api-student/app_student.py")
