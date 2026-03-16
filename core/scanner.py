import concurrent.futures
import core.reconnaissance
from tqdm import tqdm


def scan_engin(target_ip, ports):

    recon = core.reconnaissance.ReconScanner(target_ip)
    resultats_finaux = []

    # Convertir en liste 
    if isinstance(ports, int):
        liste_ports = list(range(1, ports + 1))
        print(f"[*] Analyse multi-threadée de {target_ip} (ports 1-{ports})...")
    else:
        liste_ports = ports
        print(f"[*] Analyse de {len(ports)} port(s) sur {target_ip}...")

    with tqdm(total=len(liste_ports), desc="Progression du scan", unit="port") as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=500) as executor:
            futures = {executor.submit(recon.check_port_banner, port): port for port in liste_ports}

            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    status, banner = future.result()
                    if status == "OUVERT" and banner:
                        resultats_finaux.append({"port": port, "banner": banner})
                except Exception:
                    pass
                pbar.update(1)

    # Nmap pour les ports filtrer
    if recon.silencieux:
        resultats_nmap = recon.nmap_banner()
        resultats_finaux += resultats_nmap

    return sorted(resultats_finaux, key=lambda x: x['port'])