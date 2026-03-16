import socket
import ipaddress
import concurrent.futures
import subprocess
import platform
import re
from utils.colors import print_info, print_warning, colorize, Colors


#  PARSING (CIDR / Plage)


def parse_cidr(saisie: str):
    """
    Accepte :
      - CIDR      : 192.168.1.0/24
      - Plage     : 192.168.1.20-192.168.1.100
    """
    saisie = saisie.strip()

    # Plage
    if "-" in saisie and "/" not in saisie:
        try:
            parts    = saisie.split("-")
            ip_debut = ipaddress.IPv4Address(parts[0].strip())
            ip_fin   = ipaddress.IPv4Address(parts[1].strip())
            if ip_debut > ip_fin:
                print_warning("Plage invalide : début > fin.")
                return None
            ips, current, end = [], int(ip_debut), int(ip_fin)
            while current <= end:
                ips.append(str(ipaddress.IPv4Address(current)))
                current += 1
            return ips
        except (ValueError, IndexError):
            pass

    # CIDR
    try:
        if "/" not in saisie:
            saisie += "/32"
        return ipaddress.IPv4Network(saisie, strict=False)
    except ValueError:
        return None

#  DÉCOUVERTE Ping sweep TCP
def _is_alive(ip: str, timeout: float = 1.0) -> bool:
    """Teste si une IP répond via TCP sur ports courants."""
    PROBE_PORTS = [80, 443, 22, 445, 8080, 3306, 21, 23, 135, 139]
    for port in PROBE_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                return True
            s.close()
        except Exception:
            pass
    return False


def discover_hosts(network, max_workers: int = 100,
                   timeout: float = 1.0) -> list[str]:
    """Sweep sur un réseau ou une plage. Retourne les IPs vivantes."""
    if isinstance(network, list):
        hosts = network
        label = f"{hosts[0]} → {hosts[-1]}"
    else:
        hosts = list(network.hosts()) or [str(network.network_address)]
        label = str(network)

    print_info(f"Sweep réseau sur {label}  ({len(hosts)} adresses)…")
    vivantes = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_is_alive, str(ip), timeout): str(ip) for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    vivantes.append(ip)
                    print(colorize(f"  [+] {ip}  →  EN LIGNE", Colors.GREEN))
            except Exception:
                pass

    vivantes.sort(key=lambda x: ipaddress.IPv4Address(x))
    return vivantes


#  DÉTECTION OS  (Bannière + TTL TCP + TTL Ping)

_OS_PATTERNS = [
    (r"ubuntu",            "Linux (Ubuntu)"),
    (r"debian",            "Linux (Debian)"),
    (r"centos",            "Linux (CentOS)"),
    (r"fedora",            "Linux (Fedora)"),
    (r"red hat|redhat",    "Linux (Red Hat)"),
    (r"kali",              "Linux (Kali)"),
    (r"windows|microsoft", "Windows"),
    (r"win32|win64",       "Windows"),
    (r"IIS",               "Windows / IIS"),
    (r"freebsd",           "FreeBSD"),
    (r"openbsd",           "OpenBSD"),
    (r"solaris|sunos",     "Solaris"),
    (r"cisco",             "Cisco IOS"),
    (r"junos",             "Juniper JunOS"),
    (r"android",           "Android"),
    (r"router|mikrotik",   "Network Device"),
    (r"linux|unix",        "Linux / Unix"),
]


def _ttl_to_os(ttl: int) -> str:
    """
    Détection OS par TTL avec tolérance pour les sauts réseau.
      1  – 64  → Linux / Unix   (TTL initial 64)
      65 – 128 → Windows        (TTL initial 128)
      129– 255 → Cisco / Device (TTL initial 255)
    """
    if ttl <= 64:  return "Linux / Unix"
    if ttl <= 128: return "Windows"
    return "Cisco / Network Device"


def _get_ttl_tcp(ip: str, timeout: float = 2.0) -> int | None:
    """TTL via socket TCP — fonctionne si au moins 1 port répond."""
    for port in [80, 22, 443, 445, 3389, 135, 139, 23, 8080]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
            if s.connect_ex((ip, port)) in (0, 111):
                ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                s.close()
                return ttl
            s.close()
        except Exception:
            pass
    return None


def _get_ttl_ping(ip: str) -> int | None:
    """
    TTL via ping ICMP système.
    Fallback quand 0 ports TCP sont ouverts (ex: Windows avec firewall actif).
    Fonctionne sans droits root.
    """
    try:
        is_win = platform.system().lower() == "windows"
        cmd = (["ping", "-n", "1", "-w", "1000", ip] if is_win
               else ["ping", "-c", "1", "-W", "1", ip])
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=4).stdout
        m = re.search(r"[Tt][Tt][Ll]=(\d+)", out)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return None


def _banner_os(banners: list[str]) -> str | None:
    combined = " ".join(banners)
    for pattern, os_name in _OS_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return os_name
    return None


def detect_os(ip: str, banners: list[str] = None) -> dict:
    # 1 Bannière
    hint = _banner_os(banners or [])
    if hint:
        return {"os": hint, "method": "Bannière", "confidence": "Élevé"}

    # 2 TTL ICMP ping 
    ttl = _get_ttl_ping(ip)
    if ttl:
        return {
            "os":         _ttl_to_os(ttl),
            "method":     f"TTL ping ({ttl})",
            "confidence": "Élevé" if ttl in (64, 128, 255) else "Moyen"
        }

    return {"os": "Inconnu", "method": "N/A", "confidence": "Faible"}
