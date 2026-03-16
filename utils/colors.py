"""
Codes couleur ANSI pour l'affichage terminal.
"""

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"

    # Texte
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    GREY    = "\033[90m"

    # Fond
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"


def colorize(text, *codes):
    """Entoure le texte avec les codes couleur donnés."""
    return "".join(codes) + str(text) + Colors.RESET


def severity_color(severity: str) -> str:
    """Retourne la couleur associée à une sévérité CVE."""
    s = (severity or "").upper()
    if s == "CRITICAL":
        return Colors.BOLD + Colors.RED
    elif s == "HIGH":
        return Colors.RED
    elif s == "MEDIUM":
        return Colors.YELLOW
    elif s == "LOW":
        return Colors.GREEN
    else:
        return Colors.GREY


def print_banner():
    print(colorize("""
╔═════════════════════════════════════════════════╗
║             VULNERABILITY SCANNER               ║
║          Scanner de Ports  Analyse CVE          ║
╚═════════════════════════════════════════════════╝
""", Colors.CYAN, Colors.BOLD))


def print_success(msg):
    print(colorize(f"[✔] {msg}", Colors.GREEN))

def print_info(msg):
    print(colorize(f"[*] {msg}", Colors.BLUE))

def print_warning(msg):
    print(colorize(f"[!] {msg}", Colors.YELLOW))

def print_error(msg):
    print(colorize(f"[✘] {msg}", Colors.RED))
