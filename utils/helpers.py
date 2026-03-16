"""
Fonctions utilitaires générales.
"""
from datetime import datetime


def timestamp():
    """Retourne un horodatage lisible."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_get(d, *keys, default="N/A"):
    """Accès sûr à une clé imbriquée dans un dict."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d if d is not None else default
