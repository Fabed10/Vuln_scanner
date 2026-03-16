"""
Priorité des scores CVSS :
  1. CVSS v3.1
  2. CVSS v3.0
  3. CVSS v2.0

avec vecteurs d'attaque (attack vector, complexity, privileges required, user interaction, scope)
"""


def _safe(d, *keys, default="N/A"):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k)
        if d is None:
            return default
    return d if d is not None else default


def _cvssv2_severity(score) -> str:
    try:
        s = float(score)
        if s >= 7.0: return "HIGH"
        if s >= 4.0: return "MEDIUM"
        return "LOW"
    except (TypeError, ValueError):
        return "UNKNOWN"


def _extract_cvss(metrics: dict) -> tuple:
    """
    Extrait (severity, score, version, vecteurs) depuis les métriques NVD.
    v3.1 → v3.0 → v2 dans cet ordre.
    """

    # CVSS v3.1 
    lst = metrics.get("cvssMetricV31", [])
    if lst:
        item  = lst[0]
        data  = item.get("cvssData", {})
        sev   = data.get("baseSeverity", "UNKNOWN")
        score = data.get("baseScore", None)
        if score is not None:
            return sev, score, "v3.1", {
                "vector":           data.get("vectorString", "N/A"),
                "attackVector":     data.get("attackVector", "N/A"),
                "attackComplexity": data.get("attackComplexity", "N/A"),
                "privilegesReq":    data.get("privilegesRequired", "N/A"),
                "userInteraction":  data.get("userInteraction", "N/A"),
                "scope":            data.get("scope", "N/A"),
                "confidentiality":  data.get("confidentialityImpact", "N/A"),
                "integrity":        data.get("integrityImpact", "N/A"),
                "availability":     data.get("availabilityImpact", "N/A"),
                "impactScore":      item.get("impactScore", "N/A"),
                "exploitScore":     item.get("exploitabilityScore", "N/A"),
            }

    #CVSS v3.0 
    lst = metrics.get("cvssMetricV30", [])
    if lst:
        item  = lst[0]
        data  = item.get("cvssData", {})
        sev   = data.get("baseSeverity", "UNKNOWN")
        score = data.get("baseScore", None)
        if score is not None:
            return sev, score, "v3.0", {
                "vector":           data.get("vectorString", "N/A"),
                "attackVector":     data.get("attackVector", "N/A"),
                "attackComplexity": data.get("attackComplexity", "N/A"),
                "privilegesReq":    data.get("privilegesRequired", "N/A"),
                "userInteraction":  data.get("userInteraction", "N/A"),
                "scope":            data.get("scope", "N/A"),
                "confidentiality":  data.get("confidentialityImpact", "N/A"),
                "integrity":        data.get("integrityImpact", "N/A"),
                "availability":     data.get("availabilityImpact", "N/A"),
                "impactScore":      item.get("impactScore", "N/A"),
                "exploitScore":     item.get("exploitabilityScore", "N/A"),
            }

    #CVSS v2.0 
    lst = metrics.get("cvssMetricV2", [])
    if lst:
        item  = lst[0]
        data  = item.get("cvssData", {})
        score = data.get("baseScore", None)
        if score is not None:
            sev = item.get("baseSeverity") or _cvssv2_severity(score)
            return sev, score, "v2.0", {
                "vector":           data.get("vectorString", "N/A"),
                "attackVector":     data.get("accessVector", "N/A"),
                "attackComplexity": data.get("accessComplexity", "N/A"),
                "privilegesReq":    data.get("authentication", "N/A"),
                "userInteraction":  "N/A",
                "scope":            "N/A",
                "confidentiality":  data.get("confidentialityImpact", "N/A"),
                "integrity":        data.get("integrityImpact", "N/A"),
                "availability":     data.get("availabilityImpact", "N/A"),
                "impactScore":      item.get("impactScore", "N/A"),
                "exploitScore":     item.get("exploitabilityScore", "N/A"),
            }

    return "UNKNOWN", None, "N/A", {}


def parse_cve(raw_item: dict) -> dict:
    """Normalise un item brut NVD en dict propre."""
    cve = raw_item.get("cve", {})

    # Description
    desc = "Pas de description"
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", desc)
            break

    # CVSS
    severity, score, cvss_version, vecteurs = _extract_cvss(cve.get("metrics", {}))

    # Références
    refs = [r.get("url", "") for r in cve.get("references", [])[:3]]

    # Date
    published = (cve.get("published", "N/A") or "N/A")[:10]

    # CWE
    cwe = "N/A"
    for w in cve.get("weaknesses", []):
        for desc_w in w.get("description", []):
            if desc_w.get("lang") == "en":
                cwe = desc_w.get("value", "N/A")
                break

    return {
        "id":           cve.get("id", "N/A"),
        "description":  desc,
        "severity":     severity,
        "cvss":         score,
        "cvss_version": cvss_version,
        "vecteurs":     vecteurs,        
        "published":    published,
        "cwe":          cwe,
        "refs":         refs,
        "exploit":      False,
        "patch":        False,
        "cisa_kev":     False,
        "epss":         None,
        "vendor":       "N/A",
        "product":      "N/A",
    }


def parse_cve_list(raw_items: list) -> list[dict]:
    return [parse_cve(item) for item in raw_items]
