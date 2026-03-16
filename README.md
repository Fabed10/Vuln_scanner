# Vulnerability Scanner

Scanner de ports Python avec **détection d'OS**, **analyse CVE automatique** (API NVD) et **rapport HTML**.

---

## Architecture du projet

```
vuln_scanner/
├── main.py                      ← Point d'entrée principal
├── utils_ports.py               ← ports (liste, plage, mixte)
├── requirements.txt
│
├── core/
│   ├── scanner.py               ← Moteur multi-threadé (500 workers)
│   ├── reconnaissance.py        ← Connexion socket + extraction de bannière
│   ├── vulnerability.py         ← Correspondance bannière → CVE
│   └── network_discovery.py     ← Scan CIDR/plage + détection OS 
│
├── cve/
│   ├── config.py                ← Clé API NVD 
│   ├── cve_client.py            ← Client HTTP vers l'API NVD publique
│   └── cve_parser.py            ← Normalisation CVE + extraction vecteurs CVSS
│
├── reporting/
│   ├── format.py                ← Affichage coloré terminal
│   ├── report.py                ← Rapport final terminal
│   └── html_report.py           ← Génération du rapport HTML
│
├── utils/
│   ├── colors.py                ← Codes ANSI + fonctions d'affichage
│   ├── helpers.py               ← Fonctions utilitaires
│   └── log.py                   ← Logger vers fichier
│
└── results/                     ← Rapports HTML générés automatiquement
```

---

## Installation

```bash
pip install tqdm python-nmap
```


---

## Utilisation

```bash
python main.py
```

### Menu principal

```
  1.  Scan hôte unique complet       (ports 1–65535 sur une IP)
  2.  Scan hôte unique rapide        (ports personnalisés sur une IP)
  3.  Scan réseau                    (ex: 192.168.1.0/24)  
  4.  Quitter
```

---

## Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| Scan complet | Ports 1–65535 en multi-thread (500 workers) |
| Scan rapide | Ports personnalisés (liste, plage, mixte) |
| Scan réseau | CIDR ou plage d'adresses avec découverte d'hôtes |
| Banner grabbing | SSH, HTTP, FTP, MySQL, SMB, RDP, Telnet… |
| Détection OS | Par analyse TTL ping et bannières de services |
| Analyse CVE | Recherche automatique via API NVD (NIST) — sans serveur local |
| Vecteurs CVSS | Affichage attackVector, confidentiality, integrity… |
| Rapport HTML | Tableau de bord interactif avec filtres et scores de criticité |

---

## API CVE — NVD (NIST)

Aucun serveur local requis. L'outil interroge directement l'API publique NVD :

```
https://services.nvd.nist.gov/rest/json/cves/2.0
```

### Clé API ( recommandé)

Obtenir une clé gratuite : https://nvd.nist.gov/developers/request-an-api-key

Puis l'ajouter dans `cve/config.py` :

```python
NVD_API_KEY = "votre-clé-ici"
```

---

## Pipeline de traitement

```
Port ouvert détecté
        ↓
Banner grabbing 
        ↓
core/vulnerability.py → banner_to_search_term()
        ↓  ex: "OpenSSH 8.2" → "openssh"
cve/cve_client.py → search_cves("openssh", limit=5)
        ↓  requête GET → api.nvd.nist.gov
cve/cve_parser.py → parse_cve_list()
        ↓  CVE + score CVSS + vecteurs
reporting/html_report.py → generate_html_report()
        ↓
results/rapport_xxx.html
```

---

## Codes couleur terminal

| Couleur | Signification |
|---|---|
| 🔴 Rouge gras | CRITICAL |
| 🔴 Rouge | HIGH |
| 🟡 Jaune | MEDIUM |
| 🟢 Vert | LOW |
| ⚪ Gris | UNKNOWN |
| 🔵 Cyan | En-têtes / structure |
| 🟣 Magenta | Blocs CVE par port |