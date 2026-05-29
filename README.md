# Vulnerability Scanner

Scanner de ports Python automatisé avec **analyse CVE automatique** (API NVD), **découverte réseau**, et **génération de rapports professionnels (HTML & PDF)**. Développé dans le cadre d'un projet de fin d'études.
---

## Architecture du projet

```
vuln_scanner/
├── main.py                      ← Point d'entrée principal de l'application
├── utils_ports.py               ← Gestion des options de ports (liste, plage, mixte)
├── requirements.txt             ← Liste des dépendances du projet
├── .gitignore                   ← Configuration Git (exclut les rapports générés)
│
├── core/
│   ├── scanner.py               ← Moteur de scan multi-threadé
│   ├── reconnaissance.py        ← Gestion des sockets et extraction de bannières
│   ├── vulnerability.py         ← Logique de correspondance Bannière → Mots-clés CVE
│   └── network_discovery.py     ← Scan CIDR et détection d'OS (TTL)
│
├── cve/
│   ├── config.py                ← Configuration locale et stockage de la clé API NVD
│   ├── cve_client.py            ← Client de requêtage vers l'API NVD publique (v2.0)
│   └── cve_parser.py            ← Normalisation des données et extraction des scores CVSS
│
├── reporting/
│   ├── format.py                ← Formatage des données pour les flux de sortie
│   ├── report.py                ← Rendu textuel détaillé dans le terminal
│   ├── html_report.py           ← Moteur de génération du rapport interactif HTML
│   ├── pdf_report.py            ← Point d'entrée de la structure PDF
│   └── rapport_pdf.py           ← Design, Tableaux et mise en page ReportLab du PDF
│
├── utils/
│   ├── colors.py                ← Configuration des palettes de couleurs (ANSI & RGB)
│   ├── helpers.py               ← Fonctions utilitaires globales
│   └── log.py                   ← Système de journalisation (logs de l'application)
│
└── results/                     ← Dossier local contenant les rapports générés (Ignoré par Git)
```

---

## Installation

1. Clonez le dépôt sur votre machine locale :
```bash
git clone [https://github.com/Fabed10/Vuln_scanner.git](https://github.com/Fabed10/Vuln_scanner.git)
cd Vuln_scanner
```
2. Installez l'ensemble des dépendances requises:
```bash
pip install -r requirements.txt
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

### Clé API 

1. Copie le fichier exemple :
```bash
cp cve/config.example.py cve/config.py
```

2. Ouvre `cve/config.py` et ajoute ta clé NVD :
```python
NVD_API_KEY = "ta-clé-ici"
```

3. Obtenir une clé gratuite : https://nvd.nist.gov/developers/request-an-api-key

## Pipeline de traitement

```
[Port ouvert détecté]
         ↓
[Banner grabbing] ──► Récupération de la version du service (ex: "OpenSSH 8.2")
         ↓
[core/vulnerability.py] ──► Normalisation de la bannière en mots-clés ("openssh")
         ↓
[cve/cve_client.py] ──► Requête HTTP GET vers l'API REST NVD
         ↓
[cve/cve_parser.py] ──► Extraction du code CVE, score de sévérité et vecteurs d'attaque
         ↓
[reporting/html_report.py] ──► Compilation du Dashboard HTML dynamique
         ↓
[reporting/rapport_pdf.py] ──► Génération du rapport PDF prêt à l'impression
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
