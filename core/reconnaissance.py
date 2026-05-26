import socket
import time

class ReconScanner:

    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET

        # Ports sans bannière socket 
        self.silencieux = []

    def check_port_banner(self, port):

        try:
            s = socket.socket(self.family, socket.SOCK_STREAM)
            s.settimeout(5.0)

            if s.connect_ex((self.target_ip, port)) != 0:
                s.close()
                return "FERME", ""

            banniere = ""

            # Cas spécial Telnet
            if port == 23:
                banniere = self._flux_telnet(s)
            else:
                # Tentative 1 : lecture immédiate
                data = self._lire(s)
                if data:
                    banniere = self._nettoyer(data, port)

                # Tentative 2 : sonde si rien reçu
                if not banniere:
                    sonde = self._sonde(port)
                    if sonde:
                        try:
                            s.send(sonde)
                            data = self._lire(s)
                            if data:
                                banniere = self._nettoyer(data, port)
                        except Exception:
                            pass

            s.close()

            if banniere:
                return "OUVERT", banniere
            else:
                self.silencieux.append(port)
                return "OUVERT", ""

        except Exception:
            return "ERREUR", ""


    def nmap_banner(self):

        if not self.silencieux:
            return []

        # Vérifier que nmap est installé
        try:
            import nmap
            import shutil
            if not shutil.which("nmap"):
                return []
        except ImportError:
            return []

        ports_str = ",".join(str(p) for p in self.silencieux)

        # Demander les droits admin 
        choix = input("[?] Droits administrateur requis pour nmap (o/n) : ").strip().lower()
        arguments = "-sV --version-intensity 7 -T4"
        if choix in ("o", "oui", "y", "yes"):
            arguments = "sudo " + arguments

        try:
            nm = nmap.PortScanner()
            nm.scan(
                hosts=self.target_ip,
                ports=ports_str,
                arguments=arguments
            )

            resultats = []

            if self.target_ip not in nm.all_hosts():
                return []

            if 'tcp' not in nm[self.target_ip]:
                return []

            for port in self.silencieux:
                if port not in nm[self.target_ip]['tcp']:
                    continue

                info = nm[self.target_ip]['tcp'][port]

                parties = []
                if info.get('product'):   parties.append(info['product'])
                if info.get('version'):   parties.append(info['version'])
                if info.get('extrainfo'): parties.append(f"({info['extrainfo']})")
                if not parties and info.get('name'):
                    parties.append(info['name'])

                banniere = " ".join(parties).strip()
                resultats.append({
                    "port":   port,
                    "banner": banniere if banniere else "Service Filter "
                })

            self.silencieux = []

            return resultats

        except Exception:
            return []


    def _lire(self, s, timeout=5.0):
        s.settimeout(timeout)
        morceaux = []
        try:
            while True:
                morceau = s.recv(4096)
                if not morceau:
                    break
                morceaux.append(morceau)
                if sum(len(m) for m in morceaux) >= 4096:
                    break
        except socket.timeout:
            pass
        except Exception:
            pass
        return b"".join(morceaux)

    def _sonde(self, port):
    
        HTTP = b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: Scanner\r\n\r\n"
        sondes = {
            80: HTTP, 443: HTTP, 8080: HTTP, 8443: HTTP, 8000: HTTP,
            23: bytes([0xff,0xfe,0x01, 0xff,0xfe,0x03, 0xff,0xfe,0x1f]),
            111: bytes([
                0x80,0x00,0x00,0x1c, 0x00,0x00,0x00,0x01,
                0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x02,
                0x00,0x01,0x86,0xa0, 0x00,0x00,0x00,0x02,
                0x00,0x00,0x00,0x04, 0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,
            ]),
            445: bytes([
                0x00,0x00,0x00,0x54, 0xff,0x53,0x4d,0x42,
                0x72,0x00,0x00,0x00, 0x00,0x18,0x01,0x28,
                0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00, 0x00,0x00,0xff,0xfe,
                0x00,0x00,0x00,0x00, 0x00,0x00,0x0c,0x00,
                0x02,0x4e,0x54,0x20, 0x4c,0x4d,0x20,0x30,
                0x2e,0x31,0x32,0x00,
            ]),
            1099: bytes([0x4a,0x52,0x4d,0x49,0x00,0x01,0x4b]),
            5432: bytes([0x00,0x00,0x00,0x27,0x00,0x03,0x00,0x00])
                  + b'user\x00postgres\x00database\x00postgres\x00\x00',
            3632: b'DIST',
            2049: bytes([
                0x80,0x00,0x00,0x1c, 0x00,0x00,0x00,0x02,
                0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x02,
                0x00,0x01,0x86,0xa3, 0x00,0x00,0x00,0x03,
                0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,
            ]),
        }
        return sondes.get(port, b"\r\n")

    def _supprimer_iac(self, data):
    
        result = bytearray()
        i = 0
        while i < len(data):
            if data[i] == 0xFF and i + 1 < len(data):
                cmd = data[i + 1]
                if cmd in (0xFB, 0xFC, 0xFD, 0xFE) and i + 2 < len(data):
                    i += 3
                else:
                    i += 2
            else:
                result.append(data[i])
                i += 1
        return bytes(result)

    def _nettoyer(self, data, port=0):
        #  retourne le texte lisible
        if not data:
            return ""

        if port == 3306 and len(data) >= 6 and data[4] == 0x0a:
            try:
                fin = data.index(b"\x00", 5)
                v = data[5:fin].decode("ascii", errors="ignore")
                if v: return f"MySQL {v}"
            except Exception: pass

        if port == 3389 and len(data) >= 2 and data[0] == 0x03 and data[1] == 0x00:
            return "RDP (Remote Desktop Protocol)"

        if port in (445, 139):
            if b"\xffSMB" in data: return "SMB v1"
            if b"\xfeSMB" in data: return "SMB v2/v3"

        if port == 139 and len(data) >= 1 and data[0] == 0x82:
            return "NetBIOS Session Service"

        if port == 5432 and len(data) >= 1 and data[0] == ord('E'):
            try:
                for p in data[5:].split(b'\x00'):
                    if p.startswith(b'M'):
                        return "PostgreSQL - " + p[1:].decode("latin-1", errors="ignore")[:60]
            except Exception: pass
            return "PostgreSQL"

        if port == 1099 and len(data) >= 1 and data[0] == 0x4e:
            return "Java RMI"

        if port == 111 and len(data) >= 12:
            if int.from_bytes(data[8:12], "big") == 1:
                return "RPCbind (ONC-RPC)"

        if port == 2049 and len(data) >= 12:
            if int.from_bytes(data[8:12], "big") == 1:
                return "NFS (Network File System)"

        if port == 23:
            data = self._supprimer_iac(data)

        # APRÈS
        # Pour les ports HTTP : extraire le header Server: en priorité
        if port in (80, 443, 8080, 8443, 8000):
            try:
                texte_http = data.decode("latin-1", errors="replace")
                for ligne in texte_http.splitlines():
                    if ligne.lower().startswith("server:"):
                        server = ligne.split(":", 1)[1].strip()
                        if server:
                            return server[:100]
                # Fallback : retourner la première ligne de statut HTTP
                for ligne in texte_http.splitlines():
                    ligne = ligne.strip()
                    if ligne:
                        return ligne[:100]
            except Exception:
                pass
            return ""

        try:
            texte = data.decode("latin-1", errors="replace")
        except Exception:
            return ""
        texte = "".join(c for c in texte if 31 < ord(c) < 127)
        for ligne in texte.splitlines():
            ligne = ligne.strip()
            if ligne:
                return ligne[:100]
        return ""

    def _flux_telnet(self, s):
    
        try:
            data1 = self._lire(s)
            if not data1:
                return ""

            texte1 = self._nettoyer(self._supprimer_iac(data1), 23)
            if texte1:
                return texte1

            reponse = bytearray()
            i = 0
            while i < len(data1):
                if data1[i] == 0xFF and i + 1 < len(data1):
                    cmd = data1[i + 1]
                    if cmd in (0xFB, 0xFC, 0xFD, 0xFE) and i + 2 < len(data1):
                        reponse += bytes([0xFF, 0xFE, data1[i + 2]])
                        i += 3
                    else:
                        i += 2
                else:
                    i += 1

            if reponse:
                s.send(bytes(reponse))
            time.sleep(0.6)

            try:
                data2 = self._lire(s)
                if data2:
                    return self._nettoyer(self._supprimer_iac(data2), 23)
            except Exception:
                pass
            return ""
        except Exception:
            return ""