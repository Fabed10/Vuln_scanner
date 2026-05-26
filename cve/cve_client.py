import urllib.request, urllib.parse, urllib.error, json, time
from cve.config import NVD_API_KEY, NVD_BASE_URL, CVE_RESULTS_LIMIT, REQUEST_TIMEOUT
from utils.colors import print_error, print_warning

class CVEClient:
    def __init__(self):
        self.base_url   = NVD_BASE_URL
        self.api_key    = NVD_API_KEY.strip() if NVD_API_KEY else None
        self._delay     = 0.6 if self.api_key else 6.0
        self._last_call = 0.0

    def is_available(self): return True

    def _get(self, params):
        elapsed = time.time() - self._last_call
        if elapsed < self._delay: time.sleep(self._delay - elapsed)
        self._last_call = time.time()
        url = self.base_url + "?" + urllib.parse.urlencode({k:v for k,v in params.items() if v})
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        if self.api_key: req.add_header("apiKey", self.api_key)
        # APRÈS
        retries = 3
        for attempt in range(1, retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
                    return json.loads(r.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code == 403: print_warning("NVD – rate limit ou clé invalide."); break
                elif e.code == 404: break
                else:
                    print_error(f"NVD HTTP {e.code} (tentative {attempt}/{retries})")
                    if attempt < retries: time.sleep(2 * attempt)
            except urllib.error.URLError as e:
                print_error(f"NVD connexion: {e.reason} (tentative {attempt}/{retries})")
                if attempt < retries: time.sleep(2 * attempt)
            except Exception as e:
                print_error(f"NVD erreur: {e} (tentative {attempt}/{retries})")
                if attempt < retries: time.sleep(2 * attempt)
        return None

    def search_cves(self, term, limit=CVE_RESULTS_LIMIT):
        return self._extract(self._get({"keywordSearch": term, "resultsPerPage": limit}))

    def get_cve_by_id(self, cve_id):
        items = self._extract(self._get({"cveId": cve_id}))
        return items[0] if items else None

    def search_cves_by_severity(self, sev, limit=CVE_RESULTS_LIMIT):
        return self._extract(self._get({"cvssV3Severity": sev.upper(), "resultsPerPage": limit}))

    @staticmethod
    def _extract(data): return (data or {}).get("vulnerabilities", [])
