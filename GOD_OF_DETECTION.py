import re
import urllib
import chromadb
from openai import OpenAI
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime
import os
import json
from statistics import mean
from tqdm import tqdm

# ---------------------------------------------------------------------
# LOAD ENVIRONMENT AND CLIENTS
# ---------------------------------------------------------------------
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

chroma_client = chromadb.PersistentClient(
    path=os.getenv("CHROMA_PATH", "/app/chroma_db_v2"))
collection = chroma_client.get_collection(name="attack_templates_v2")

# Paths
LOG_FILE_PATH   = os.getenv("LOG_FILE_PATH", "/app/master_log.txt")
RESULTS_FILE    = "/app/detection_results.json"
OFFSET_FILE     = "/app/detection_offset.json"   # tracks how far we've read

# ---------------------------------------------------------------------
# OFFSET HELPERS  (incremental processing)
# ---------------------------------------------------------------------
def load_offset() -> int:
    """Return byte offset of last processed position in the log file."""
    if os.path.exists(OFFSET_FILE):
        try:
            with open(OFFSET_FILE) as f:
                return json.load(f).get("offset", 0)
        except Exception:
            pass
    return 0


def save_offset(offset: int):
    with open(OFFSET_FILE, "w") as f:
        json.dump({"offset": offset, "updated": datetime.now().isoformat()}, f)


def load_existing_results() -> dict:
    """Load previous detection_results.json if it exists."""
    if os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------
# ATTACK TAXONOMY
# ---------------------------------------------------------------------
ATTACK_TAXONOMY = {
    "vulnerability_scanner": {"category": "recon",      "severity": 7,  "mitre": "T1595"},
    "directory_enumeration": {"category": "recon",      "severity": 5,  "mitre": "T1083"},
    "web_fingerprinting":    {"category": "recon",      "severity": 4,  "mitre": "T1592"},
    "sensitive_file_probe":  {"category": "recon",      "severity": 6,  "mitre": "T1083"},
    "backup_file_probe":     {"category": "recon",      "severity": 7,  "mitre": "T1083"},
    "config_file_probe":     {"category": "recon",      "severity": 8,  "mitre": "T1083"},
    "sql_injection":         {"category": "injection",  "severity": 9,  "mitre": "T1190"},
    "sql_injection_union":   {"category": "injection",  "severity": 9,  "mitre": "T1190"},
    "sql_injection_blind":   {"category": "injection",  "severity": 8,  "mitre": "T1190"},
    "sql_injection_time":    {"category": "injection",  "severity": 8,  "mitre": "T1190"},
    "sql_injection_error":   {"category": "injection",  "severity": 8,  "mitre": "T1190"},
    "xss_reflected":         {"category": "injection",  "severity": 7,  "mitre": "T1059.007"},
    "xss_stored":            {"category": "injection",  "severity": 8,  "mitre": "T1059.007"},
    "command_injection":     {"category": "injection",  "severity": 10, "mitre": "T1059"},
    "code_injection":        {"category": "injection",  "severity": 10, "mitre": "T1059"},
    "ldap_injection":        {"category": "injection",  "severity": 8,  "mitre": "T1190"},
    "xpath_injection":       {"category": "injection",  "severity": 7,  "mitre": "T1190"},
    "ssi_injection":         {"category": "injection",  "severity": 7,  "mitre": "T1190"},
    "path_traversal":        {"category": "file_access","severity": 8,  "mitre": "T1083"},
    "lfi":                   {"category": "file_access","severity": 9,  "mitre": "T1083"},
    "rfi":                   {"category": "file_access","severity": 10, "mitre": "T1105"},
    "brute_force_ssh":       {"category": "credential", "severity": 7,  "mitre": "T1110"},
    "brute_force_web":       {"category": "credential", "severity": 7,  "mitre": "T1110"},
    "LOGIN_PATTERNS":        {"category": "credential", "severity": 4,  "mitre": "T1110"},
    "credential_stuffing":   {"category": "credential", "severity": 8,  "mitre": "T1110.004"},
    "password_spray":        {"category": "credential", "severity": 7,  "mitre": "T1110.003"},
    "default_credentials":   {"category": "credential", "severity": 6,  "mitre": "T1078.001"},
    "admin_panel_probe":     {"category": "webapp",     "severity": 5,  "mitre": "T1190"},
    "cms_exploit":           {"category": "webapp",     "severity": 8,  "mitre": "T1190"},
    "webshell_upload":       {"category": "webapp",     "severity": 10, "mitre": "T1505.003"},
    "file_upload_bypass":    {"category": "webapp",     "severity": 9,  "mitre": "T1190"},
    "http_method_tampering": {"category": "protocol",   "severity": 5,  "mitre": "T1190"},
    "http_smuggling":        {"category": "protocol",   "severity": 8,  "mitre": "T1190"},
    "header_injection":      {"category": "protocol",   "severity": 6,  "mitre": "T1190"},
    "cisco_ios_probe":       {"category": "infrastructure","severity": 8,"mitre": "T1190"},
    "router_exploit":        {"category": "infrastructure","severity": 9,"mitre": "T1190"},
    "iis_exploit":           {"category": "infrastructure","severity": 8,"mitre": "T1190"},
    "apache_exploit":        {"category": "infrastructure","severity": 8,"mitre": "T1190"},
    "tomcat_exploit":        {"category": "infrastructure","severity": 8,"mitre": "T1190"},
    "asa_port_scan":         {"category": "recon",      "severity": 7,  "mitre": "T1046"},
    "asa_fw_bypass":         {"category": "evasion",    "severity": 8,  "mitre": "T1562"},
    "asa_vpn_bruteforce":    {"category": "credential", "severity": 8,  "mitre": "T1110"},
    "asa_connection_flood":  {"category": "dos",        "severity": 9,  "mitre": "T1498"},
    "asa_denied":            {"category": "firewall",   "severity": 6,  "mitre": "T1190"},
    "ddos":                  {"category": "dos",        "severity": 9,  "mitre": "T1498"},
    "normal":                {"category": "benign",     "severity": 0,  "mitre": None},
    "monitoring":            {"category": "benign",     "severity": 1,  "mitre": None},
}

# ---------------------------------------------------------------------
# ATTACK DETECTOR  (copy from original — unchanged)
# ---------------------------------------------------------------------
class AttackDetector:
    def __init__(self):
        self.patterns = self._compile_patterns()

    def _compile_patterns(self):
        return {
            "sql_injection_union": [
                re.compile(r"union(\s+|%20|\+)(all(\s+|%20|\+))?select", re.I),
            ],
            "sql_injection_blind": [
                re.compile(r"(and|or)(\s+|%20|\+)\d+(\s+|%20|\+)?(=|%3D)(\s+|%20|\+)?\d+", re.I),
                re.compile(r"'\s*(and|or)\s*'", re.I),
                re.compile(r"(--|%2d%2d|#|%23)", re.I),
            ],
            "sql_injection_time": [
                re.compile(r"sleep\s*\(|waitfor(\s+|%20|\+)delay|benchmark\s*\(|pg_sleep", re.I),
            ],
            "sql_injection_error": [
                re.compile(r"extractvalue|updatexml|floor\s*\(\s*rand|exp\s*\(\s*~", re.I),
            ],
            "sql_injection": [
                re.compile(r"information_schema|table_name|column_name", re.I),
                re.compile(r"(drop|insert|delete|update)(\s+|%20|\+)(table|into|from|set)", re.I),
                re.compile(r"(load_file|into(\s+|%20|\+)outfile|group_concat|concat)\s*\(", re.I),
                re.compile(r"@@version|char\s*\(\d+|0x[0-9a-f]{6,}", re.I),
                re.compile(r"(select|insert|update|delete|drop|union|where)\s*;", re.I),
                re.compile(r";\s*(select|insert|update|delete|drop|union)", re.I),
            ],
            "xss_reflected": [
                re.compile(r"<script[^>]*>", re.I),
                re.compile(r"</script>", re.I),
                re.compile(r"javascript\s*:", re.I),
                re.compile(r"on(error|load|click|mouse|focus)\s*=", re.I),
                re.compile(r"<img[^>]+onerror", re.I),
                re.compile(r"<svg[^>]+onload", re.I),
                re.compile(r"<iframe", re.I),
                re.compile(r"%3Cscript", re.I),
                re.compile(r"alert\s*\(", re.I),
                re.compile(r"document\.cookie", re.I),
                re.compile(r"document\.domain", re.I),
            ],
            "command_injection": [
                re.compile(r";\s*(ls|cat|pwd|id|whoami|uname)", re.I),
                re.compile(r"\|\s*(ls|cat|pwd|id|whoami)", re.I),
                re.compile(r"`[^`]+`"),
                re.compile(r"\$\([^)]+\)"),
                re.compile(r"system\s*\(", re.I),
                re.compile(r"exec\s*\(", re.I),
                re.compile(r"passthru\s*\(", re.I),
                re.compile(r"shell_exec", re.I),
                re.compile(r"popen\s*\(", re.I),
                re.compile(r"proc_open", re.I),
                re.compile(r"/bin/(bash|sh|zsh)", re.I),
                re.compile(r"cmd\.exe", re.I),
                re.compile(r"powershell", re.I),
            ],
            "path_traversal": [
                re.compile(r"\.\./"),
                re.compile(r"\.\.\\"),
                re.compile(r"%2e%2e[/%5c]", re.I),
                re.compile(r"\.\.%2f", re.I),
                re.compile(r"\.\.%5c", re.I),
                re.compile(r"%252e%252e", re.I),
            ],
            "lfi": [
                re.compile(r"/etc/passwd"),
                re.compile(r"/etc/shadow"),
                re.compile(r"/etc/hosts"),
                re.compile(r"/proc/self"),
                re.compile(r"/var/log"),
                re.compile(r"c:\\\\windows", re.I),
                re.compile(r"c:\\\\boot\.ini", re.I),
                re.compile(r"boot\.ini", re.I),
                re.compile(r"win\.ini", re.I),
            ],
            "rfi": [
                re.compile(r"=\s*https?://", re.I),
                re.compile(r"=\s*ftp://", re.I),
                re.compile(r"=\s*php://", re.I),
                re.compile(r"=\s*data://", re.I),
                re.compile(r"=\s*expect://", re.I),
                re.compile(r"=\s*file://", re.I),
                re.compile(r"rfiinc\.txt", re.I),
            ],
            "vulnerability_scanner": [
                re.compile(r"nikto", re.I),
                re.compile(r"nessus", re.I),
                re.compile(r"acunetix", re.I),
                re.compile(r"sqlmap", re.I),
                re.compile(r"wpscan", re.I),
                re.compile(r"openvas", re.I),
                re.compile(r"nmap", re.I),
                re.compile(r"masscan", re.I),
                re.compile(r"burpsuite", re.I),
                re.compile(r"zap/", re.I),
                re.compile(r"dirbuster", re.I),
                re.compile(r"gobuster", re.I),
                re.compile(r"ffuf", re.I),
                re.compile(r"wfuzz", re.I),
            ],
            "config_file_probe": [
                re.compile(r"\.env$", re.I),
                re.compile(r"\.git/config", re.I),
                re.compile(r"wp-config\.php", re.I),
                re.compile(r"config\.php", re.I),
                re.compile(r"settings\.php", re.I),
                re.compile(r"database\.yml", re.I),
                re.compile(r"\.htaccess", re.I),
                re.compile(r"\.htpasswd", re.I),
                re.compile(r"web\.config", re.I),
                re.compile(r"applicationhost\.config", re.I),
                re.compile(r"php\.ini", re.I),
                re.compile(r"my\.cnf", re.I),
            ],
            "backup_file_probe": [
                re.compile(r"\.(bak|backup|old|orig|copy|tmp|temp)$", re.I),
                re.compile(r"\.(sql|dump|gz|tar|zip|rar|7z)$", re.I),
                re.compile(r"~$"),
                re.compile(r"\.swp$"),
            ],
            "sensitive_file_probe": [
                re.compile(r"\.(pem|cer|crt|key|jks|p12|pfx)$", re.I),
                re.compile(r"id_rsa"),
                re.compile(r"\.ssh/"),
                re.compile(r"authorized_keys"),
                re.compile(r"\.aws/credentials", re.I),
                re.compile(r"\.docker/config", re.I),
            ],
            "admin_panel_probe": [
                re.compile(r"/admin[^a-z]", re.I),
                re.compile(r"/administrator", re.I),
                re.compile(r"/manager/", re.I),
                re.compile(r"/phpmyadmin", re.I),
                re.compile(r"/adminer", re.I),
                re.compile(r"/wp-admin", re.I),
                re.compile(r"/wp-login", re.I),
                re.compile(r"/controlpanel", re.I),
                re.compile(r"/cpanel", re.I),
                re.compile(r"/webadmin", re.I),
            ],
            "cms_exploit": [
                re.compile(r"xmlrpc\.php", re.I),
                re.compile(r"wp-content/plugins", re.I),
                re.compile(r"wp-includes", re.I),
                re.compile(r"components/com_", re.I),
                re.compile(r"index\.php\?option=com_", re.I),
            ],
            "brute_force_ssh": [
                re.compile(r"failed\s+password\s+for", re.I),
                re.compile(r"authentication\s+failure", re.I),
                re.compile(r"invalid\s+user", re.I),
                re.compile(r"sshd\[.*\]:\s+failed", re.I),
            ],
            "brute_force_web": [
                re.compile(r"login\s+failed", re.I),
                re.compile(r"auth.*failed", re.I),
                re.compile(r"access\s+denied", re.I),
                re.compile(r"401\s", re.I),
            ],
            "LOGIN_PATTERNS": [
                re.compile(r"/login", re.I),
                re.compile(r"/wp-login\.php", re.I),
                re.compile(r"/admin/login", re.I),
                re.compile(r"/signin", re.I),
            ],
            "cisco_ios_probe": [
                re.compile(r"/level/\d+/exec", re.I),
                re.compile(r"/exec/show", re.I),
                re.compile(r"show\s+config", re.I),
            ],
            "iis_exploit": [
                re.compile(r"\.ida$", re.I),
                re.compile(r"\.idq$", re.I),
                re.compile(r"_vti_bin", re.I),
            ],
            "tomcat_exploit": [
                re.compile(r"/manager/html", re.I),
                re.compile(r"/host-manager", re.I),
                re.compile(r"\.jsp%00", re.I),
            ],
            "apache_exploit": [
                re.compile(r"/server-status", re.I),
                re.compile(r"/server-info", re.I),
                re.compile(r"mod_status", re.I),
            ],
            "ssi_injection": [
                re.compile(r"<!--\s*#\s*(exec|include|echo)", re.I),
                re.compile(r"\.shtml", re.I),
            ],
            "http_method_tampering": [
                re.compile(r'"(TRACE|TRACK|DEBUG|OPTIONS|PROPFIND|PATCH)\s+/', re.I),
            ],
            "webshell_upload": [
                re.compile(r"c99\.php", re.I),
                re.compile(r"r57\.php", re.I),
                re.compile(r"shell\.php", re.I),
                re.compile(r"cmd\.php", re.I),
                re.compile(r"backdoor", re.I),
                re.compile(r"webshell", re.I),
            ],
            "directory_enumeration": [
                re.compile(r"/[a-zA-Z0-9]{6,10}\.(php|asp|aspx|jsp|txt|html?|xml|json|sql|bak)$"),
            ],
            "web_fingerprinting": [
                re.compile(r"robots\.txt", re.I),
                re.compile(r"sitemap\.xml", re.I),
                re.compile(r"phpinfo\.php", re.I),
                re.compile(r"info\.php", re.I),
            ],
            "asa_port_scan": [
                re.compile(r"%ASA-\d-733100", re.I),
                re.compile(r"port\s+scan", re.I),
                re.compile(r"scanning\s+detected", re.I),
            ],
            "asa_fw_bypass": [
                re.compile(r"%ASA-\d-106100", re.I),
                re.compile(r"access-list\s+\S+\s+denied", re.I),
            ],
            "asa_vpn_bruteforce": [
                re.compile(r"%ASA-\d-113005", re.I),
                re.compile(r"AAA\s+user\s+authentication\s+Rejected", re.I),
                re.compile(r"Invalid\s+password", re.I),
            ],
            "asa_connection_flood": [
                re.compile(r"%ASA-\d-419001", re.I),
                re.compile(r"half-open\s+TCP\s+connections", re.I),
                re.compile(r"SYN\s+flood", re.I),
            ],
            "asa_denied": [
                re.compile(r"%ASA-\d-106023", re.I),
                re.compile(r"Deny\s+\w+\s+src", re.I),
            ],
        }

    def detect(self, log: str) -> list:
        attacks = []
        for attack_name, patterns in self.patterns.items():
            for pat in patterns:
                if pat.search(log):
                    attacks.append(attack_name)
                    break
        return attacks if attacks else ["normal"]

    def get_severity(self, attacks) -> int:
        return max((ATTACK_TAXONOMY.get(a, {}).get("severity", 0) for a in attacks), default=0)

    def get_mitre_tactics(self, attacks) -> list:
        return list({ATTACK_TAXONOMY.get(a, {}).get("mitre") for a in attacks
                     if ATTACK_TAXONOMY.get(a, {}).get("mitre")})

    def get_categories(self, attacks) -> list:
        return list({ATTACK_TAXONOMY.get(a, {}).get("category", "unknown") for a in attacks})


# ---------------------------------------------------------------------
# LOG NORMALIZER  (copy from original)
# ---------------------------------------------------------------------
class LogNormalizer:
    def normalize(self, log: str) -> str:
        try:
            log = urllib.parse.unquote(log)
            log = urllib.parse.unquote(log)
        except Exception:
            pass
        log = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'IP_ADDR', log)
        log = re.sub(r'\b\d{4,}\b', 'NUM', log)
        log = re.sub(r'"[A-Z]+ ', '"METHOD ', log)
        return log.lower().strip()

    def extract_metadata(self, log: str) -> dict:
        meta = {"source_ip": "unknown", "timestamp": None,
                "http_method": None, "http_status": None, "url": None}
        ip_m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', log)
        if ip_m:
            meta["source_ip"] = ip_m.group(1)
        # Apache/nginx format
        ts_m = re.search(r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})', log)
        if ts_m:
            try:
                meta["timestamp"] = datetime.strptime(ts_m.group(1), "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                pass
        # Syslog format
        if not meta["timestamp"]:
            ts_m2 = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', log)
            if ts_m2:
                try:
                    meta["timestamp"] = datetime.strptime(
                        f"{ts_m2.group(1)} {datetime.now().year}", "%b %d %H:%M:%S %Y")
                except ValueError:
                    pass
        method_m = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\s', log)
        if method_m:
            meta["http_method"] = method_m.group(1)
        status_m = re.search(r'" (\d{3}) ', log)
        if status_m:
            meta["http_status"] = status_m.group(1)
        url_m = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ([^\s"]+)', log)
        if url_m:
            meta["url"] = url_m.group(1)
        return meta


# ---------------------------------------------------------------------
# CONTEXT ANALYZER  (copy from original)
# ---------------------------------------------------------------------
class ContextAnalyzer:
    def __init__(self):
        self.ip_events = defaultdict(lambda: {
            "attacks": [], "total_requests": 0, "max_severity": 0,
            "mitre_tactics": set(), "categories": set(),
            "sample_logs": [], "attack_counts": defaultdict(int),
            "http_methods": defaultdict(int), "http_statuses": defaultdict(int),
        })

    def update(self, ip: str, attacks: list, severity: int,
               mitre: list, categories: list, log: str,
               http_method: str = None, http_status: str = None):
        d = self.ip_events[ip]
        d["total_requests"] += 1
        d["max_severity"] = max(d["max_severity"], severity)
        d["mitre_tactics"].update(mitre)
        d["categories"].update(categories)
        for a in attacks:
            if a != "normal":
                d["attacks"].append(a)
                d["attack_counts"][a] += 1
        if http_method:
            d["http_methods"][http_method] += 1
        if http_status:
            d["http_statuses"][http_status] += 1
        if len(d["sample_logs"]) < 5 and severity > 3:
            d["sample_logs"].append(log[:200])

    def get_ip_threat_score(self, ip: str) -> int:
        d = self.ip_events[ip]
        score = 0
        score += min(d["total_requests"] // 10, 20)
        score += d["max_severity"] * 5
        unique_attacks = len(set(d["attacks"]))
        score += min(unique_attacks * 3, 15)
        high_sev = sum(1 for a in set(d["attacks"])
                       if ATTACK_TAXONOMY.get(a, {}).get("severity", 0) >= 8)
        score += high_sev * 5
        score += len(d["attack_chains_detected"] if hasattr(d, "attack_chains_detected") else []) * 5
        return min(score, 100)

    def detect_attack_chain(self, ip: str) -> list:
        attacks = set(self.ip_events[ip]["attacks"])
        chains = []
        if any(a in attacks for a in ["vulnerability_scanner","directory_enumeration","web_fingerprinting"]):
            if any(a in attacks for a in ["sql_injection","xss_reflected","command_injection","lfi"]):
                chains.append("Recon → Exploitation")
        if "brute_force_web" in attacks or "brute_force_ssh" in attacks:
            if any(a in attacks for a in ["webshell_upload","command_injection","lfi"]):
                chains.append("Credential Attack → Execution")
        if any(a in attacks for a in ["path_traversal","lfi"]):
            if any(a in attacks for a in ["webshell_upload","rfi"]):
                chains.append("File Access → Backdoor")
        if "asa_vpn_bruteforce" in attacks and "asa_connection_flood" in attacks:
            chains.append("VPN Brute + DoS (Cisco ASA)")
        return chains


# ---------------------------------------------------------------------
# SEMANTIC DETECTION
# ---------------------------------------------------------------------
def embed_text(text: str) -> list[float]:
    emb = client.embeddings.create(model="text-embedding-ada-002", input=text[:512])
    return emb.data[0].embedding


def semantic_detect(log, normalizer, top_k=5):
    normalized = normalizer.normalize(log)
    embedding  = embed_text(normalized)
    results    = collection.query(query_embeddings=[embedding], n_results=top_k)
    if not results["documents"]:
        return []
    matches = []
    for doc, meta, dist in zip(results["documents"][0],
                               results["metadatas"][0],
                               results["distances"][0]):
        matches.append({
            "template":     doc,
            "attack_types": [a.strip() for a in meta.get("attacks","").split(",") if a.strip()],
            "severity":     meta.get("severity", 0),
            "mitre":        [m.strip() for m in meta.get("mitre_tactics","").split(",") if m.strip()],
            "category":     meta.get("category","unknown"),
            "distance":     dist,
        })
    return matches


def interpret_semantic_hits(hits, dist_threshold=0.30):
    weighted = defaultdict(list)
    for h in hits:
        if h["distance"] <= dist_threshold:
            confidence = 1 - h["distance"]
            for atk in h["attack_types"]:
                if atk and atk != "normal":
                    weighted[atk].append(confidence)
    if not weighted:
        return [], 0, [], []
    avg_conf = {atk: mean(v) for atk, v in weighted.items()}
    best = max(avg_conf.items(), key=lambda x: x[1])
    attacks_sorted = sorted(avg_conf.items(), key=lambda x: x[1], reverse=True)
    main_attacks = [a for a, c in attacks_sorted if c > 0.4 * best[1]]
    severity_estimate = 0
    mitre_set = set()
    category_set = set()
    for h in hits:
        if h["distance"] <= dist_threshold:
            if any(a in h["attack_types"] for a in main_attacks):
                severity_estimate = max(severity_estimate, h["severity"])
                mitre_set.update(h["mitre"])
                category_set.add(h["category"])
    return main_attacks, severity_estimate, list(mitre_set), list(category_set)


# ---------------------------------------------------------------------
# COMBINED DETECTION
# ---------------------------------------------------------------------
def analyze_log(log, detector, normalizer, use_semantic=True):
    rule_attacks    = detector.detect(log)
    rule_severity   = detector.get_severity(rule_attacks)
    rule_mitre      = detector.get_mitre_tactics(rule_attacks)
    rule_categories = detector.get_categories(rule_attacks)
    sem_attacks = sem_severity = 0
    sem_mitre = sem_categories = []
    if use_semantic and rule_attacks == ["normal"]:
        hits = semantic_detect(log, normalizer)
        sem_attacks, sem_severity, sem_mitre, sem_categories = interpret_semantic_hits(hits)
    if sem_attacks:
        final_attacks    = list(set(rule_attacks + sem_attacks) - {"normal"}) or ["normal"]
        final_severity   = max(rule_severity, sem_severity)
        final_mitre      = list(set(rule_mitre + sem_mitre))
        final_categories = list(set(rule_categories + sem_categories))
    else:
        final_attacks    = rule_attacks
        final_severity   = rule_severity
        final_mitre      = rule_mitre
        final_categories = rule_categories
    metadata = normalizer.extract_metadata(log)
    return {
        "attacks":     final_attacks,
        "severity":    final_severity,
        "mitre":       final_mitre,
        "categories":  final_categories,
        "source_ip":   metadata["source_ip"],
        "http_method": metadata["http_method"],
        "http_status": metadata["http_status"],
        "timestamp":   metadata["timestamp"],
    }


# ---------------------------------------------------------------------
# MERGE helpers  (for incremental update)
# ---------------------------------------------------------------------
def merge_results(existing: dict, new_data: dict) -> dict:
    """
    Merge a fresh partial-run result into the existing full result.
    Counts are additive; per-IP data is merged by IP key.
    """
    if not existing:
        return new_data

    merged = dict(existing)
    merged["generated_at"]  = new_data["generated_at"]
    merged["total_logs"]    += new_data["total_logs"]
    merged["unique_ips"]     = new_data["unique_ips"]   # refreshed each run
    merged["log_end"]        = new_data.get("log_end") or existing.get("log_end")

    # Merge attack_stats (additive)
    for attack, count in new_data.get("attack_stats", {}).items():
        merged["attack_stats"][attack] = merged["attack_stats"].get(attack, 0) + count

    # Merge severity_distribution (additive)
    for sev, count in new_data.get("severity_distribution", {}).items():
        merged["severity_distribution"][sev] = \
            merged["severity_distribution"].get(sev, 0) + count

    # Merge suspicious_ips by IP address
    existing_ip_map = {d["ip"]: d for d in merged.get("suspicious_ips", [])}
    for ip_data in new_data.get("suspicious_ips", []):
        ip = ip_data["ip"]
        if ip in existing_ip_map:
            e = existing_ip_map[ip]
            e["total_requests"] += ip_data["total_requests"]
            e["max_severity"]    = max(e["max_severity"], ip_data["max_severity"])
            e["threat_score"]    = max(e["threat_score"], ip_data["threat_score"])
            for atk, cnt in ip_data.get("attacks", {}).items():
                e["attacks"][atk] = e["attacks"].get(atk, 0) + cnt
            e["mitre_tactics"]  = list(set(e["mitre_tactics"]) | set(ip_data["mitre_tactics"]))
            e["categories"]     = list(set(e["categories"])    | set(ip_data["categories"]))
            e["attack_chains"]  = list(set(e["attack_chains"]) | set(ip_data["attack_chains"]))
            # keep up to 5 sample logs
            e["sample_logs"] = (e["sample_logs"] + ip_data.get("sample_logs", []))[:5]
            e["last_seen"]   = ip_data.get("last_seen") or e.get("last_seen")
        else:
            existing_ip_map[ip] = ip_data

    # Re-sort by threat_score
    merged["suspicious_ips"]       = sorted(existing_ip_map.values(),
                                            key=lambda x: x["threat_score"], reverse=True)
    merged["suspicious_ips_count"] = len(merged["suspicious_ips"])
    return merged


# ---------------------------------------------------------------------
# MAIN  (incremental)
# ---------------------------------------------------------------------
def main():
    print("=" * 60)
    print("🛡️  GOD OF DETECTION  (incremental mode)")
    print("=" * 60)

    if not os.path.exists(LOG_FILE_PATH):
        print(f"❌ Log file not found: {LOG_FILE_PATH}")
        return

    # ── Find how many bytes we already processed ───────────────────────
    start_offset  = load_offset()
    current_size  = os.path.getsize(LOG_FILE_PATH)

    if start_offset >= current_size:
        print(f"✅ No new data since last run (offset {start_offset} = size {current_size})")
        return

    # ── Read ONLY the new bytes ────────────────────────────────────────
    with open(LOG_FILE_PATH, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(start_offset)
        new_text = f.read()
        new_offset = f.tell()

    logs = [line.strip() for line in new_text.splitlines() if line.strip()]

    if not logs:
        print("✅ No new log lines.")
        save_offset(new_offset)
        return

    print(f"📊 Processing {len(logs)} NEW log lines "
          f"(bytes {start_offset} → {new_offset})…\n")

    # ── Init components ────────────────────────────────────────────────
    detector         = AttackDetector()
    normalizer       = LogNormalizer()
    context_analyzer = ContextAnalyzer()

    ip_events      = defaultdict(lambda: {
        "attacks": [], "total_requests": 0, "max_severity": 0,
        "mitre_tactics": set(), "categories": set(),
        "sample_logs": [], "attack_counts": defaultdict(int),
        "http_methods": defaultdict(int), "http_statuses": defaultdict(int),
    })
    attack_stats   = defaultdict(int)
    severity_stats = defaultdict(int)
    ip_timestamps  = defaultdict(list)
    all_log_timestamps = []

    DDOS_THRESHOLD = 50
    DDOS_WINDOW    = 60

    for log in tqdm(logs, desc="Processing"):
        result   = analyze_log(log, detector, normalizer, use_semantic=True)
        metadata = normalizer.extract_metadata(log)
        ts       = metadata.get("timestamp")
        if ts:
            all_log_timestamps.append(ts)

        ip = result["source_ip"]

        # DDoS detection
        if ts and ip != "unknown":
            ip_timestamps[ip].append(ts)
            ip_timestamps[ip] = [
                t for t in ip_timestamps[ip]
                if (ts - t).total_seconds() <= DDOS_WINDOW
            ]
            if len(ip_timestamps[ip]) >= DDOS_THRESHOLD:
                if "ddos" not in result["attacks"]:
                    result["attacks"].append("ddos")
                result["severity"] = max(result["severity"], 9)

        # Login brute-force escalation
        if "LOGIN_PATTERNS" in result["attacks"]:
            count = ip_events[ip]["attack_counts"].get("LOGIN_PATTERNS", 0) + 1
            if count > 20:
                result["severity"] = 9
                result["attacks"] = [
                    "brute_force_web" if a == "LOGIN_PATTERNS" else a
                    for a in result["attacks"]]
            elif count > 5:
                result["severity"] = 6

        # Update ip_events
        ip_events[ip]["total_requests"] += 1
        ip_events[ip]["max_severity"]    = max(ip_events[ip]["max_severity"], result["severity"])
        ip_events[ip]["mitre_tactics"].update(result["mitre"])
        ip_events[ip]["categories"].update(result["categories"])
        for a in result["attacks"]:
            ip_events[ip]["attacks"].append(a)
            ip_events[ip]["attack_counts"][a] += 1
            attack_stats[a] += 1
        if result["http_method"]:
            ip_events[ip]["http_methods"][result["http_method"]] += 1
        if result["http_status"]:
            ip_events[ip]["http_statuses"][result["http_status"]] += 1
        if len(ip_events[ip]["sample_logs"]) < 5 and result["severity"] > 3:
            ip_events[ip]["sample_logs"].append(log[:200])
        severity_stats[result["severity"]] += 1
        context_analyzer.ip_events[ip] = ip_events[ip]

    # ── Build partial result ───────────────────────────────────────────
    all_suspicious = []
    for ip, data in ip_events.items():
        if ip == "unknown":
            continue
        attacks = [a for a in data["attacks"] if a != "normal"]
        if attacks:
            threat_score   = context_analyzer.get_ip_threat_score(ip)
            attack_chains  = context_analyzer.detect_attack_chain(ip)
            all_suspicious.append((ip, data, threat_score, attack_chains))
    all_suspicious.sort(key=lambda x: x[2], reverse=True)

    # ── Build timestamps for per-IP ────────────────────────────────────
    ip_ts_cache = defaultdict(list)
    for log in logs:
        metadata = normalizer.extract_metadata(log)
        ip = metadata.get("source_ip", "unknown")
        ts = metadata.get("timestamp")
        if ts and ip != "unknown":
            ip_ts_cache[ip].append(ts)

    partial = {
        "generated_at": datetime.now().isoformat(),
        "log_start":    min(all_log_timestamps).isoformat() if all_log_timestamps else None,
        "log_end":      max(all_log_timestamps).isoformat() if all_log_timestamps else None,
        "total_logs":   len(logs),
        "unique_ips":   len(ip_events),
        "suspicious_ips_count": len(all_suspicious),
        "attack_stats": dict(attack_stats),
        "severity_distribution": {str(k): v for k, v in severity_stats.items()},
        "suspicious_ips": [],
    }

    for ip, data, threat_score, attack_chains in all_suspicious:
        ts_list = ip_ts_cache.get(ip, [])
        partial["suspicious_ips"].append({
            "ip":             ip,
            "threat_score":   threat_score,
            "total_requests": data["total_requests"],
            "max_severity":   data["max_severity"],
            "attacks":        dict(data["attack_counts"]),
            "mitre_tactics":  list(data["mitre_tactics"]),
            "categories":     list(data["categories"]),
            "attack_chains":  attack_chains or [],
            "http_methods":   dict(data["http_methods"]),
            "http_statuses":  dict(data["http_statuses"]),
            "sample_logs":    data["sample_logs"][:3],
            "first_seen":     min(ts_list).isoformat() if ts_list else None,
            "last_seen":      max(ts_list).isoformat() if ts_list else None,
        })

    # ── Merge with existing results ────────────────────────────────────
    existing = load_existing_results()
    final    = merge_results(existing, partial)

    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(final, f, ensure_ascii=False, indent=2)

    # Save new offset so next run starts from here
    save_offset(new_offset)

    print(f"\n✅ Done. Processed {len(logs)} new lines.")
    print(f"   Cumulative: {final['total_logs']} logs | "
          f"{final['suspicious_ips_count']} suspicious IPs")
    print(f"   Results → {RESULTS_FILE}")
    print(f"   Next run will start at byte {new_offset}\n")


if __name__ == "__main__":
    main()
