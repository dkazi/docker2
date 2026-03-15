import os
import re
import urllib

# MUST set before importing chromadb — otherwise telemetry init runs first
os.environ["ANONYMIZED_TELEMETRY"] = "false"
os.environ["CHROMA_TELEMETRY"]     = "false"

import chromadb
from openai import OpenAI
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime
from statistics import mean
from tqdm import tqdm

# ---------------------------------------------------------------------
# LOAD ENVIRONMENT AND CLIENTS
# ---------------------------------------------------------------------
load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

chroma_client = chromadb.PersistentClient(
    path=os.getenv("CHROMA_PATH", "/app/chroma_db_v2"),
    settings=chromadb.Settings(anonymized_telemetry=False))
collection = chroma_client.get_collection(name="attack_templates_v2")

# ---------------------------------------------------------------------
# ATTACK TAXONOMY (ίδιο με το training)
# ---------------------------------------------------------------------
ATTACK_TAXONOMY = {
    # Reconnaissance
    "vulnerability_scanner": {"category": "recon", "severity": 7, "mitre": "T1595"},
    "directory_enumeration": {"category": "recon", "severity": 5, "mitre": "T1083"},
    "web_fingerprinting": {"category": "recon", "severity": 4, "mitre": "T1592"},
    "sensitive_file_probe": {"category": "recon", "severity": 6, "mitre": "T1083"},
    "backup_file_probe": {"category": "recon", "severity": 7, "mitre": "T1083"},
    "config_file_probe": {"category": "recon", "severity": 8, "mitre": "T1083"},

    # Injection Attacks
    "sql_injection": {"category": "injection", "severity": 9, "mitre": "T1190"},
    "sql_injection_union": {"category": "injection", "severity": 9, "mitre": "T1190"},
    "sql_injection_blind": {"category": "injection", "severity": 8, "mitre": "T1190"},
    "sql_injection_time": {"category": "injection", "severity": 8, "mitre": "T1190"},
    "sql_injection_error": {"category": "injection", "severity": 8, "mitre": "T1190"},
    "xss_reflected": {"category": "injection", "severity": 7, "mitre": "T1059.007"},
    "xss_stored": {"category": "injection", "severity": 8, "mitre": "T1059.007"},
    "command_injection": {"category": "injection", "severity": 10, "mitre": "T1059"},
    "code_injection": {"category": "injection", "severity": 10, "mitre": "T1059"},
    "ldap_injection": {"category": "injection", "severity": 8, "mitre": "T1190"},
    "xpath_injection": {"category": "injection", "severity": 7, "mitre": "T1190"},
    "ssi_injection": {"category": "injection", "severity": 7, "mitre": "T1190"},

    # Path Traversal & LFI/RFI
    "path_traversal": {"category": "file_access", "severity": 8, "mitre": "T1083"},
    "lfi": {"category": "file_access", "severity": 9, "mitre": "T1083"},
    "rfi": {"category": "file_access", "severity": 10, "mitre": "T1105"},

    # Authentication Attacks
    "brute_force_ssh": {"category": "credential", "severity": 7, "mitre": "T1110"},
    "brute_force_web": {"category": "credential", "severity": 7, "mitre": "T1110"},
    "LOGIN_PATTERNS": {"category": "credential", "severity": 4, "mitre": "T1110"},
    "credential_stuffing": {"category": "credential", "severity": 8, "mitre": "T1110.004"},
    "password_spray": {"category": "credential", "severity": 7, "mitre": "T1110.003"},
    "default_credentials": {"category": "credential", "severity": 6, "mitre": "T1078.001"},

    # Web Application Attacks
    "admin_panel_probe": {"category": "webapp", "severity": 5, "mitre": "T1190"},
    "cms_exploit": {"category": "webapp", "severity": 8, "mitre": "T1190"},
    "webshell_upload": {"category": "webapp", "severity": 10, "mitre": "T1505.003"},
    "file_upload_bypass": {"category": "webapp", "severity": 9, "mitre": "T1190"},

    # Protocol/Server Attacks
    "http_method_tampering": {"category": "protocol", "severity": 5, "mitre": "T1190"},
    "http_smuggling": {"category": "protocol", "severity": 8, "mitre": "T1190"},
    "header_injection": {"category": "protocol", "severity": 6, "mitre": "T1190"},

    # Infrastructure
    "cisco_ios_probe": {"category": "infrastructure", "severity": 8, "mitre": "T1190"},
    "router_exploit": {"category": "infrastructure", "severity": 9, "mitre": "T1190"},
    "iis_exploit": {"category": "infrastructure", "severity": 8, "mitre": "T1190"},
    "apache_exploit": {"category": "infrastructure", "severity": 8, "mitre": "T1190"},
    "tomcat_exploit": {"category": "infrastructure", "severity": 8, "mitre": "T1190"},

    # Cisco ASA Firewall
    "asa_port_scan":        {"category": "recon",      "severity": 7, "mitre": "T1046"},
    "asa_fw_bypass":        {"category": "evasion",    "severity": 8, "mitre": "T1562"},
    "asa_vpn_bruteforce":   {"category": "credential", "severity": 8, "mitre": "T1110"},
    "asa_connection_flood": {"category": "dos",        "severity": 9, "mitre": "T1498"},
    "asa_denied":           {"category": "firewall",   "severity": 6, "mitre": "T1190"},

    # DoS/DDoS
    "ddos": {"category": "dos", "severity": 9, "mitre": "T1498"},

    # Benign
    "normal": {"category": "benign", "severity": 0, "mitre": None},
    "monitoring": {"category": "benign", "severity": 1, "mitre": None},
}


# ---------------------------------------------------------------------
# ATTACK DETECTOR (ίδιο με το training)
# ---------------------------------------------------------------------
class AttackDetector:
    def __init__(self):
        self.patterns = self._compile_patterns()

    def _compile_patterns(self):
        return {
            # SQL Injection - Granular
            "sql_injection_union": [
                # Καλύπτει union select με κενά, +, ή %20
                re.compile(r"union(\s+|%20|\+)(all(\s+|%20|\+))?select", re.I),
            ],
            "sql_injection_blind": [
                # Πιάνει το or 1=1, or 1%3D1, ή or 1 = 1
                re.compile(r"(and|or)(\s+|%20|\+)\d+(\s+|%20|\+)?(=|%3D)(\s+|%20|\+)?\d+", re.I),
                re.compile(r"'\s*(and|or)\s*'", re.I),
                # Πιάνει το -- (comment) ακόμα και αν είναι encoded ως %2D%2D
                re.compile(r"(--|%2d%2d|#|%23)", re.I),
            ],
            "sql_injection_time": [
                re.compile(r"sleep\s*\(|waitfor(\s+|%20|\+)delay|benchmark\s*\(|pg_sleep", re.I),
            ],
            "sql_injection_error": [
                re.compile(r"extractvalue|updatexml|floor\s*\(\s*rand|exp\s*\(\s*~", re.I),
            ],
            "sql_injection": [
                # Πολύ σημαντικό: Πιάνει την πρόσβαση σε metadata
                re.compile(r"information_schema|table_name|column_name", re.I),
                re.compile(r"(drop|insert|delete|update)(\s+|%20|\+)(table|into|from|set)", re.I),
                re.compile(r"(load_file|into(\s+|%20|\+)outfile|group_concat|concat)\s*\(", re.I),
                re.compile(r"@@version|char\s*\(\d+|0x[0-9a-f]{6,}", re.I),
                # Πιάνει semicolons μόνο με SQL context (Fix 1: αποφυγή false positives σε path traversal)
                re.compile(r"(select|insert|update|delete|drop|union|where)\s*;", re.I),
                re.compile(r";\s*(select|insert|update|delete|drop|union)", re.I),
            ],

            # XSS
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

            # Command Injection
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

            # Path Traversal / LFI
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

            # Vulnerability Scanners
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

            # Sensitive File Probing
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
                re.compile(r"#.*#$"),
                re.compile(r"\.(war|ear|jar)$", re.I),
            ],
            "sensitive_file_probe": [
                re.compile(r"\.(pem|cer|crt|key|jks|p12|pfx)$", re.I),
                re.compile(r"id_rsa"),
                re.compile(r"\.ssh/"),
                re.compile(r"authorized_keys"),
                re.compile(r"\.aws/credentials", re.I),
                re.compile(r"\.docker/config", re.I),
            ],

            # Admin Panel Probing
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
                re.compile(r"/siteadmin", re.I),
            ],

            # CMS Exploits
            "cms_exploit": [
                re.compile(r"xmlrpc\.php", re.I),
                re.compile(r"wp-content/plugins", re.I),
                re.compile(r"wp-includes", re.I),
                re.compile(r"components/com_", re.I),
                re.compile(r"index\.php\?option=com_", re.I),
                re.compile(r"modules\.php\?name=", re.I),
                re.compile(r"postnuke", re.I),
                re.compile(r"phpnuke", re.I),
                re.compile(r"phpbb", re.I),
                re.compile(r"joomla", re.I),
                re.compile(r"drupal", re.I),
            ],

            # Authentication Attacks
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
                re.compile(r"/user/login", re.I),
            ],

            # Infrastructure Attacks
            "cisco_ios_probe": [
                re.compile(r"/level/\d+/exec", re.I),
                re.compile(r"/exec/show", re.I),
                re.compile(r"show\s+config", re.I),
                re.compile(r"show\s+running", re.I),
                re.compile(r"show\s+version", re.I),
            ],
            "iis_exploit": [
                re.compile(r"\.ida$", re.I),
                re.compile(r"\.idq$", re.I),
                re.compile(r"\.printer$", re.I),
                re.compile(r"\.htr$", re.I),
                re.compile(r"_vti_bin", re.I),
                re.compile(r"_vti_pvt", re.I),
                re.compile(r"msadc/", re.I),
            ],
            "tomcat_exploit": [
                re.compile(r"/manager/html", re.I),
                re.compile(r"/host-manager", re.I),
                re.compile(r"/jk-manager", re.I),
                re.compile(r"/jk-status", re.I),
                re.compile(r"\.jsp%00", re.I),
                re.compile(r"/invoker/", re.I),
            ],
            "apache_exploit": [
                re.compile(r"/server-status", re.I),
                re.compile(r"/server-info", re.I),
                re.compile(r"\.htaccess", re.I),
                re.compile(r"mod_status", re.I),
            ],

            # SSI Injection
            "ssi_injection": [
                re.compile(r"<!--\s*#\s*(exec|include|echo)", re.I),
                re.compile(r"\.shtml", re.I),
                re.compile(r"\.stm", re.I),
            ],

            # HTTP Method Tampering
            "http_method_tampering": [
                re.compile(r'"(TRACE|TRACK|DEBUG|OPTIONS|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|PATCH)\s+/',
                           re.I),
            ],

            # Webshell Indicators
            "webshell_upload": [
                re.compile(r"c99\.php", re.I),
                re.compile(r"r57\.php", re.I),
                re.compile(r"shell\.php", re.I),
                re.compile(r"cmd\.php", re.I),
                re.compile(r"backdoor", re.I),
                re.compile(r"webshell", re.I),
                re.compile(r"FilesMan", re.I),
            ],

            # Directory Enumeration
            "directory_enumeration": [
                re.compile(r"/[a-zA-Z0-9]{6,10}\.(php|asp|aspx|jsp|txt|html?|xml|json|sql|bak)$"),
            ],

            # Web Fingerprinting
            "web_fingerprinting": [
                re.compile(r"robots\.txt", re.I),
                re.compile(r"sitemap\.xml", re.I),
                re.compile(r"crossdomain\.xml", re.I),
                re.compile(r"security\.txt", re.I),
                re.compile(r"\.well-known", re.I),
                re.compile(r"phpinfo\.php", re.I),
                re.compile(r"info\.php", re.I),
                re.compile(r"test\.php", re.I),
                re.compile(r"\?=PHP[A-Z0-9]+-", re.I),
            ],

            # -----------------------------------------------------------------
            # Cisco ASA Firewall Patterns
            # -----------------------------------------------------------------
            "asa_port_scan": [
                re.compile(r"%ASA-\d-733100", re.I),
                re.compile(r"%ASA-\d-733101", re.I),
                re.compile(r"port\s+scan", re.I),
                re.compile(r"scanning\s+detected", re.I),
            ],
            "asa_fw_bypass": [
                re.compile(r"%ASA-\d-106100", re.I),
                re.compile(r"%ASA-\d-710003", re.I),
                re.compile(r"%ASA-\d-710005", re.I),
                re.compile(r"access-list\s+\S+\s+denied", re.I),
                re.compile(r"deny\s+\w+\s+src\s+outside", re.I),
            ],
            "asa_vpn_bruteforce": [
                re.compile(r"%ASA-\d-113005", re.I),
                re.compile(r"%ASA-\d-113006", re.I),
                re.compile(r"%ASA-\d-113015", re.I),
                re.compile(r"%ASA-\d-113021", re.I),
                re.compile(r"AAA\s+user\s+authentication\s+Rejected", re.I),
                re.compile(r"locked\s+out\s+exceeding\s+maximum\s+failed", re.I),
                re.compile(r"Invalid\s+password", re.I),
            ],
            "asa_connection_flood": [
                re.compile(r"%ASA-\d-419001", re.I),
                re.compile(r"%ASA-\d-419002", re.I),
                re.compile(r"half-open\s+TCP\s+connections", re.I),
                re.compile(r"embryonic\s+conn\s+limit\s+exceeded", re.I),
                re.compile(r"SYN\s+flood", re.I),
                re.compile(r"connection\s+flood\s+detected", re.I),
            ],
            "asa_denied": [
                re.compile(r"%ASA-\d-106023", re.I),
                re.compile(r"%ASA-\d-106001", re.I),
                re.compile(r"%ASA-\d-106006", re.I),
                re.compile(r"%ASA-\d-106007", re.I),
                re.compile(r"Inbound\s+\w+\s+connection\s+denied", re.I),
            ],
        }

    def detect(self, log):
        """Detect all attack types in a log entry"""
        attacks = []

        # 1. ΚΑΘΑΡΙΣΜΟΣ: Μετατρέπουμε το log σε "ανθρώπινη" μορφή
        # π.χ. το %20 γίνεται κενό, το %27 γίνεται ' κτλ.
        decoded_log = urllib.parse.unquote(log)

        # 2. ΑΝΑΛΥΣΗ: Τρέχουμε τα patterns πάνω στο DECODED log
        for attack_type, patterns in self.patterns.items():
            for pattern in patterns:
                # Χρησιμοποιούμε το decoded_log αντί για το σκέτο log
                if pattern.search(decoded_log):
                    attacks.append(attack_type)
                    break

                    # Το υπόλοιπο κομμάτι παραμένει ως έχει
        attacks = self._deduplicate_attacks(attacks)

        if not attacks:
            if " 404 " in log:  # Εδώ το log είναι οκ, γιατί το " 404 " δεν είναι encoded
                attacks.append("directory_enumeration")
            else:
                attacks.append("normal")

        return attacks

    def _deduplicate_attacks(self, attacks):
        """Remove generic attacks if specific ones are present"""
        specific_map = {
            "sql_injection": ["sql_injection_union", "sql_injection_blind",
                              "sql_injection_time", "sql_injection_error"],
        }

        # Fix 2: Αν ανιχνευτεί path traversal/lfi/rfi, αφαίρεσε generic sql_injection
        # που ενεργοποιήθηκε λάθος από semicolon
        file_access = {"path_traversal", "lfi", "rfi"}
        if any(a in attacks for a in file_access):
            attacks = [a for a in attacks if a not in
                       ("sql_injection", "sql_injection_blind")]

        # Fix 3: Αν ανιχνευτεί injection, το LOGIN_PATTERNS είναι noise
        injection_types = {
            "sql_injection", "sql_injection_blind", "sql_injection_union",
            "sql_injection_time", "sql_injection_error",
            "command_injection", "code_injection"
        }
        if any(a in attacks for a in injection_types):
            attacks = [a for a in attacks if a != "LOGIN_PATTERNS"]

        # Fix 4: Αν υπάρχει LOGIN_PATTERNS ή brute_force, το /admin/login
        # δεν είναι admin probe — είναι credential attack
        cred_types = {"LOGIN_PATTERNS", "brute_force_web", "brute_force_ssh"}
        if any(a in attacks for a in cred_types):
            attacks = [a for a in attacks if a != "admin_panel_probe"]

        # Fix 5: asa_connection_flood είναι πιο specific από asa_port_scan
        if "asa_connection_flood" in attacks:
            attacks = [a for a in attacks if a != "asa_port_scan"]

        # Fix 6: asa_fw_bypass είναι πιο specific από asa_denied
        if "asa_fw_bypass" in attacks:
            attacks = [a for a in attacks if a != "asa_denied"]

        result = attacks.copy()
        for generic, specifics in specific_map.items():
            if generic in result:
                if any(s in result for s in specifics):
                    result.remove(generic)

        return list(set(result))

    def get_severity(self, attacks):
        """Calculate max severity from attack list"""
        max_severity = 0
        for attack in attacks:
            if attack in ATTACK_TAXONOMY:
                max_severity = max(max_severity, ATTACK_TAXONOMY[attack]["severity"])
        return max_severity

    def get_mitre_tactics(self, attacks):
        """Get MITRE ATT&CK tactics"""
        tactics = set()
        for attack in attacks:
            if attack in ATTACK_TAXONOMY and ATTACK_TAXONOMY[attack]["mitre"]:
                tactics.add(ATTACK_TAXONOMY[attack]["mitre"])
        return list(tactics)

    def get_categories(self, attacks):
        """Get attack categories"""
        categories = set()
        for attack in attacks:
            if attack in ATTACK_TAXONOMY:
                categories.add(ATTACK_TAXONOMY[attack]["category"])
        return list(categories)


# ---------------------------------------------------------------------
# LOG NORMALIZER (ίδιο με το training)
# ---------------------------------------------------------------------
class LogNormalizer:
    def __init__(self):
        self.ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        self.timestamp_patterns = [
            re.compile(r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]'),
            re.compile(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}'),
            re.compile(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'),
        ]
        self.hex_pattern = re.compile(r'0x[0-9a-fA-F]+')
        self.random_string = re.compile(r'/[a-zA-Z0-9]{8,12}\.')
        self.port_pattern = re.compile(r'port\s+\d+')
        self.pid_pattern = re.compile(r'\[\d+\]')
        self.session_pattern = re.compile(r'session\s+\d+', re.I)

    def normalize(self, log):
        """Normalize log for better template extraction"""
        normalized = log
        normalized = self.ip_pattern.sub('<IP>', normalized)
        for pattern in self.timestamp_patterns:
            normalized = pattern.sub('<TIMESTAMP>', normalized)
        normalized = self.hex_pattern.sub('<HEX>', normalized)
        normalized = self.random_string.sub('/<RANDOM_FILE>.', normalized)
        normalized = self.port_pattern.sub('port <PORT>', normalized)
        normalized = self.pid_pattern.sub('[<PID>]', normalized)
        normalized = self.session_pattern.sub('session <SESSION>', normalized)
        return normalized

    def extract_metadata(self, log):
        """Extract useful metadata from log — υποστηρίζει Apache και Cisco ASA format"""
        metadata = {}

        # --- Cisco ASA format detection ---
        is_cisco = bool(re.search(r'%ASA-\d-\d+', log, re.I))

        if is_cisco:
            cisco_ip = re.search(
                r'(?:src\s+\w+:|from\s+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log, re.I
            )
            metadata['source_ip'] = cisco_ip.group(1) if cisco_ip else "unknown"
            metadata['http_status'] = None
            metadata['http_method'] = None
            metadata['url_path'] = None
            metadata['user_agent'] = None

            # Cisco timestamp: Jun 01 2024 10:00:01
            ts_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})', log)
            if ts_match:
                try:
                    from datetime import datetime as dt
                    metadata['timestamp'] = dt.strptime(ts_match.group(1), "%b %d %Y %H:%M:%S")
                except ValueError:
                    metadata['timestamp'] = None
            else:
                metadata['timestamp'] = None

        else:
            # --- Apache / standard format ---
            ip_match = self.ip_pattern.search(log)
            metadata['source_ip'] = ip_match.group() if ip_match else "unknown"

            status_match = re.search(r'"\s+(\d{3})\s+', log)
            metadata['http_status'] = int(status_match.group(1)) if status_match else None

            method_match = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+', log)
            metadata['http_method'] = method_match.group(1) if method_match else None

            url_match = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s]+)', log)
            metadata['url_path'] = url_match.group(1) if url_match else None

            ua_match = re.search(r'"([^"]*(?:Mozilla|curl|wget|python|scanner)[^"]*)"', log, re.I)
            metadata['user_agent'] = ua_match.group(1) if ua_match else None

            # Apache timestamp
            ts_match = re.search(r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})', log)
            if ts_match:
                try:
                    from datetime import datetime as dt
                    metadata['timestamp'] = dt.strptime(ts_match.group(1), "%d/%b/%Y:%H:%M:%S")
                except ValueError:
                    metadata['timestamp'] = None
            else:
                metadata['timestamp'] = None

        return metadata


# ---------------------------------------------------------------------
# ATTACK CONTEXT ANALYZER
# ---------------------------------------------------------------------
class AttackContextAnalyzer:
    """Analyze attack context for better classification"""

    def __init__(self):
        self.ip_history = defaultdict(list)

    def add_event(self, ip, attacks, severity, timestamp=None):
        """Add an event to the IP history"""
        self.ip_history[ip].append({
            "attacks": attacks,
            "severity": severity,
            "timestamp": timestamp or datetime.now()
        })

    def get_ip_threat_score(self, ip):
        """Calculate threat score for an IP based on history"""
        if ip not in self.ip_history:
            return 0

        events = self.ip_history[ip]
        event_count = len(events)

        all_attacks = set()
        total_severity = 0
        for event in events:
            all_attacks.update(event["attacks"])
            total_severity += event["severity"]

        attack_diversity = len(all_attacks)
        avg_severity = total_severity / event_count if event_count > 0 else 0

        score = min(100, (
                (event_count * 1.5) +
                (attack_diversity * 8) +
                (avg_severity * 4)
        ))

        return round(score)

    def detect_attack_chain(self, ip):
        """Detect multi-stage attack patterns"""
        if ip not in self.ip_history:
            return []

        events = self.ip_history[ip]
        all_attacks = set()
        for event in events:
            all_attacks.update(event["attacks"])

        chains = []

        recon_attacks = {"vulnerability_scanner", "directory_enumeration",
                         "web_fingerprinting", "sensitive_file_probe",
                         "backup_file_probe", "config_file_probe", "admin_panel_probe"}
        exploit_attacks = {"sql_injection", "sql_injection_union", "sql_injection_blind",
                           "sql_injection_time", "sql_injection_error", "xss_reflected",
                           "command_injection", "path_traversal", "lfi", "rfi",
                           "cms_exploit", "webshell_upload"}

        if all_attacks & recon_attacks and all_attacks & exploit_attacks:
            chains.append("RECON_TO_EXPLOIT")

        cred_attacks = {"brute_force_ssh", "brute_force_web", "credential_stuffing", "password_spray","LOGIN_PATTERNS"}
        if all_attacks & cred_attacks and len(events) > 10:
            chains.append("CREDENTIAL_ATTACK, POSSIBLE BRUTE FORCE")

        infra_attacks = {"cisco_ios_probe", "iis_exploit", "apache_exploit", "tomcat_exploit"}
        if all_attacks & infra_attacks:
            chains.append("INFRASTRUCTURE_ATTACK")

        if len(events) > 50:
            chains.append("HIGH_VOLUME_SCANNING")

        return chains

    def get_attack_summary(self, ip):
        """Get summary of attacks for an IP"""
        if ip not in self.ip_history:
            return {}

        events = self.ip_history[ip]
        attack_counts = defaultdict(int)

        for event in events:
            for attack in event["attacks"]:
                if attack != "normal":
                    attack_counts[attack] += 1

        return dict(attack_counts)


# ---------------------------------------------------------------------
# SEMANTIC SEARCH ENGINE
# ---------------------------------------------------------------------
def embed_text(text):
    """Generate embedding with OpenAI small model."""
    emb = client.embeddings.create(
        model="text-embedding-3-small",
        input=text
    )
    return emb.data[0].embedding


def semantic_detect(log, normalizer, top_k=5):
    """Search in trained ChromaDB collection for similar attack templates."""
    normalized_log = normalizer.normalize(log)
    embedding = embed_text(normalized_log)

    results = collection.query(
        query_embeddings=[embedding],
        n_results=top_k
    )

    if not results["documents"]:
        return []

    matches = []
    for doc, meta, dist in zip(results["documents"][0], results["metadatas"][0], results["distances"][0]):
        matches.append({
            "template": doc,
            "attack_types": [a.strip() for a in meta.get("attacks", "").split(",") if a.strip()],
            "severity": meta.get("severity", 0),
            "mitre": [m.strip() for m in meta.get("mitre_tactics", "").split(",") if m.strip()],
            "category": meta.get("category", "unknown"),
            "distance": dist
        })
    return matches


def interpret_semantic_hits(hits, dist_threshold=0.30):
    """Summarize semantic search results into top probable attack types."""
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
    """Comprehensive log analysis combining rule-based and semantic detection."""

    # Rule-based detection
    rule_attacks = detector.detect(log)
    rule_severity = detector.get_severity(rule_attacks)
    rule_mitre = detector.get_mitre_tactics(rule_attacks)
    rule_categories = detector.get_categories(rule_attacks)

    # Semantic detection (optional)
    sem_attacks = []
    sem_severity = 0
    sem_mitre = []
    sem_categories = []

    if use_semantic:
        semantic_hits = semantic_detect(log, normalizer)
        sem_attacks, sem_severity, sem_mitre, sem_categories = interpret_semantic_hits(semantic_hits)

    # Combine results
    all_attacks = list(set(rule_attacks + sem_attacks))
    all_attacks = [a for a in all_attacks if a != "normal"]

    if not all_attacks:
        all_attacks = ["normal"]

    final_severity = max(rule_severity, sem_severity)
    all_mitre = list(set(rule_mitre + sem_mitre))
    all_categories = list(set(rule_categories + sem_categories))

    metadata = normalizer.extract_metadata(log)

    return {
        "attacks": all_attacks,
        "severity": final_severity,
        "mitre": all_mitre,
        "categories": all_categories,
        "source_ip": metadata["source_ip"],
        "http_status": metadata["http_status"],
        "http_method": metadata["http_method"],
        "url_path": metadata["url_path"],
        "detection_sources": {
            "rule_based": rule_attacks,
            "semantic": sem_attacks
        }
    }


# ---------------------------------------------------------------------
# MAIN DETECTION LOOP
# ---------------------------------------------------------------------
def main():
    print("=" * 70)
    print("🔍 ADVANCED SECURITY LOG DETECTION SYSTEM")
    print("=" * 70)

    # Initialize components
    detector = AttackDetector()
    normalizer = LogNormalizer()
    context_analyzer = AttackContextAnalyzer()

    # Load logs
    try:
        with open("new_logs.txt") as f:
            logs = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("❌ Error: new_logs.txt not found!")
        return

    print(f"\n📊 Analyzing {len(logs)} log entries...\n")

    # Process logs
    ip_events = defaultdict(lambda: {
        "attacks": [],
        "total_requests": 0,
        "max_severity": 0,
        "mitre_tactics": set(),
        "categories": set(),
        "sample_logs": [],
        "attack_counts": defaultdict(int),
        "http_methods": defaultdict(int),
        "http_statuses": defaultdict(int)
    })

    attack_stats = defaultdict(int)
    severity_stats = defaultdict(int)

    # DDoS tracking: timestamps ανά IP
    DDOS_THRESHOLD = 50
    DDOS_WINDOW = 60
    ip_timestamps = defaultdict(list)

    # Log timestamp tracking για χρονικά φίλτρα στο chat
    all_log_timestamps = []

    for log in tqdm(logs, desc="Processing"):
        result = analyze_log(log, detector, normalizer, use_semantic=True)

        # Συλλογή timestamps για χρονικά φίλτρα
        metadata = normalizer.extract_metadata(log)
        ts = metadata.get("timestamp")
        if ts:
            all_log_timestamps.append(ts)

        ip = result["source_ip"]

        # --- DDoS DETECTION (χρησιμοποιούμε το ήδη εξαχθέν metadata) ---
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
        # ------------------------------

        # --- ΕΔΩ ΒΑΖΕΙΣ ΤΟΝ ΚΩΔΙΚΑ ---ΜΕΤΡΑΣ ΠΟΣΕΣ ΦΟΡΕΣ ΚΑΝΕΙ LOGIN ΕΝΔΕΧΟΜΕΝΟ BRUTE FORCE
        if "LOGIN_PATTERNS" in result["attacks"]:
            # Ελέγχουμε πόσα login patterns έχει ήδη η IP στα στατιστικά της
            count = ip_events[ip]["attack_counts"].get("LOGIN_PATTERNS", 0) + 1

            if count > 20:
                result["severity"] = 9
                # Ενημερώνουμε τη λίστα των attacks για να φαίνεται ως brute force
                result["attacks"] = [a if a != "LOGIN_PATTERNS" else "brute_force_web" for a in result["attacks"]]
            elif count > 5:
                result["severity"] = 6
        # ------------------------------

        # Update IP events
        ip_events[ip]["total_requests"] += 1
        ip_events[ip]["max_severity"] = max(ip_events[ip]["max_severity"], result["severity"])

        for attack in result["attacks"]:
            if attack != "normal":
                if attack not in ip_events[ip]["attacks"]:
                    ip_events[ip]["attacks"].append(attack)
                ip_events[ip]["attack_counts"][attack] += 1
                attack_stats[attack] += 1

        ip_events[ip]["mitre_tactics"].update(result["mitre"])
        ip_events[ip]["categories"].update(result["categories"])

        if result["http_method"]:
            ip_events[ip]["http_methods"][result["http_method"]] += 1
        if result["http_status"]:
            ip_events[ip]["http_statuses"][result["http_status"]] += 1

        if len(ip_events[ip]["sample_logs"]) < 5:
            ip_events[ip]["sample_logs"].append(log[:200])

        # Update context analyzer
        context_analyzer.add_event(ip, result["attacks"], result["severity"])

        # Stats
        severity_stats[result["severity"]] += 1

    # ---------------------------------------------------------------------
    # REPORTING
    # ---------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("🚨 ATTACK DETECTION RESULTS")
    print("=" * 70)

    # Filter suspicious IPs
    ALERT_THRESHOLD = 7  # Μόνο severity 7+ εμφανίζεται στο report
    suspicious_ips = []
    for ip, data in ip_events.items():
        if ip == "unknown":
            continue
        attacks = [a for a in data["attacks"] if a != "normal"]
        if attacks and data["max_severity"] >= ALERT_THRESHOLD:
            threat_score = context_analyzer.get_ip_threat_score(ip)
            attack_chains = context_analyzer.detect_attack_chain(ip)
            suspicious_ips.append((ip, data, threat_score, attack_chains))

    # Sort by threat score
    suspicious_ips.sort(key=lambda x: x[2], reverse=True)

    # Print detailed report
    for ip, data, threat_score, attack_chains in suspicious_ips:
        print(f"\n{'─' * 60}")
        print(f"🔴 IP: {ip}")
        print(f"{'─' * 60}")
        print(f"   📈 Threat Score: {threat_score}/100")
        print(f"   📊 Total Requests: {data['total_requests']}")
        print(f"   ⚠️  Max Severity: {data['max_severity']}/10")

        print(f"\n   🎯 Detected Attacks:")
        for attack, count in sorted(data["attack_counts"].items(), key=lambda x: x[1], reverse=True):
            severity = ATTACK_TAXONOMY.get(attack, {}).get("severity", 0)
            print(f"      • {attack}: {count} occurrences (severity: {severity})")

        if data["mitre_tactics"]:
            print(f"\n   🗺️  MITRE ATT&CK: {', '.join(data['mitre_tactics'])}")

        if data["categories"]:
            print(f"   📁 Categories: {', '.join(data['categories'])}")

        if attack_chains:
            print(f"\n   ⛓️  Attack Chains Detected:")
            for chain in attack_chains:
                print(f"      • {chain}")

        # Threat level assessment
        if threat_score >= 70:
            print(f"\n   🔴 THREAT LEVEL: CRITICAL - Immediate action required!")
        elif threat_score >= 50:
            print(f"\n   🟠 THREAT LEVEL: HIGH - Coordinated attack activity")
        elif threat_score >= 30:
            print(f"\n   🟡 THREAT LEVEL: MEDIUM - Suspicious probing")
        else:
            print(f"\n   🟢 THREAT LEVEL: LOW - Possible reconnaissance")

        # Sample logs
        print(f"\n   📝 Sample Logs:")
        for i, sample in enumerate(data["sample_logs"][:3], 1):
            print(f"      {i}. {sample}...")

    # ---------------------------------------------------------------------
    # GLOBAL STATISTICS
    # ---------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("📊 GLOBAL STATISTICS")
    print("=" * 70)

    print(f"\n   Total Logs Analyzed: {len(logs)}")
    print(f"   Unique IPs: {len(ip_events)}")
    print(f"   Suspicious IPs: {len(suspicious_ips)}")

    print(f"\n   Top Attack Types:")
    for attack, count in sorted(attack_stats.items(), key=lambda x: x[1], reverse=True)[:15]:
        severity = ATTACK_TAXONOMY.get(attack, {}).get("severity", 0)
        category = ATTACK_TAXONOMY.get(attack, {}).get("category", "unknown")
        print(f"      • {attack}: {count} ({category}, severity: {severity})")

    print(f"\n   Severity Distribution:")
    for sev in range(10, -1, -1):
        if severity_stats[sev] > 0:
            bar = "█" * min(50, severity_stats[sev] // 10)
            print(f"      Severity {sev:2d}: {severity_stats[sev]:5d} {bar}")

    # ---------------------------------------------------------------------
    # AI THREAT SUMMARY
    # ---------------------------------------------------------------------
    if suspicious_ips:
        print("\n" + "=" * 70)
        print("🤖 AI THREAT INTELLIGENCE SUMMARY")
        print("=" * 70)

        prompt = """You are a senior SOC analyst. Analyze the following threat data and provide:
1. Overall threat assessment
2. Top 3 most dangerous attackers with justification
3. Attack patterns and potential objectives
4. Recommended immediate actions
5. Suggested firewall rules or mitigations

Threat Data:
"""
        for ip, data, threat_score, attack_chains in suspicious_ips[:10]:
            prompt += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IP: {ip}
Threat Score: {threat_score}/100
Total Requests: {data['total_requests']}
Max Severity: {data['max_severity']}/10
Attacks: {dict(data['attack_counts'])}
MITRE Tactics: {list(data['mitre_tactics'])}
Attack Chains: {attack_chains}
Sample logs: {data['sample_logs'][:2]}
"""

        prompt += "\n\nProvide a concise but comprehensive analysis."

        try:
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system",
                     "content": "You are an expert SOC analyst specializing in web application security and intrusion detection. Be technical, specific, and actionable."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=800,
                temperature=0.3
            )
            print(f"\n{resp.choices[0].message.content}")
        except Exception as e:
            print(f"\n❌ AI Summary unavailable: {e}")
    else:
        print("\n✅ No significant malicious activity detected.")

    print("\n" + "=" * 70)
    print("🏁 DETECTION COMPLETE")
    print("=" * 70)

    # ---------------------------------------------------------------------
    # JSON EXPORT για GOD_OF_CHAT
    # Χρησιμοποιούμε ΟΛΕΣ τις ύποπτες IPs χωρίς ALERT_THRESHOLD
    # ---------------------------------------------------------------------
    import json

    all_suspicious = []
    for ip, data in ip_events.items():
        if ip == "unknown":
            continue
        attacks = [a for a in data["attacks"] if a != "normal"]
        if attacks:
            threat_score = context_analyzer.get_ip_threat_score(ip)
            attack_chains = context_analyzer.detect_attack_chain(ip)
            all_suspicious.append((ip, data, threat_score, attack_chains))

    all_suspicious.sort(key=lambda x: x[2], reverse=True)

    export_data = {
        "generated_at": datetime.now().isoformat(),
        "log_start": min(all_log_timestamps).isoformat() if all_log_timestamps else None,
        "log_end": max(all_log_timestamps).isoformat() if all_log_timestamps else None,
        "total_logs": len(logs),
        "unique_ips": len(ip_events),
        "suspicious_ips_count": len(all_suspicious),
        "attack_stats": dict(attack_stats),
        "severity_distribution": {str(k): v for k, v in severity_stats.items()},
        "suspicious_ips": []
    }

    for ip, data, threat_score, attack_chains in all_suspicious:
        # Εξαγωγή timestamps από sample logs για χρονικά φίλτρα
        ip_ts_list = []
        for sample in data["sample_logs"]:
            # Apache format
            m = re.search(r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})', sample)
            if m:
                try:
                    ip_ts_list.append(datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S"))
                except ValueError:
                    pass
            # Cisco ASA format
            m2 = re.search(r'(\w{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})', sample)
            if m2:
                try:
                    ip_ts_list.append(datetime.strptime(m2.group(1), "%b %d %Y %H:%M:%S"))
                except ValueError:
                    pass

        export_data["suspicious_ips"].append({
            "ip": ip,
            "threat_score": threat_score,
            "total_requests": data["total_requests"],
            "max_severity": data["max_severity"],
            "attacks": dict(data["attack_counts"]),
            "mitre_tactics": list(data["mitre_tactics"]),
            "categories": list(data["categories"]),
            "attack_chains": attack_chains or [],
            "http_methods": dict(data["http_methods"]),
            "http_statuses": dict(data["http_statuses"]),
            "sample_logs": data["sample_logs"][:3],
            "first_seen": min(ip_ts_list).isoformat() if ip_ts_list else None,
            "last_seen": max(ip_ts_list).isoformat() if ip_ts_list else None,
        })

    with open("detection_results.json", "w", encoding="utf-8") as f:
        json.dump(export_data, f, ensure_ascii=False, indent=2)

    print(f"\n💾 Results exported → detection_results.json")
    print(f"   {len(all_suspicious)} IPs αποθηκεύτηκαν για το GOD_OF_CHAT.py\n")


if __name__ == "__main__":
    main()
