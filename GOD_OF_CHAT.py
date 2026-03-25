import json
import re
import os
from datetime import datetime, timedelta
from openai import OpenAI
from dotenv import load_dotenv

# ---------------------------------------------------------------------
# SETUP
# ---------------------------------------------------------------------
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

RESULTS_FILE = "detection_results.json"

SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst.
You have access to security log analysis results and answer questions about them.
Be concise, technical, and actionable. Answer in the same language as the user.
When listing IPs or attacks, be specific with numbers and severity scores.
If asked for recommendations, provide concrete firewall rules or actions."""

# ---------------------------------------------------------------------
# LOAD RESULTS
# ---------------------------------------------------------------------
def load_results():
    if not os.path.exists(RESULTS_FILE):
        print(f"❌ Δεν βρέθηκε το {RESULTS_FILE}.")
        print(f"   Τρέξε πρώτα το GOD_OF_DETECTION.py.")
        exit(1)
    with open(RESULTS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

# ---------------------------------------------------------------------
# INTENT DETECTION — Python side (0 tokens)
# ---------------------------------------------------------------------
def detect_intent(question: str):
    q = question.lower()

    # Χρονικό φίλτρο
    hour_match = re.search(r'(\d+)\s*(ώρ|hour|hr)', q)
    if hour_match:
        return "time_filter", int(hour_match.group(1))

    # Συγκεκριμένη IP
    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', question)
    if ip_match:
        return "ip_lookup", ip_match.group(1)

    # DDoS/Flood
    if any(w in q for w in ["ddos", "flood", "syn", "dos"]):
        return "attack_filter", "dos"

    # SQL Injection
    if any(w in q for w in ["sql", "injection", "sqli"]):
        return "attack_filter", "injection"

    # XSS
    if any(w in q for w in ["xss", "cross site", "script"]):
        return "attack_filter", "xss"

    # Brute Force / VPN
    if any(w in q for w in ["brute", "vpn", "password", "login", "κωδικ"]):
        return "attack_filter", "credential"

    # Cisco ASA
    if any(w in q for w in ["asa", "cisco", "firewall", "fw"]):
        return "attack_filter", "asa"

    # Path traversal / LFI
    if any(w in q for w in ["traversal", "lfi", "path", "αρχε"]):
        return "attack_filter", "file_access"

    # Επικίνδυνες IPs / top threats
    if any(w in q for w in ["επικίνδυν", "top", "χειρότερ", "σοβαρ", "dangerous", "worst"]):
        return "top_threats", None

    # Γενική ανασκόπηση / σήμερα / περίεργο
    if any(w in q for w in ["σήμερα", "today", "περίεργ", "unusual", "γενικ", "summary", "ανακεφ", "overview"]):
        return "summary", None

    # Recommendations / τι να κάνω
    if any(w in q for w in ["τι να κάν", "recommend", "προτείν", "block", "μπλοκ", "action"]):
        return "recommendations", None

    # Default
    return "general", None


# ---------------------------------------------------------------------
# CONTEXT BUILDERS — δημιουργούν το context για το GPT
# ---------------------------------------------------------------------
def build_context_time_filter(data: dict, hours: int) -> str:
    """Φιλτράρει βάσει του τρέχοντος χρόνου vs timestamps των logs."""

    now = datetime.now()
    cutoff = now - timedelta(hours=hours)

    log_end_str   = data.get("log_end")
    log_start_str = data.get("log_start")

    if log_end_str:
        log_end   = datetime.fromisoformat(log_end_str)
        log_start = datetime.fromisoformat(log_start_str) if log_start_str else log_end

        # Αν τα logs είναι παλιότερα από το cutoff → κανένα log στο παράθυρο
        if log_end < cutoff:
            context = f"""
Ερώτηση: επιθέσεις τις τελευταίες {hours} ώρες (από {cutoff.strftime('%d/%m/%Y %H:%M')} έως τώρα {now.strftime('%d/%m/%Y %H:%M')})
Περίοδος διαθέσιμων logs: {log_start.strftime('%d/%m/%Y %H:%M')} → {log_end.strftime('%d/%m/%Y %H:%M')}
Αποτέλεσμα: ΔΕΝ υπάρχουν logs στο ζητούμενο χρονικό παράθυρο.
Τα logs είναι από {log_end.strftime('%d/%m/%Y')} — πριν από {int((now - log_end).days)} μέρες.
"""
            return context

        # Αν τα logs εμπίπτουν (μερικώς ή πλήρως) στο παράθυρο
        effective_start = max(log_start, cutoff)
        context = f"""
Ερώτηση: επιθέσεις τις τελευταίες {hours} ώρες
Τρέχων χρόνος: {now.strftime('%d/%m/%Y %H:%M')}
Παράθυρο αναζήτησης: {cutoff.strftime('%d/%m/%Y %H:%M')} → {now.strftime('%d/%m/%Y %H:%M')}
Logs που εμπίπτουν: {effective_start.strftime('%d/%m/%Y %H:%M')} → {log_end.strftime('%d/%m/%Y %H:%M')}
Σύνολο logs: {data['total_logs']}
"""
    else:
        context = f"Δεν υπάρχουν χρονικές πληροφορίες για τα logs.\n"

    # Εμφάνιση ύποπτων IPs
    context += f"\nΕνεργές ύποπτες IPs ({data['suspicious_ips_count']}):\n"
    for ip_data in data["suspicious_ips"][:5]:
        context += f"""  • IP: {ip_data['ip']} | Score: {ip_data['threat_score']}/100 | Severity: {ip_data['max_severity']}/10
    Επιθέσεις: {ip_data['attacks']}
"""
    context += "\nTop επιθέσεις:\n"
    for attack, count in sorted(data["attack_stats"].items(), key=lambda x: x[1], reverse=True)[:8]:
        context += f"  • {attack}: {count}\n"

    return context


def build_context_ip_lookup(data: dict, ip: str) -> str:
    """Βρίσκει συγκεκριμένη IP."""
    found = [x for x in data["suspicious_ips"] if x["ip"] == ip]

    if not found:
        return f"Δεν βρέθηκε η IP {ip} στις ύποπτες IPs. Πιθανόν να είναι κανονικό traffic."

    ip_data = found[0]
    context = f"""
Πληροφορίες για IP: {ip}
Threat Score: {ip_data['threat_score']}/100
Σύνολο requests: {ip_data['total_requests']}
Max Severity: {ip_data['max_severity']}/10
Κατηγορίες: {', '.join(ip_data['categories'])}
MITRE Tactics: {', '.join(ip_data['mitre_tactics'])}
Attack Chains: {', '.join(ip_data['attack_chains']) if ip_data['attack_chains'] else 'Κανένα'}

Επιθέσεις:
"""
    for attack, count in sorted(ip_data["attacks"].items(), key=lambda x: x[1], reverse=True):
        context += f"  • {attack}: {count} φορές\n"

    context += "\nSample logs:\n"
    for log in ip_data["sample_logs"]:
        context += f"  {log}\n"

    return context


def build_context_attack_filter(data: dict, category: str) -> str:
    """Φιλτράρει κατά κατηγορία επίθεσης."""

    # Κατηγορίες για κάθε τύπο επίθεσης
    dos_keywords      = ["ddos", "flood", "asa_connection", "dos", "syn"]
    cred_keywords     = ["brute", "login", "vpn", "credential", "asa_vpn"]
    file_keywords     = ["lfi", "rfi", "traversal", "path"]
    inject_keywords   = ["sql", "injection", "xss", "command", "code"]

    def matches_category(attack_name, cat):
        k = attack_name.lower()
        if cat == "dos":
            return any(w in k for w in dos_keywords)
        if cat == "injection":
            return any(w in k for w in inject_keywords)
        if cat == "xss":
            return "xss" in k
        if cat == "credential":
            return any(w in k for w in cred_keywords)
        if cat == "file_access":
            return any(w in k for w in file_keywords)
        if cat == "asa":
            return k.startswith("asa_")
        return cat in k

    relevant_attacks = {k: v for k, v in data["attack_stats"].items()
                       if matches_category(k, category)}

    if not relevant_attacks:
        return f"Δεν βρέθηκαν επιθέσεις κατηγορίας '{category}'."

    context = f"Επιθέσεις κατηγορίας '{category}':\n"
    for attack, count in sorted(relevant_attacks.items(), key=lambda x: x[1], reverse=True):
        context += f"  • {attack}: {count}\n"

    # Ψάχνει σε ΟΛΕΣ τις IPs (όχι μόνο τις top)
    context += "\nIPs με αυτές τις επιθέσεις:\n"
    matched_ips = []
    for ip_data in data["suspicious_ips"]:
        matching = {k: v for k, v in ip_data["attacks"].items()
                   if matches_category(k, category)}
        if matching:
            matched_ips.append((ip_data, matching))

    if not matched_ips:
        context += "  Δεν βρέθηκαν συγκεκριμένες IPs.\n"
    else:
        # Ταξινόμηση κατά severity
        matched_ips.sort(key=lambda x: x[0]["max_severity"], reverse=True)
        for ip_data, matching in matched_ips:
            context += f"  • {ip_data['ip']} (score: {ip_data['threat_score']}/100, severity: {ip_data['max_severity']}/10)\n"
            for attack, count in sorted(matching.items(), key=lambda x: x[1], reverse=True):
                context += f"      - {attack}: {count} φορές\n"

    return context


def build_context_top_threats(data: dict) -> str:
    """Top 5 πιο επικίνδυνες IPs."""
    context = f"Top επικίνδυνες IPs (από {data['suspicious_ips_count']} ύποπτες):\n\n"
    for i, ip_data in enumerate(data["suspicious_ips"][:5], 1):
        context += f"""#{i} IP: {ip_data['ip']}
   Threat Score: {ip_data['threat_score']}/100
   Max Severity: {ip_data['max_severity']}/10
   Επιθέσεις: {ip_data['attacks']}
   Attack Chains: {ip_data['attack_chains']}

"""
    return context


def build_context_summary(data: dict) -> str:
    """Γενική ανασκόπηση."""
    context = f"""
Γενική Ανασκόπηση Ασφάλειας:
Ανάλυση: {data['generated_at']}
Σύνολο logs: {data['total_logs']}
Unique IPs: {data['unique_ips']}
Ύποπτες IPs: {data['suspicious_ips_count']}

Κατανομή Severity:
"""
    for sev, count in sorted(data["severity_distribution"].items(), key=lambda x: int(x[0]), reverse=True):
        if count > 0:
            context += f"  Severity {sev}: {count}\n"

    context += "\nTop 10 Attack Types:\n"
    for attack, count in sorted(data["attack_stats"].items(), key=lambda x: x[1], reverse=True)[:10]:
        context += f"  • {attack}: {count}\n"

    context += "\nTop 3 πιο επικίνδυνες IPs:\n"
    for ip_data in data["suspicious_ips"][:3]:
        context += f"  • {ip_data['ip']} (score: {ip_data['threat_score']}/100, severity: {ip_data['max_severity']}/10)\n"

    return context


def build_context_recommendations(data: dict) -> str:
    """Δεδομένα για recommendations."""
    context = build_context_top_threats(data)
    context += "\nTop attacks:\n"
    for attack, count in sorted(data["attack_stats"].items(), key=lambda x: x[1], reverse=True)[:8]:
        context += f"  • {attack}: {count}\n"
    return context


def build_context_general(data: dict) -> str:
    """Default — γενικό summary."""
    return build_context_summary(data)


# ---------------------------------------------------------------------
# MAIN CHAT FUNCTION
# ---------------------------------------------------------------------
def ask(question: str, data: dict, history: list) -> str:
    # 1. Detect intent — Python side, 0 tokens
    intent, param = detect_intent(question)

    # 2. Build context — Python side, 0 tokens
    builders = {
        "time_filter":     lambda: build_context_time_filter(data, param),
        "ip_lookup":       lambda: build_context_ip_lookup(data, param),
        "attack_filter":   lambda: build_context_attack_filter(data, param),
        "top_threats":     lambda: build_context_top_threats(data),
        "summary":         lambda: build_context_summary(data),
        "recommendations": lambda: build_context_recommendations(data),
        "general":         lambda: build_context_general(data),
    }
    context = builders[intent]()

    # 3. Build messages με history (για follow-up ερωτήσεις)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    # Προσθέτουμε τελευταία 4 μηνύματα από history για context
    messages.extend(history[-4:])

    # Τρέχουσα ερώτηση με context
    messages.append({
        "role": "user",
        "content": f"Security Data:\n{context}\n\nΕρώτηση: {question}"
    })

    # 4. GPT call
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            max_tokens=600,
            temperature=0.3
        )
        answer = resp.choices[0].message.content

        # Update history
        history.append({"role": "user", "content": question})
        history.append({"role": "assistant", "content": answer})

        return answer

    except Exception as e:
        return f"❌ Σφάλμα: {e}"


# ---------------------------------------------------------------------
# MAIN LOOP
# ---------------------------------------------------------------------
def main():
    print("=" * 60)
    print("🛡️  GOD OF CHAT — Security Analysis Assistant")
    print("=" * 60)

    # Load results
    data = load_results()

    generated_at = data.get("generated_at", "unknown")
    print(f"\n📊 Φορτώθηκαν αποτελέσματα από: {generated_at}")
    print(f"   Logs: {data['total_logs']} | Ύποπτες IPs: {data['suspicious_ips_count']}")
    print(f"\n💡 Παραδείγματα ερωτήσεων:")
    print(f"   • 'Είχαμε καμία επίθεση τις τελευταίες 4 ώρες;'")
    print(f"   • 'Πες μου για την IP 185.220.101.45'")
    print(f"   • 'Ποια η πιο επικίνδυνη IP;'")
    print(f"   • 'Είδες κάτι περίεργο σήμερα;'")
    print(f"   • 'Τι πρέπει να κάνω τώρα;'")
    print(f"   • 'Είχαμε DDoS επιθέσεις;'")
    print(f"\n   Γράψε 'exit' για έξοδο.\n")
    print("=" * 60)

    history = []

    while True:
        try:
            question = input("\n🔍 Ερώτηση: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n👋 Αντίο!")
            break

        if not question:
            continue

        if question.lower() in ["exit", "quit", "q", "έξοδος"]:
            print("\n👋 Αντίο!")
            break

        print("\n🤔 Αναλύω...")
        answer = ask(question, data, history)
        print(f"\n🛡️  {answer}")
        print("\n" + "─" * 60)
#Ai

if __name__ == "__main__":
    main()
