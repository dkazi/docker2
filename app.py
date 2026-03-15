import streamlit as st
import os
import time
import json
import re
import subprocess
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from datetime import datetime
from openai import OpenAI

# ── PATHS ──────────────────────────────────────────────────────────────────────
WATCH_DIR        = "/data_to_monitor"
MASTER_FILE_PATH = "/app/master_log.txt"
HISTORY_DIR      = "/app/chat_history"
FLAGS_FILE       = "/app/flagged_ips.json"
RESULTS_FILE     = "/app/detection_results.json"
os.makedirs(HISTORY_DIR, exist_ok=True)

st.set_page_config(page_title="AI Log Security Analyst",
                   layout="wide", page_icon="🛡️")

# ── API KEY από .env ───────────────────────────────────────────────────────────
api_key = os.getenv("OPENAI_API_KEY", "")

# ── SESSION STATE ──────────────────────────────────────────────────────────────
for k, v in {
    "logging_active":  False,
    "messages":        [],       # chatbot tab
    "soc_messages":    [],       # soc tab
    "multiselect_key": 0,
    "ai_error":        None,
    "last_pos":        {},
    "session_name":    datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
}.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ── FILE DISCOVERY ─────────────────────────────────────────────────────────────
files = []
if os.path.exists(WATCH_DIR):
    for root, _, filenames in os.walk(WATCH_DIR):
        for filename in filenames:
            rel = os.path.relpath(os.path.join(root, filename), WATCH_DIR)
            files.append(rel)
    files.sort()

# ── HELPERS ────────────────────────────────────────────────────────────────────
def read_last_n_lines(filepath, n=200):
    try:
        with open(filepath, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return []
            chunk = min(size, n * 250)
            f.seek(-chunk, 2)
            data = f.read().decode("utf-8", errors="replace")
        return data.splitlines()[-n:]
    except Exception as e:
        return [f"[error: {e}]"]


def save_history(session_name, messages):
    path = os.path.join(HISTORY_DIR, f"{session_name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"session": session_name, "messages": messages}, f,
                  ensure_ascii=False, indent=2)


def load_all_sessions():
    sessions = {}
    for fname in sorted(os.listdir(HISTORY_DIR), reverse=True):
        if fname.endswith(".json"):
            path = os.path.join(HISTORY_DIR, fname)
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                sessions[fname[:-5]] = data.get("messages", [])
            except Exception:
                pass
    return sessions


def load_detection_results():
    if os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None


def run_detection():
    """
    Τρέχει GOD_OF_DETECTION incremental.
    Επιστρέφει (success, output_text).
    """
    env = os.environ.copy()
    env["OPENAI_API_KEY"]  = api_key
    env["LOG_FILE_PATH"]   = MASTER_FILE_PATH
    env["CHROMA_PATH"]     = "/app/chroma_db_v2"
    try:
        result = subprocess.run(
            ["python3", "/app/GOD_OF_DETECTION.py"],
            capture_output=True, text=True,
            cwd="/app", env=env, timeout=300,
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


def ask_god_of_chat(question, history):
    """
    Καλεί GOD_OF_CHAT.ask() με τα τρέχοντα detection results.
    Επιστρέφει string απάντηση.
    """
    import GOD_OF_CHAT as god_chat
    results = load_detection_results()
    if not results:
        return "❌ Δεν υπάρχουν detection results. Βεβαιώσου ότι έχεις επιλέξει log αρχεία και κάνεις monitoring."
    # Τελευταία 4 μηνύματα για follow-up context
    chat_history = [m for m in history if m["role"] in ("user", "assistant")][-4:]
    return god_chat.ask(question, results, chat_history)


def generate_pdf(messages, session_name):
    lines = ["LogGuard AI — Chat Export", f"Session: {session_name}", ""]
    for m in messages:
        role = "You" if m["role"] == "user" else "AI Analyst"
        lines.append(f"[{role}]")
        for paragraph in m["content"].split("\n"):
            while len(paragraph) > 90:
                lines.append(paragraph[:90])
                paragraph = paragraph[90:]
            lines.append(paragraph)
        lines.append("")

    objects_body = b""
    offsets = []

    def write_obj(oid, content):
        nonlocal objects_body
        offsets.append(len(b"%PDF-1.4\n") + len(objects_body))
        objects_body += f"{oid} 0 obj\n{content}\nendobj\n".encode()

    stream_lines = ["BT", "/F1 10 Tf", "50 780 Td"]
    y = 780
    for line in lines:
        safe = (line.replace("\\", "\\\\")
                    .replace("(", "\\(").replace(")", "\\)")
                    .encode("latin-1", errors="replace").decode("latin-1"))
        stream_lines.append(f"({safe}) Tj")
        y -= 14
        if y < 50:
            stream_lines += ["ET", "BT", "/F1 10 Tf", "50 780 Td"]
            y = 780
        else:
            stream_lines.append("0 -14 Td")
    stream_lines.append("ET")
    stream_bytes = "\n".join(stream_lines).encode("latin-1", errors="replace")

    write_obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
    write_obj(2, "<< /Type /Pages /Kids [4 0 R] /Count 1 >>")
    write_obj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    write_obj(4, ("<< /Type /Page /Parent 2 0 R "
                  "/MediaBox [0 0 612 842] /Contents 5 0 R "
                  "/Resources << /Font << /F1 3 0 R >> >> >>"))
    write_obj(5, (f"<< /Length {len(stream_bytes)} >>\nstream\n"
                  + stream_bytes.decode("latin-1") + "\nendstream"))

    xref_offset = len(b"%PDF-1.4\n") + len(objects_body)
    xref = "xref\n0 6\n0000000000 65535 f \n"
    for off in offsets:
        xref += f"{off:010d} 00000 n \n"
    trailer = (f"trailer\n<< /Size 6 /Root 1 0 R >>\n"
               f"startxref\n{xref_offset}\n%%EOF")
    return b"%PDF-1.4\n" + objects_body + xref.encode() + trailer.encode()


def load_flags():
    if os.path.exists(FLAGS_FILE):
        try:
            with open(FLAGS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_flags(data):
    with open(FLAGS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def extract_ips_from_logs(selected, n=1000):
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    counts = {}
    for rel in selected:
        for line in read_last_n_lines(os.path.join(WATCH_DIR, rel), n):
            for ip in ip_pattern.findall(line):
                counts[ip] = counts.get(ip, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


# ── CHART HELPERS ──────────────────────────────────────────────────────────────
DARK_BG   = "#0e1117"
DARK_FG   = "#c8c8c8"
DARK_GRID = "#2a2a2a"
ACCENT    = ["#4da6ff","#ff4b4b","#ffa600","#00e676",
             "#bf5af2","#ff6b6b","#48dbfb","#ffd32a"]

def _base_fig(w=7, h=3.2):
    fig, ax = plt.subplots(figsize=(w, h))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_BG)
    ax.tick_params(colors=DARK_FG, labelsize=8)
    ax.spines[:].set_color(DARK_GRID)
    ax.yaxis.grid(True, color=DARK_GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    return fig, ax

def bar_chart(data, title, color="#4da6ff"):
    if not data: return None
    fig, ax = _base_fig()
    keys, vals = list(data.keys()), list(data.values())
    bars = ax.bar(keys, vals, color=color, width=0.6, zorder=3)
    ax.set_title(title, color=DARK_FG, fontsize=10, pad=8)
    ax.set_xticklabels(keys, rotation=35, ha="right", fontsize=7)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.3,
                str(val), ha="center", va="bottom", color=DARK_FG, fontsize=7)
    fig.tight_layout()
    return fig

def pie_chart(data, title):
    if not data: return None
    items = sorted(data.items(), key=lambda x: x[1], reverse=True)
    if len(items) > 6:
        top = dict(items[:6])
        top["Other"] = sum(v for _, v in items[6:])
        items = list(top.items())
    labels = [k for k, _ in items]
    values = [v for _, v in items]
    fig, ax = _base_fig(w=5, h=4)
    wedges, _, autotexts = ax.pie(
        values, colors=ACCENT[:len(labels)], autopct="%1.0f%%",
        startangle=140, wedgeprops={"linewidth":0.5, "edgecolor":DARK_BG},
        pctdistance=0.78)
    for t in autotexts:
        t.set_color(DARK_BG); t.set_fontsize(8); t.set_fontweight("bold")
    ax.legend(wedges, labels, loc="lower center", bbox_to_anchor=(0.5,-0.18),
              ncol=3, fontsize=7, frameon=False, labelcolor=DARK_FG)
    ax.set_title(title, color=DARK_FG, fontsize=10, pad=10)
    fig.tight_layout()
    return fig

def hourly_bar(hourly, title):
    if not any(hourly.values()): return None
    fig, ax = _base_fig(w=8, h=3)
    hours, vals = list(hourly.keys()), list(hourly.values())
    bars = ax.bar(hours, vals, color="#4da6ff", width=0.7, zorder=3)
    ax.set_title(title, color=DARK_FG, fontsize=10, pad=8)
    ax.set_xlabel("Hour (00–23)", color=DARK_FG, fontsize=8)
    ax.tick_params(axis="x", labelsize=6)
    if vals:
        peak = max(vals)
        for bar, val in zip(bars, vals):
            if val == peak and peak > 0:
                bar.set_color("#ffa600")
    fig.tight_layout()
    return fig


# ── LOADING ANIMATION HTML ─────────────────────────────────────────────────────
LOADING_BLUE = """
<style>
@keyframes blink {
  0%,100% { opacity: 1; } 50% { opacity: 0.2; }
}
</style>
<div style="display:flex;align-items:center;gap:10px;padding:8px 0;">
  <div style="display:flex;gap:5px;">
    <div style="width:8px;height:8px;border-radius:50%;background:#4da6ff;
                animation:blink 1.2s ease-in-out infinite;"></div>
    <div style="width:8px;height:8px;border-radius:50%;background:#4da6ff;
                animation:blink 1.2s ease-in-out infinite 0.2s;"></div>
    <div style="width:8px;height:8px;border-radius:50%;background:#4da6ff;
                animation:blink 1.2s ease-in-out infinite 0.4s;"></div>
  </div>
  <span style="color:#4da6ff;font-size:13px;font-family:monospace;">
    SOC Analyst analyzing…
  </span>
</div>
"""

LOADING_GREEN = """
<div style="display:flex;align-items:center;gap:10px;padding:8px 0;">
  <div style="display:flex;gap:5px;">
    <div style="width:8px;height:8px;border-radius:50%;background:#00e676;
                animation:blink 1.2s ease-in-out infinite;"></div>
    <div style="width:8px;height:8px;border-radius:50%;background:#00e676;
                animation:blink 1.2s ease-in-out infinite 0.2s;"></div>
    <div style="width:8px;height:8px;border-radius:50%;background:#00e676;
                animation:blink 1.2s ease-in-out infinite 0.4s;"></div>
  </div>
  <span style="color:#00e676;font-size:13px;font-family:monospace;">
    Analyzing logs…
  </span>
</div>
"""


# ── SIDEBAR ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ System Settings")
    if not api_key:
        st.error("⚠️ OPENAI_API_KEY δεν βρέθηκε.\nΠρόσθεσέ το στο .env αρχείο.")
    else:
        st.success("✅ OpenAI API Key φορτώθηκε.")
    st.markdown("---")
    st.subheader("📁 Log Sources")

    selected_files = st.multiselect(
        "Select Files:", options=files, default=None,
        disabled=st.session_state.logging_active,
        key=f"files_{st.session_state.multiselect_key}",
    )

    if not st.session_state.logging_active:
        if st.button("✅ Start Monitoring", type="primary",
                     use_container_width=True):
            if selected_files:
                st.session_state.logging_active  = True
                st.session_state.session_name    = datetime.now().strftime(
                    "%Y-%m-%d_%H-%M-%S")
                st.session_state.last_pos = {}
                with open(MASTER_FILE_PATH, "w", encoding="utf-8") as f:
                    f.write(f"--- SESSION START: {time.strftime('%H:%M:%S')} ---\n")
                st.rerun()
            else:
                st.warning("Select at least one file!")
    else:
        if st.button("🗑️ Reset & Clear All", type="secondary",
                     use_container_width=True):
            st.session_state.logging_active  = False
            st.session_state.messages        = []
            st.session_state.soc_messages    = []
            st.session_state.ai_error        = None
            st.session_state.multiselect_key += 1
            st.session_state.last_pos        = {}
            if os.path.exists(MASTER_FILE_PATH):
                os.remove(MASTER_FILE_PATH)
            st.rerun()

    if st.session_state.logging_active:
        st.markdown("---")
        st.success("📡 Monitoring Active")


# ── TABS ───────────────────────────────────────────────────────────────────────
tab_soc, tab_chat, tab_dashboard, tab_live, tab_history, tab_flags = st.tabs([
    "🛡️ SOC Analysis",
    "🤖 AI Chatbot",
    "📊 Dashboard",
    "📡 Live Logs",
    "🕓 History",
    "🚩 Flagged IPs",
])


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 1 — SOC ANALYSIS
#  Ροή: prompt → GOD_OF_DETECTION (auto) → GOD_OF_CHAT.ask() → interface
# ══════════════════════════════════════════════════════════════════════════════
with tab_soc:
    st.title("🛡️ SOC Analysis")

    # Κουμπιά πάνω
    tb1, tb2, tb3 = st.columns([1, 1, 1])
    with tb1:
        if st.button("🆕 New chat", use_container_width=True):
            if st.session_state.soc_messages:
                save_history("SOC_" + st.session_state.session_name,
                             st.session_state.soc_messages)
            st.session_state.soc_messages = []
            st.rerun()
    with tb2:
        if st.button("💾 Save chat", use_container_width=True,
                     disabled=not st.session_state.soc_messages):
            save_history("SOC_" + st.session_state.session_name,
                         st.session_state.soc_messages)
            st.toast("✅ Chat saved!")
    with tb3:
        if st.session_state.soc_messages:
            pdf_bytes = generate_pdf(st.session_state.soc_messages,
                                     st.session_state.session_name)
            st.download_button("📄 Export PDF", data=pdf_bytes,
                file_name=f"soc_{st.session_state.session_name}.pdf",
                mime="application/pdf", use_container_width=True)

    st.divider()

    # Status από τελευταίο detection run
    results = load_detection_results()
    if results:
        st.caption(
            f"🔍 Last detection: {results['generated_at'][:16]}  |  "
            f"{results['total_logs']} logs  |  "
            f"{results['suspicious_ips_count']} suspicious IPs"
        )

    can_chat = bool(api_key and st.session_state.logging_active)
    if not can_chat:
        if not api_key:
            st.error("OPENAI_API_KEY δεν βρέθηκε στο .env αρχείο.")
        elif not st.session_state.logging_active:
            st.warning("Start monitoring from the sidebar first.")

    # Chat history
    for msg in st.session_state.soc_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Chat input
    if soc_prompt := st.chat_input(
        "Ρώτα για τα logs… π.χ. 'Ποια η πιο επικίνδυνη IP;'",
        disabled=not can_chat,
        key="soc_input",
    ):
        st.session_state.soc_messages.append(
            {"role": "user", "content": soc_prompt})
        with st.chat_message("user"):
            st.markdown(soc_prompt)

        with st.chat_message("assistant"):
            loading = st.empty()
            loading.html(LOADING_BLUE)

            try:
                # ── Βήμα 1: Τρέξε GOD_OF_DETECTION (incremental) ─────────────
                det_ok, det_out = run_detection()
                if not det_ok:
                    loading.empty()
                    st.warning(f"Detection warning: {det_out[:300]}")

                # ── Βήμα 2: Στείλε prompt στο GOD_OF_CHAT ────────────────────
                reply = ask_god_of_chat(
                    soc_prompt,
                    st.session_state.soc_messages[:-1]  # χωρίς το τρέχον
                )

                loading.empty()
                st.markdown(reply)
                st.session_state.soc_messages.append(
                    {"role": "assistant", "content": reply})
                # Auto-save
                save_history("SOC_" + st.session_state.session_name,
                             st.session_state.soc_messages)

            except Exception as e:
                loading.empty()
                st.error(f"Error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 2 — CHATBOT (απλός, βασισμένος σε raw logs)
# ══════════════════════════════════════════════════════════════════════════════
with tab_chat:
    st.title("🤖 AI Chatbot")

    tb1, tb2, tb3 = st.columns([1, 1, 1])
    with tb1:
        if st.button("🆕 New chat", use_container_width=True, key="chat_new"):
            if st.session_state.messages:
                save_history(st.session_state.session_name,
                             st.session_state.messages)
            st.session_state.messages    = []
            st.session_state.session_name = datetime.now().strftime(
                "%Y-%m-%d_%H-%M-%S")
            st.rerun()
    with tb2:
        if st.button("💾 Save chat", use_container_width=True,
                     disabled=not st.session_state.messages,
                     key="chat_save"):
            save_history(st.session_state.session_name,
                         st.session_state.messages)
            st.toast("✅ Chat saved!")
    with tb3:
        if st.session_state.messages:
            pdf_bytes = generate_pdf(st.session_state.messages,
                                     st.session_state.session_name)
            st.download_button("📄 Export PDF", data=pdf_bytes,
                file_name=f"logguard_{st.session_state.session_name}.pdf",
                mime="application/pdf", use_container_width=True,
                key="chat_pdf")

    st.divider()

    can_chat_simple = bool(api_key and selected_files
                           and st.session_state.logging_active)
    if not can_chat_simple:
        if not api_key:
            st.error("OPENAI_API_KEY δεν βρέθηκε.")
        elif not st.session_state.logging_active:
            st.warning("Start monitoring from the sidebar first.")

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if prompt := st.chat_input("Ask me about the logs…",
                                disabled=not can_chat_simple,
                                key="chat_input"):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("assistant"):
            loading = st.empty()
            loading.html(LOADING_GREEN)
            try:
                client = OpenAI(api_key=api_key)
                log_context = ""
                if os.path.exists(MASTER_FILE_PATH):
                    with open(MASTER_FILE_PATH, "r", encoding="utf-8") as f:
                        log_context = f.read()[-5000:]
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system",
                         "content": "You are a Cyber Security Analyst."},
                        {"role": "user",
                         "content": f"LOGS:\n{log_context}\n\nQUESTION: {prompt}"},
                    ],
                )
                reply = response.choices[0].message.content
                loading.empty()
                st.markdown(reply)
                st.session_state.messages.append(
                    {"role": "assistant", "content": reply})
                save_history(st.session_state.session_name,
                             st.session_state.messages)
            except Exception as e:
                loading.empty()
                st.error(f"AI Error: {e}")
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 3 — DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
with tab_dashboard:
    st.title("📊 Log Dashboard")

    if not st.session_state.logging_active or not selected_files:
        st.info("Start monitoring from the sidebar to see the dashboard.")
    else:
        dc1, dc2 = st.columns([1, 5])
        with dc1:
            if st.button("🔄 Refresh", use_container_width=True,
                         key="dash_refresh"):
                st.rerun()
        with dc2:
            st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")
        st.divider()

        total_lines  = 0
        ip_counts    = {}
        keyword_counts = {
            "Failed password": 0,
            "Accepted":        0,
            "sudo":            0,
            "Invalid user":    0,
            "error":           0,
            "UFW BLOCK":       0,
        }
        hourly_counts = {str(h).zfill(2): 0 for h in range(24)}
        ip_pattern    = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

        for rel in selected_files:
            lines = read_last_n_lines(os.path.join(WATCH_DIR, rel), 2000)
            total_lines += len(lines)
            for line in lines:
                for ip in ip_pattern.findall(line):
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                for kw in keyword_counts:
                    if kw.lower() in line.lower():
                        keyword_counts[kw] += 1
                m = re.search(r"\b(\d{2}):\d{2}:\d{2}\b", line)
                if m and m.group(1) in hourly_counts:
                    hourly_counts[m.group(1)] += 1

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("📄 Lines analysed",  f"{total_lines:,}")
        c2.metric("🚫 Failed logins",    keyword_counts["Failed password"])
        c3.metric("✅ Accepted logins",  keyword_counts["Accepted"])
        c4.metric("🔥 Firewall blocks",  keyword_counts["UFW BLOCK"])
        st.divider()

        r1l, r1r = st.columns(2)
        with r1l:
            kw_data = {k: v for k, v in keyword_counts.items() if v > 0}
            fig = bar_chart(kw_data, "Keyword frequency", color="#4da6ff")
            if fig:
                st.pyplot(fig, use_container_width=True); plt.close(fig)
            else:
                st.caption("No keyword matches yet.")
        with r1r:
            fig = pie_chart({k: v for k, v in keyword_counts.items() if v > 0},
                            "Event type breakdown")
            if fig:
                st.pyplot(fig, use_container_width=True); plt.close(fig)
            else:
                st.caption("No data yet.")

        st.divider()
        fig = hourly_bar(hourly_counts, "Activity by hour  (🟠 = busiest)")
        if fig:
            st.pyplot(fig, use_container_width=True); plt.close(fig)
        else:
            st.caption("No timestamped entries found.")

        st.divider()
        if ip_counts:
            top_ips = dict(sorted(ip_counts.items(),
                                  key=lambda x: x[1], reverse=True)[:10])
            r3l, r3r = st.columns(2)
            with r3l:
                fig = bar_chart(top_ips, "Top 10 IPs", color="#ffa600")
                if fig:
                    st.pyplot(fig, use_container_width=True); plt.close(fig)
            with r3r:
                fig = pie_chart(top_ips, "Top IPs — share of traffic")
                if fig:
                    st.pyplot(fig, use_container_width=True); plt.close(fig)
        else:
            st.caption("No IPs found.")


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 4 — LIVE LOGS
# ══════════════════════════════════════════════════════════════════════════════
with tab_live:
    st.title("📡 Live Logs")

    if not st.session_state.logging_active or not selected_files:
        st.info("Start monitoring from the sidebar to see live logs.")
    else:
        now_str = datetime.now().strftime("%H:%M:%S")
        top1, top2, top3 = st.columns([3, 1, 1])
        with top1:
            st.html(f"""
<style>
@keyframes pulse {{
  0%,100%{{ opacity:1; transform:scale(1); }}
  50%     {{ opacity:0.3; transform:scale(0.8); }}
}}
</style>
<div style="display:flex;align-items:center;gap:10px;background:#0e1117;
            border:1px solid #1a3a1a;border-radius:8px;padding:7px 14px;">
  <div style="width:10px;height:10px;border-radius:50%;background:#00e676;
              flex-shrink:0;animation:pulse 1.4s ease-in-out infinite;"></div>
  <span style="color:#00e676;font-size:13px;font-weight:600;
               font-family:monospace;">LIVE</span>
  <span style="color:#555;font-size:12px;font-family:monospace;">{now_str}</span>
</div>""")
        with top2:
            if st.button("🔄 Refresh", use_container_width=True, key="live_ref"):
                st.rerun()
        with top3:
            auto = st.toggle("Auto 4s", key="live_auto")

        n_lines = st.slider("Lines per file", 50, 500, 150, step=50,
                            key="live_slider")
        search  = st.text_input("Filter",
                                placeholder="e.g. sshd, sudo, 192.168",
                                label_visibility="collapsed")

        for rel in selected_files:
            lines = read_last_n_lines(os.path.join(WATCH_DIR, rel), n_lines)
            if search:
                lines = [l for l in lines if search.lower() in l.lower()]
            with st.expander(f"📄 {rel}  ({len(lines)} lines)", expanded=True):
                if not lines:
                    st.caption("No lines match your filter.")
                else:
                    rows = "".join(
                        '<div style="font-family:monospace;font-size:12px;'
                        'padding:1px 4px;color:#c8c8c8;">'
                        + l.replace("&","&amp;").replace("<","&lt;")
                                   .replace(">","&gt;")
                        + "</div>" for l in lines)
                    st.html('<div style="background:#0e1117;border-radius:6px;'
                            'padding:10px;max-height:320px;overflow-y:auto;'
                            'border:1px solid #2a2a2a;">' + rows + "</div>")

        if auto:
            time.sleep(4)
            st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 5 — HISTORY
# ══════════════════════════════════════════════════════════════════════════════
with tab_history:
    st.title("🕓 Chat History")
    sessions = load_all_sessions()
    if not sessions:
        st.info("No saved sessions yet.")
    else:
        sel = st.selectbox("Select a session:", options=list(sessions.keys()))
        if sel:
            msgs = sessions[sel]
            st.caption(f"{len(msgs)} messages · {sel}")
            st.divider()
            for msg in msgs:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])
            st.divider()
            hc1, hc2 = st.columns([1, 1])
            with hc1:
                pdf_bytes = generate_pdf(msgs, sel)
                st.download_button("📄 Export PDF", data=pdf_bytes,
                    file_name=f"logguard_{sel}.pdf", mime="application/pdf",
                    key="hist_pdf", use_container_width=True)
            with hc2:
                if st.button("🗑️ Delete session", key="del_session",
                             use_container_width=True):
                    path = os.path.join(HISTORY_DIR, f"{sel}.json")
                    if os.path.exists(path):
                        os.remove(path)
                    st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 6 — FLAGGED IPs
# ══════════════════════════════════════════════════════════════════════════════
with tab_flags:
    st.title("🚩 Flagged IPs")
    flags = load_flags()

    st.subheader("IPs detected in logs")
    if not selected_files or not st.session_state.logging_active:
        st.info("Start monitoring to detect IPs.")
    else:
        ip_counts = extract_ips_from_logs(selected_files, 1000)
        if not ip_counts:
            st.caption("No IPs found.")
        else:
            for ip, count in list(ip_counts.items())[:30]:
                is_flagged = flags.get(ip, {}).get("flagged", False)
                col_ip, col_count, col_flag, col_note = st.columns([2, 1, 1, 4])
                with col_ip:
                    st.markdown(f"{'🚩' if is_flagged else '  '} `{ip}`")
                with col_count:
                    st.caption(f"{count} hits")
                with col_flag:
                    if st.button("Unflag" if is_flagged else "🚩 Flag",
                                 key=f"flag_{ip}", use_container_width=True):
                        if ip not in flags:
                            flags[ip] = {}
                        flags[ip]["flagged"] = not is_flagged
                        save_flags(flags)
                        st.rerun()
                with col_note:
                    note = st.text_input("Note", key=f"note_{ip}",
                        value=flags.get(ip, {}).get("note", ""),
                        placeholder="add a note…",
                        label_visibility="collapsed")
                    if note != flags.get(ip, {}).get("note", ""):
                        if ip not in flags:
                            flags[ip] = {}
                        flags[ip]["note"] = note
                        save_flags(flags)

    st.divider()
    st.subheader("All flagged IPs")
    flagged = {ip: d for ip, d in flags.items() if d.get("flagged")}
    if not flagged:
        st.caption("No flagged IPs yet.")
    else:
        for ip, d in flagged.items():
            fc1, fc2, fc3 = st.columns([2, 4, 1])
            with fc1:
                st.markdown(f"🚩 `{ip}`")
            with fc2:
                st.caption(d.get("note", "—"))
            with fc3:
                if st.button("Remove", key=f"remflag_{ip}",
                             use_container_width=True):
                    flags[ip]["flagged"] = False
                    save_flags(flags)
                    st.rerun()


# ── FRAGMENT — log engine ──────────────────────────────────────────────────────
@st.fragment(run_every="2s")
def log_engine():
    if st.session_state.logging_active and selected_files:
        if "last_pos" not in st.session_state:
            st.session_state.last_pos = {}
        with open(MASTER_FILE_PATH, "a", encoding="utf-8") as master:
            for f_name in selected_files:
                full_path = os.path.join(WATCH_DIR, f_name)
                if os.path.exists(full_path):
                    with open(full_path, "r", encoding="utf-8",
                              errors="ignore") as f:
                        f.seek(st.session_state.last_pos.get(f_name, 0))
                        new_data = f.read()
                        if new_data:
                            master.write(
                                f"\n[SOURCE: {f_name} | "
                                f"{time.strftime('%H:%M:%S')}]\n{new_data}")
                            st.session_state.last_pos[f_name] = f.tell()

log_engine()
