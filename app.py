import streamlit as st
import os
import time
from openai import OpenAI

# --- ΡΥΘΜΙΣΕΙΣ PATHS ---
WATCH_DIR = "/data_to_monitor"
MASTER_FILE_PATH = "/app/master_log.txt"

st.set_page_config(page_title="AI Log Security Analyst", layout="wide", page_icon="🛡️")

# --- INITIALIZATION ---
if 'logging_active' not in st.session_state:
    st.session_state.logging_active = False
if "messages" not in st.session_state:
    st.session_state.messages = []
if 'multiselect_key' not in st.session_state:
    st.session_state.multiselect_key = 0
if 'ai_error' not in st.session_state:
    st.session_state.ai_error = None

# --- 1. ΑΝΙΧΝΕΥΣΗ ΑΡΧΕΙΩΝ ---
files = []
if os.path.exists(WATCH_DIR):
    for root, dirs, filenames in os.walk(WATCH_DIR):
        for filename in filenames:
            rel_path = os.path.relpath(os.path.join(root, filename), WATCH_DIR)
            files.append(rel_path)
    files.sort()

# --- 2. SIDEBAR: ΡΥΘΜΙΣΕΙΣ ---
with st.sidebar:
    st.header("⚙️ System Settings")
    api_key = st.text_input("OpenAI API Key:", type="password", autocomplete="new-password")
    st.markdown("---")
    st.subheader("📁 Log Sources")

    selected_files = st.multiselect(
        "Select Files:", options=files, default=None,
        disabled=st.session_state.logging_active,
        key=f"files_{st.session_state.multiselect_key}"
    )

    if not st.session_state.logging_active:
        if st.button("✅ Start", type="primary", use_container_width=True):
            if selected_files:
                st.session_state.logging_active = True
                with open(MASTER_FILE_PATH, "w", encoding="utf-8") as f:
                    f.write(f"--- SESSION START: {time.strftime('%H:%M:%S')} ---\n")
                st.rerun()
            else:
                st.warning("Select files!")
    else:
        if st.button("🗑️ Reset & Clear All", type="secondary", use_container_width=True):
            st.session_state.logging_active = False
            st.session_state.messages = []
            st.session_state.ai_error = None
            st.session_state.multiselect_key += 1
            if 'last_pos' in st.session_state: del st.session_state.last_pos
            if os.path.exists(MASTER_FILE_PATH): os.remove(MASTER_FILE_PATH)
            st.rerun()

    if st.session_state.logging_active:
        st.markdown("---")
        st.success("📡 System Monitoring Active")
   
    if st.session_state.ai_error:
        st.error(st.session_state.ai_error)

# --- 3. ΚΥΡΙΟ GUI: CHATBOT ---
st.title("🤖 AI Security Analyst")
can_chat = api_key and selected_files and st.session_state.logging_active

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

if prompt := st.chat_input("Ask me about the logs...", disabled=not can_chat):
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.session_state.ai_error = None
   
    try:
        client = OpenAI(api_key=api_key)
        log_context = ""
        if os.path.exists(MASTER_FILE_PATH):
            with open(MASTER_FILE_PATH, "r", encoding="utf-8") as f:
                log_context = f.read()[-5000:]

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a Cyber Security Analyst."},
                {"role": "user", "content": f"LOGS:\n{log_context}\n\nQUESTION: {prompt}"}
            ]
        )
        st.session_state.messages.append({"role": "assistant", "content": response.choices[0].message.content})
    except:
        st.session_state.ai_error = "AI Error: Check your API Key."
    st.rerun()

# --- 4. THE MAGIC FRAGMENT (ANTI-FLICKER) ---
@st.fragment(run_every="2s")
def log_engine():
    if st.session_state.logging_active and selected_files:
        if 'last_pos' not in st.session_state:
            st.session_state.last_pos = {f: 0 for f in selected_files}

        with open(MASTER_FILE_PATH, "a", encoding="utf-8") as master:
            for f_name in selected_files:
                full_path = os.path.join(WATCH_DIR, f_name)
                if os.path.exists(full_path):
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(st.session_state.last_pos.get(f_name, 0))
                        new_data = f.read()
                        if new_data:
                            master.write(f"\n[SOURCE: {f_name} | {time.strftime('%H:%M:%S')}]\n{new_data}")
                            st.session_state.last_pos[f_name] = f.tell()

# Καλούμε το fragment
log_engine()
