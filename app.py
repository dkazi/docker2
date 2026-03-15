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

# --- 1. ΑΝΙΧΝΕΥΣΗ ΑΡΧΕΙΩΝ ---
files = []
if os.path.exists(WATCH_DIR):
    for root, dirs, filenames in os.walk(WATCH_DIR):
        for filename in filenames:
            rel_path = os.path.relpath(os.path.join(root, filename), WATCH_DIR)
            files.append(rel_path)
    files.sort()

# --- 2. SIDEBAR: ΡΥΘΜΙΣΕΙΣ ---
st.sidebar.header("⚙️ System Settings")

api_key = st.sidebar.text_input(
    "OpenAI API Key:",
    type="password",
    autocomplete="new-password"
)

st.sidebar.markdown("---")
st.sidebar.subheader("📁 Log Sources")

selected_files = st.sidebar.multiselect(
    "Select Files:",
    options=files,
    default=None,
    disabled=st.session_state.logging_active,
    key=f"files_{st.session_state.multiselect_key}"
)

col1, col2 = st.sidebar.columns(2)
with col1:
    if not st.session_state.logging_active:
        if st.button("✅ Start", type="primary", use_container_width=True):
            if selected_files:
                st.session_state.logging_active = True
                with open(MASTER_FILE_PATH, "w", encoding="utf-8") as f:
                    f.write(f"--- SESSION START: {time.strftime('%H:%M:%S')} ---\n")
                st.rerun()
            else:
                st.sidebar.warning("Select files!")
with col2:
    if st.button("🗑️ Reset", use_container_width=True):
        st.session_state.logging_active = False
        st.session_state.messages = []
        st.session_state.multiselect_key += 1
        if 'last_pos' in st.session_state:
            del st.session_state.last_pos
        if os.path.exists(MASTER_FILE_PATH):
            os.remove(MASTER_FILE_PATH)
        st.rerun()

# --- 3. ΚΥΡΙΟ GUI: CHATBOT ---
st.title("🤖 AI Security Analyst")

# Έλεγχος αν επιτρέπεται το chat
can_chat = api_key and selected_files and st.session_state.logging_active

# Προβολή μηνυμάτων
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat Input (Disabled αν δεν πληρούνται οι προϋποθέσεις)
prompt = st.chat_input(
    "Ask me about the security logs..." if can_chat else "Provide API Key, Select Files and press Start to chat",
    disabled=not can_chat
)

if prompt:
    # Προσθήκη και εμφάνιση του χρήστη αμέσως
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Διάβασμα Context
    log_context = ""
    if os.path.exists(MASTER_FILE_PATH):
        with open(MASTER_FILE_PATH, "r", encoding="utf-8") as f:
            log_context = f.read()[-5000:]

    # AI Response
    try:
        client = OpenAI(api_key=api_key)
        with st.chat_message("assistant"):
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a Cyber Security Analyst. Analyze the logs provided."},
                    {"role": "user", "content": f"LOGS:\n{log_context}\n\nQUESTION: {prompt}"}
                ]
            )
            answer = response.choices[0].message.content
            st.markdown(answer)
            st.session_state.messages.append({"role": "assistant", "content": answer})
    except Exception as e:
        st.error(f"AI Error: {e}")

# --- 4. BACKGROUND LOGGING ENGINE ---
if st.session_state.logging_active and selected_files:
    # Χρήση ενός σταθερού container για το status στο sidebar για αποφυγή flickering
    st.sidebar.markdown("---")
    st.sidebar.success("📡 System Monitoring Active")
   
    if 'last_pos' not in st.session_state:
        st.session_state.last_pos = {f: 0 for f in selected_files}

    # Εκτέλεση του logging
    with open(MASTER_FILE_PATH, "a", encoding="utf-8") as master:
        for f_name in selected_files:
            full_path = os.path.join(WATCH_DIR, f_name)
            if os.path.exists(full_path):
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(st.session_state.last_pos.get(f_name, 0))
                    new_data = f.read()
                    if new_data:
                        header = f"\n[SOURCE: {f_name} | {time.strftime('%H:%M:%S')}]\n"
                        master.write(header + new_data)
                        st.session_state.last_pos[f_name] = f.tell()
   
    # Το rerun γίνεται μόνο αν δεν υπάρχει ενεργό chat input αυτή τη στιγμή
    time.sleep(2)
    st.rerun()
