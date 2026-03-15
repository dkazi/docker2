import streamlit as st
import os, time, json, re, subprocess, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from datetime import datetime
from openai import OpenAI

WATCH_DIR        = "/data_to_monitor"
MASTER_FILE_PATH = "/app/master_log.txt"
HISTORY_DIR      = "/app/chat_history"
FLAGS_FILE       = "/app/flagged_ips.json"
RESULTS_FILE     = "/app/detection_results.json"
os.makedirs(HISTORY_DIR, exist_ok=True)

st.set_page_config(page_title="LogGuard AI", layout="wide", page_icon="🛡️")

api_key = os.getenv("OPENAI_API_KEY", "")

for k, v in {
    "logging_active":  False,
    "soc_messages":    [],
    "multiselect_key": 0,
    "last_pos":        {},
    "session_name":    datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
}.items():
    if k not in st.session_state:
        st.session_state[k] = v

files = []
if os.path.exists(WATCH_DIR):
    for root, _, fnames in os.walk(WATCH_DIR):
        for fn in fnames:
            files.append(os.path.relpath(os.path.join(root, fn), WATCH_DIR))
    files.sort()

def read_last_n(path, n=200):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if not size: return []
            f.seek(-min(size, n*250), 2)
            return f.read().decode("utf-8", errors="replace").splitlines()[-n:]
    except:
        return []

def save_history(name, msgs):
    with open(os.path.join(HISTORY_DIR, f"{name}.json"), "w", encoding="utf-8") as f:
        json.dump({"session": name, "messages": msgs}, f, ensure_ascii=False, indent=2)

def load_sessions():
    out = {}
    for fn in sorted(os.listdir(HISTORY_DIR), reverse=True):
        if fn.endswith(".json"):
            try:
                with open(os.path.join(HISTORY_DIR, fn), encoding="utf-8") as f:
                    d = json.load(f)
                out[fn[:-5]] = d.get("messages", [])
            except: pass
    return out

def load_results():
    try:
        with open(RESULTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except: return None

def run_detection():
    env = os.environ.copy()
    env["OPENAI_API_KEY"] = api_key
    env["LOG_FILE_PATH"]  = MASTER_FILE_PATH
    env["CHROMA_PATH"]    = "/app/chroma_db_v2"
    try:
        r = subprocess.run(["python3", "/app/GOD_OF_DETECTION.py"],
            capture_output=True, text=True, cwd="/app", env=env, timeout=300)
        return r.returncode == 0, r.stdout + r.stderr
    except Exception as e:
        return False, str(e)

def ask_soc(question, history):
    import GOD_OF_CHAT as gc
    results = load_results()
    if not results:
        return "❌ Δεν υπάρχουν detection results ακόμα. Βεβαιώσου ότι έχεις ξεκινήσει monitoring."
    h = [m for m in history if m["role"] in ("user","assistant")][-4:]
    return gc.ask(question, results, h)

def make_pdf(msgs, name):
    lines = ["LogGuard SOC Export", f"Session: {name}", ""]
    for m in msgs:
        lines.append(f"[{'You' if m['role']=='user' else 'SOC AI'}]")
        for p in m["content"].split("\n"):
            while len(p) > 90: lines.append(p[:90]); p = p[90:]
            lines.append(p)
        lines.append("")
    body = b""
    offs = []
    def wo(oid, c):
        nonlocal body
        offs.append(len(b"%PDF-1.4\n")+len(body))
        body += f"{oid} 0 obj\n{c}\nendobj\n".encode()
    sl = ["BT","/F1 10 Tf","50 780 Td"]; y=780
    for ln in lines:
        s = ln.replace("\\","\\\\").replace("(","\\(").replace(")","\\)").encode("latin-1",errors="replace").decode("latin-1")
        sl.append(f"({s}) Tj"); y-=14
        if y<50: sl+=["ET","BT","/F1 10 Tf","50 780 Td"]; y=780
        else: sl.append("0 -14 Td")
    sl.append("ET")
    sb = "\n".join(sl).encode("latin-1",errors="replace")
    wo(1,"<< /Type /Catalog /Pages 2 0 R >>")
    wo(2,"<< /Type /Pages /Kids [4 0 R] /Count 1 >>")
    wo(3,"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    wo(4,"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Contents 5 0 R /Resources << /Font << /F1 3 0 R >> >> >>")
    wo(5,f"<< /Length {len(sb)} >>\nstream\n"+sb.decode("latin-1")+"\nendstream")
    xo = len(b"%PDF-1.4\n")+len(body)
    xref = "xref\n0 6\n0000000000 65535 f \n"+"".join(f"{o:010d} 00000 n \n" for o in offs)
    return b"%PDF-1.4\n"+body+xref.encode()+f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xo}\n%%EOF".encode()

def load_flags():
    try:
        with open(FLAGS_FILE) as f: return json.load(f)
    except: return {}

def save_flags(d):
    with open(FLAGS_FILE,"w") as f: json.dump(d,f,indent=2)

DARK="#0e1117"; FG="#c8c8c8"; GRID="#2a2a2a"
ACC=["#4da6ff","#ff4b4b","#ffa600","#00e676","#bf5af2","#ff6b6b","#48dbfb","#ffd32a"]

def _fig(w=7,h=3.2):
    f,a=plt.subplots(figsize=(w,h))
    f.patch.set_facecolor(DARK); a.set_facecolor(DARK)
    a.tick_params(colors=FG,labelsize=8); a.spines[:].set_color(GRID)
    a.yaxis.grid(True,color=GRID,linewidth=0.5); a.set_axisbelow(True)
    return f,a

def barchart(data,title,color="#4da6ff"):
    if not data: return None
    f,a=_fig(); k,v=list(data.keys()),list(data.values())
    bars=a.bar(k,v,color=color,width=0.6,zorder=3)
    a.set_title(title,color=FG,fontsize=10,pad=8)
    a.set_xticklabels(k,rotation=35,ha="right",fontsize=7)
    for b,val in zip(bars,v):
        a.text(b.get_x()+b.get_width()/2,b.get_height()+0.3,str(val),ha="center",va="bottom",color=FG,fontsize=7)
    f.tight_layout(); return f

def piechart(data,title):
    if not data: return None
    items=sorted(data.items(),key=lambda x:x[1],reverse=True)
    if len(items)>6:
        top=dict(items[:6]); top["Other"]=sum(v for _,v in items[6:]); items=list(top.items())
    lb=[k for k,_ in items]; vl=[v for _,v in items]
    f,a=_fig(5,4)
    w,_,at=a.pie(vl,colors=ACC[:len(lb)],autopct="%1.0f%%",startangle=140,
        wedgeprops={"linewidth":0.5,"edgecolor":DARK},pctdistance=0.78)
    for t in at: t.set_color(DARK); t.set_fontsize(8); t.set_fontweight("bold")
    a.legend(w,lb,loc="lower center",bbox_to_anchor=(0.5,-0.18),ncol=3,fontsize=7,frameon=False,labelcolor=FG)
    a.set_title(title,color=FG,fontsize=10,pad=10); f.tight_layout(); return f

def hourbarchart(hourly,title):
    if not any(hourly.values()): return None
    f,a=_fig(8,3); h,v=list(hourly.keys()),list(hourly.values())
    bars=a.bar(h,v,color="#4da6ff",width=0.7,zorder=3)
    a.set_title(title,color=FG,fontsize=10,pad=8)
    a.set_xlabel("Hour (00-23)",color=FG,fontsize=8); a.tick_params(axis="x",labelsize=6)
    if v:
        pk=max(v)
        for b,val in zip(bars,v):
            if val==pk and pk>0: b.set_color("#ffa600")
    f.tight_layout(); return f

LOADING = """<style>@keyframes blink{0%,100%{opacity:1}50%{opacity:0.2}}</style>
<div style="display:flex;align-items:center;gap:10px;padding:8px 0;">
<div style="display:flex;gap:5px;">
<div style="width:8px;height:8px;border-radius:50%;background:#4da6ff;animation:blink 1.2s ease-in-out infinite;"></div>
<div style="width:8px;height:8px;border-radius:50%;background:#4da6ff;animation:blink 1.2s ease-in-out infinite 0.2s;"></div>
<div style="width:8px;height:8px;border-radius:50%;background:#4da6ff;animation:blink 1.2s ease-in-out infinite 0.4s;"></div>
</div>
<span style="color:#4da6ff;font-size:13px;font-family:monospace;">SOC Analyst analyzing…</span></div>"""

# ── SIDEBAR ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ LogGuard AI")
    st.success("✅ API Key loaded.") if api_key else st.error("⚠️ OPENAI_API_KEY missing in .env")
    st.markdown("---")
    st.subheader("📁 Log Sources")
    selected = st.multiselect("Select files:", options=files, default=None,
        disabled=st.session_state.logging_active,
        key=f"files_{st.session_state.multiselect_key}")
    if not st.session_state.logging_active:
        if st.button("✅ Start Monitoring", type="primary", use_container_width=True):
            if selected:
                st.session_state.logging_active = True
                st.session_state.session_name = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                st.session_state.last_pos = {}
                with open(MASTER_FILE_PATH, "w", encoding="utf-8") as f:
                    f.write(f"--- SESSION START: {time.strftime('%H:%M:%S')} ---\n")
                st.rerun()
            else:
                st.warning("Select at least one file!")
    else:
        if st.button("🗑️ Reset & Clear", type="secondary", use_container_width=True):
            st.session_state.logging_active  = False
            st.session_state.soc_messages    = []
            st.session_state.multiselect_key += 1
            st.session_state.last_pos        = {}
            if os.path.exists(MASTER_FILE_PATH): os.remove(MASTER_FILE_PATH)
            st.rerun()
        st.success("📡 Monitoring Active")

# ── TABS ───────────────────────────────────────────────────────────────────────
t1, t2, t3, t4, t5 = st.tabs(["🛡️ SOC Analysis","📊 Dashboard","📡 Live Logs","🕓 History","🚩 Flagged IPs"])

# ══ SOC ANALYSIS ══════════════════════════════════════════════════════════════
with t1:
    st.title("🛡️ SOC Analysis")
    c1,c2,c3 = st.columns(3)
    with c1:
        if st.button("🆕 New chat", use_container_width=True):
            if st.session_state.soc_messages:
                save_history("SOC_"+st.session_state.session_name, st.session_state.soc_messages)
            st.session_state.soc_messages = []
            st.rerun()
    with c2:
        if st.button("💾 Save", use_container_width=True, disabled=not st.session_state.soc_messages):
            save_history("SOC_"+st.session_state.session_name, st.session_state.soc_messages)
            st.toast("✅ Saved!")
    with c3:
        if st.session_state.soc_messages:
            st.download_button("📄 PDF", data=make_pdf(st.session_state.soc_messages, st.session_state.session_name),
                file_name=f"soc_{st.session_state.session_name}.pdf", mime="application/pdf", use_container_width=True)
    st.divider()
    res = load_results()
    if res:
        st.caption(f"🔍 Last run: {res['generated_at'][:16]} | {res['total_logs']} logs | {res['suspicious_ips_count']} suspicious IPs")
    can = bool(api_key and st.session_state.logging_active)
    if not can:
        st.error("OPENAI_API_KEY missing.") if not api_key else st.warning("Start monitoring first.")
    for m in st.session_state.soc_messages:
        with st.chat_message(m["role"]): st.markdown(m["content"])
    if prompt := st.chat_input("Ask the SOC analyst…", disabled=not can, key="soc_input"):
        st.session_state.soc_messages.append({"role":"user","content":prompt})
        with st.chat_message("user"): st.markdown(prompt)
        with st.chat_message("assistant"):
            loading = st.empty()
            loading.html(LOADING)
            try:
                run_detection()
                reply = ask_soc(prompt, st.session_state.soc_messages[:-1])
                loading.empty()
                st.markdown(reply)
                st.session_state.soc_messages.append({"role":"assistant","content":reply})
                save_history("SOC_"+st.session_state.session_name, st.session_state.soc_messages)
            except Exception as e:
                loading.empty()
                st.error(f"Error: {e}")

# ══ DASHBOARD ══════════════════════════════════════════════════════════════════
with t2:
    st.title("📊 Dashboard")
    if not st.session_state.logging_active or not selected:
        st.info("Start monitoring to see dashboard.")
    else:
        c1,c2=st.columns([1,5])
        with c1:
            if st.button("🔄 Refresh", key="dr"): st.rerun()
        with c2:
            st.caption(datetime.now().strftime("%H:%M:%S"))
        st.divider()
        total=0; ips={}
        kw={"Failed password":0,"Accepted":0,"sudo":0,"Invalid user":0,"error":0,"UFW BLOCK":0}
        hr={str(h).zfill(2):0 for h in range(24)}
        ipr=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        for rel in selected:
            lns=read_last_n(os.path.join(WATCH_DIR,rel),2000); total+=len(lns)
            for ln in lns:
                for ip in ipr.findall(ln): ips[ip]=ips.get(ip,0)+1
                for k in kw:
                    if k.lower() in ln.lower(): kw[k]+=1
                m=re.search(r"\b(\d{2}):\d{2}:\d{2}\b",ln)
                if m and m.group(1) in hr: hr[m.group(1)]+=1
        c1,c2,c3,c4=st.columns(4)
        c1.metric("📄 Lines",f"{total:,}"); c2.metric("🚫 Failed",kw["Failed password"])
        c3.metric("✅ Accepted",kw["Accepted"]); c4.metric("🔥 UFW Block",kw["UFW BLOCK"])
        st.divider()
        r1,r2=st.columns(2)
        with r1:
            f=barchart({k:v for k,v in kw.items() if v},"Keyword frequency")
            if f: st.pyplot(f,use_container_width=True); plt.close(f)
        with r2:
            f=piechart({k:v for k,v in kw.items() if v},"Event breakdown")
            if f: st.pyplot(f,use_container_width=True); plt.close(f)
        st.divider()
        f=hourbarchart(hr,"Activity by hour")
        if f: st.pyplot(f,use_container_width=True); plt.close(f)
        st.divider()
        if ips:
            top=dict(sorted(ips.items(),key=lambda x:x[1],reverse=True)[:10])
            r1,r2=st.columns(2)
            with r1:
                f=barchart(top,"Top 10 IPs","#ffa600")
                if f: st.pyplot(f,use_container_width=True); plt.close(f)
            with r2:
                f=piechart(top,"Top IPs traffic share")
                if f: st.pyplot(f,use_container_width=True); plt.close(f)

# ══ LIVE LOGS ══════════════════════════════════════════════════════════════════
with t3:
    st.title("📡 Live Logs")
    if not st.session_state.logging_active or not selected:
        st.info("Start monitoring to see live logs.")
    else:
        now=datetime.now().strftime("%H:%M:%S")
        c1,c2,c3=st.columns([3,1,1])
        with c1:
            st.html(f"""<style>@keyframes pulse{{0%,100%{{opacity:1;transform:scale(1)}}50%{{opacity:0.3;transform:scale(0.8)}}}}</style>
<div style="display:flex;align-items:center;gap:10px;background:#0e1117;border:1px solid #1a3a1a;border-radius:8px;padding:7px 14px;">
<div style="width:10px;height:10px;border-radius:50%;background:#00e676;flex-shrink:0;animation:pulse 1.4s ease-in-out infinite;"></div>
<span style="color:#00e676;font-size:13px;font-weight:600;font-family:monospace;">LIVE</span>
<span style="color:#555;font-size:12px;font-family:monospace;">{now}</span></div>""")
        with c2:
            if st.button("🔄 Refresh", key="lr"): st.rerun()
        with c3:
            auto=st.toggle("Auto 4s",key="la")
        n=st.slider("Lines",50,500,150,step=50,key="ls")
        srch=st.text_input("Filter",placeholder="sshd, 192.168, sudo",label_visibility="collapsed")
        for rel in selected:
            lns=read_last_n(os.path.join(WATCH_DIR,rel),n)
            if srch: lns=[l for l in lns if srch.lower() in l.lower()]
            with st.expander(f"📄 {rel} ({len(lns)} lines)",expanded=True):
                if not lns: st.caption("No lines.")
                else:
                    rows="".join(f'<div style="font-family:monospace;font-size:12px;padding:1px 4px;color:#c8c8c8;">{l.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")}</div>' for l in lns)
                    st.html(f'<div style="background:#0e1117;border-radius:6px;padding:10px;max-height:320px;overflow-y:auto;border:1px solid #2a2a2a;">{rows}</div>')
        if auto: time.sleep(4); st.rerun()

# ══ HISTORY ═══════════════════════════════════════════════════════════════════
with t4:
    st.title("🕓 History")
    sessions=load_sessions()
    if not sessions: st.info("No saved sessions yet.")
    else:
        sel=st.selectbox("Session:",list(sessions.keys()))
        if sel:
            msgs=sessions[sel]
            st.caption(f"{len(msgs)} messages · {sel}"); st.divider()
            for m in msgs:
                with st.chat_message(m["role"]): st.markdown(m["content"])
            st.divider()
            h1,h2=st.columns(2)
            with h1:
                st.download_button("📄 Export PDF",data=make_pdf(msgs,sel),
                    file_name=f"soc_{sel}.pdf",mime="application/pdf",key="hpdf",use_container_width=True)
            with h2:
                if st.button("🗑️ Delete",key="hdel",use_container_width=True):
                    p=os.path.join(HISTORY_DIR,f"{sel}.json")
                    if os.path.exists(p): os.remove(p)
                    st.rerun()

# ══ FLAGGED IPs ═══════════════════════════════════════════════════════════════
with t5:
    st.title("🚩 Flagged IPs")
    flags=load_flags()
    if not selected or not st.session_state.logging_active:
        st.info("Start monitoring to detect IPs.")
    else:
        ipr=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"); counts={}
        for rel in selected:
            for ln in read_last_n(os.path.join(WATCH_DIR,rel),1000):
                for ip in ipr.findall(ln): counts[ip]=counts.get(ip,0)+1
        counts=dict(sorted(counts.items(),key=lambda x:x[1],reverse=True))
        for ip,cnt in list(counts.items())[:30]:
            flagged=flags.get(ip,{}).get("flagged",False)
            c1,c2,c3,c4=st.columns([2,1,1,4])
            with c1: st.markdown(f"{'🚩' if flagged else '  '} `{ip}`")
            with c2: st.caption(f"{cnt} hits")
            with c3:
                if st.button("Unflag" if flagged else "🚩 Flag",key=f"f_{ip}",use_container_width=True):
                    if ip not in flags: flags[ip]={}
                    flags[ip]["flagged"]=not flagged; save_flags(flags); st.rerun()
            with c4:
                note=st.text_input("Note",key=f"n_{ip}",value=flags.get(ip,{}).get("note",""),
                    placeholder="note…",label_visibility="collapsed")
                if note!=flags.get(ip,{}).get("note",""):
                    if ip not in flags: flags[ip]={}
                    flags[ip]["note"]=note; save_flags(flags)
    st.divider(); st.subheader("All flagged")
    flagged_all={ip:d for ip,d in flags.items() if d.get("flagged")}
    if not flagged_all: st.caption("None yet.")
    else:
        for ip,d in flagged_all.items():
            c1,c2,c3=st.columns([2,4,1])
            with c1: st.markdown(f"🚩 `{ip}`")
            with c2: st.caption(d.get("note","—"))
            with c3:
                if st.button("Remove",key=f"r_{ip}",use_container_width=True):
                    flags[ip]["flagged"]=False; save_flags(flags); st.rerun()

# ── LOG ENGINE FRAGMENT ────────────────────────────────────────────────────────
@st.fragment(run_every="2s")
def log_engine():
    if st.session_state.logging_active and selected:
        if "last_pos" not in st.session_state: st.session_state.last_pos={}
        with open(MASTER_FILE_PATH,"a",encoding="utf-8") as master:
            for fn in selected:
                fp=os.path.join(WATCH_DIR,fn)
                if os.path.exists(fp):
                    with open(fp,"r",encoding="utf-8",errors="ignore") as f:
                        f.seek(st.session_state.last_pos.get(fn,0))
                        data=f.read()
                        if data:
                            master.write(f"\n[SOURCE: {fn} | {time.strftime('%H:%M:%S')}]\n{data}")
                            st.session_state.last_pos[fn]=f.tell()

log_engine()
