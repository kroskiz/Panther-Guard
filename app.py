import streamlit as st
from pathlib import Path

import pandas as pd
import json

# ---------------------------------------------------------
# Page Configuration & FIU Custom Styling
# ---------------------------------------------------------
st.set_page_config(
    page_title="Panther Guard Security Dashboard",
    page_icon="🐆",
    layout="wide"
)

LOG_FILE =Path(__file__).parent / "data" / "security_logs.json"

THREAT_LABELS = {"low": "Safe", "medium": "Warning", "high": "Critical"}

SAMPLE_LOGS = [
    {"status": "running", "process_name": "chrome.exe", "threat_level": "low", "timestamp": "2026-11-01T10:15:00"},
    {"status": "running", "process_name": "explorer.exe", "threat_level": "low", "timestamp": "2026-11-01T10:15:05"},
    {"status": "running", "process_name": "updater.exe", "threat_level": "medium", "timestamp": "2026-11-01T10:16:10"},
    {"status": "running", "process_name": "unknown_tool.exe", "threat_level": "high", "timestamp": "2026-11-01T10:16:30"},
    {"status": "stopped", "process_name": "setup_helper.exe", "threat_level": "medium", "timestamp": "2026-11-01T10:17:45"},
]

def load_logs():
    """Read the log file. If it's missing or unusable, return sample data."""
    try:
        with open(LOG_FILE, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return SAMPLE_LOGS

    if isinstance(data, dict):
        data = [data]
    if isinstance(data, list) and len(data) > 0:
        return data
    return SAMPLE_LOGS

def color_threat(value):
  if value == "Critical":
    return "background-color: #B3261E; color: white; font-weight: bold"
  if value == "Warning":
        return "background-color: #C5960C; color: #001538; font-weight: bold"
  return ""

st.markdown(
    """
    <style>
    /* --- Kroskiz's Global Theme & Layout --- */
    .stApp {
        background-color: #001538;
        color: #FFFFFF;
    }
    .fiu-gold-text {
        color: #C5960C;
        font-weight: bold;
    }
    .fiu-card {
        background-color: #002255;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #C5960C;
        margin-bottom: 15px;
    }
    .threat-banner {
        padding: 12px;
        border-radius: 6px;
        margin-bottom: 12px;
        font-weight: 500;
    }
    [data-testid="stSidebar"] {
        background-color: #000F29;
    }

    /* --- Kimarni's Refined Metrics & Responsive Containers --- */
    [data-testid="stMetric"] {
        background-color: #0A2250;
        border-left: 5px solid #C5960C;
        border-radius: 8px;
        padding: 12px 16px;
    }
    [data-testid="stMetricLabel"],
    [data-testid="stMetricLabel"] p {
        color: #C5960C;
        font-weight: 600;
    }
    [data-testid="stMetricValue"] {
        color: #FFFFFF;
    }
    .block-container {
        padding-top: 2rem;
        padding-left: 2rem;
        padding-right: 2rem;
        max-width: 1400px;
    }
    @media (max-width: 640px) {
        .block-container {
            padding-left: 1rem;
            padding-right: 1rem;
        }
        h1 { font-size: 1.6rem !important; }
        [data-testid="stMetricValue"] { font-size: 1.5rem; }
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ---------------------------------------------------------
# Sidebar Navigation
# ---------------------------------------------------------
st.sidebar.title("🐆 Panther Guard")
st.sidebar.markdown("---")

navigation_choice = st.sidebar.radio(
    "Navigation Menu",
    [
        "🛡️ Security Monitor",
        "🤖 Roary AI Assistant",
        "❓ Help & Support"
    ]
)

st.sidebar.markdown("---")
st.sidebar.info("System Status: **Active Monitoring**")

# ---------------------------------------------------------
# Page 1: Security Monitor (Scanner, Alerts & Quarantine)
# ---------------------------------------------------------
if navigation_choice == "🛡️ Security Monitor":
    df = pd.DataFrame(load_logs())
    df["Threat"] = df["threat_level"].map(THREAT_LABELS).fillna("Unknown")
    df = df.rename(columns={"timestamp": "Time", "process_name": "Process", "status": "Status"})
    use_container_width=True

    st.markdown("<h1 style='color: #C5960C;'>🐆 Panther Guard Security Dashboard</h1>", unsafe_allow_html=True)
    st.write("Real-time system process scanning, telemetry analysis, and threat management.")
    
    st.markdown("---")
    
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("System Process Scanner")
        
        if st.button("Run System Scan", use_container_width=False):
            st.code(
                "[INFO] Initializing Panther Guard Process Scanner...\n"
                "[SCAN] Checked active Windows background processes & IPC channels.\n"
                "[ANOMALY] 1 suspicious background hook flagged for review.\n"
                "[STATUS] Monitoring active threats...",
                language="bash"
            )
            st.success("Scan completed successfully!")
            
    with col2:
        st.subheader("Quick Health Overview")
        st.markdown(
            """
            <div class="fiu-card">
                <h4>System Integrity Status</h4>
                <p style="color: #4CAF50; font-weight: bold;">🟢 Threat Level: MODERATE</p>
                <p>IPC Telemetry: Operational</p>
                <p>Background Engine: Active</p>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")
    
    # Member 5 & 6 Controls: Active Threat Management & Quarantine
    st.subheader("🛡️ Active Threat Management")
    simulated_threat = "suspicious_background_process.exe (PID: 4092)"

    col_alert1, col_alert2 = st.columns([3, 1])

    with col_alert1:
        st.markdown(
            f"""
            <div class="threat-banner" style="background-color: #ffe6e6; color: #990000; border: 1px solid #cc0000;">
            ⚠️ <b>Anomaly Flagged:</b> {simulated_threat} requires verification.
            </div>
            """,
            unsafe_allow_html=True
        )

    with col_alert2:
        if st.button("🚨 Quarantine Process", use_container_width=True):
            st.success(f"Successfully isolated and terminated {simulated_threat}!")

    st.subheader("Security Logs")
    
    f1, f2 = st.columns([1, 2], gap="medium")
    search = f1.text_input("Search processes", placeholder="e.g. chrome")
    levels = f2.multiselect(
        "Threat level",
        ["Safe", "Warning", "Critical"],
        default=["Safe", "Warning", "Critical"],
    )



    filtered = df[df["Threat"].isin(levels)]
    if search:
        filtered = filtered[
            filtered["Process"].str.contains(search, case=False, regex=False, na=False)
        ]

    if filtered.empty:
        st.info("No entries match your search and filters.")
    else:
        table = filtered[["Time", "Process", "Threat", "Status"]]
        st.dataframe(table.style.map(color_threat, subset=["Threat"]), hide_index=True)

# ---------------------------------------------------------
# Page 2: Roary AI Assistant
# ---------------------------------------------------------
elif navigation_choice == "🤖 Roary AI Assistant":
    st.markdown("<h1 style='color: #C5960C;'>🤖 Roary AI Security Helper</h1>", unsafe_allow_html=True)
    st.write("Ask Roary about system security, active alerts, or general cybersecurity questions.")

    st.markdown("---")

    # Chat interface container
    st.subheader("Chat with Roary")
    
    if "messages" not in st.session_state:
        st.session_state.messages = [
            {"role": "assistant", "content": "Hi! I'm Roary, your Panther Guard AI Assistant. How can I help secure your workstation today?"}
        ]

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if user_input := st.chat_input("Ask Roary a security question..."):
        st.session_state.messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        # Simulated Roary response (Ready for Gemini API hookup)
        roary_response = f"**Roary:** I received your query about *'{user_input}'*. The current system telemetry indicates all active background processes are executing within safe baseline thresholds."
        st.session_state.messages.append({"role": "assistant", "content": roary_response})
        with st.chat_message("assistant"):
            st.markdown(roary_response)

# ---------------------------------------------------------
# Page 3: Help & Support
# ---------------------------------------------------------
elif navigation_choice == "❓ Help & Support":
    st.markdown("<h1 style='color: #C5960C;'>❓ Panther Guard Support & Documentation</h1>", unsafe_allow_html=True)
    st.write("Find quick answers to common questions and operational guidance.")

    st.markdown("---")

    with st.expander("🔍 How does the System Scanner work?"):
        st.write("Panther Guard interfaces directly with compiled Java process scanning modules to poll running Windows processes, analyzing telemetry for unauthorized hooks or anomalies.")

    with st.expander("🚨 What should I do if a threat is flagged?"):
        st.write("Navigate to the **Security Monitor** section and click the **Quarantine Process** button to immediately isolate and terminate the flagged PID.")

    with st.expander("🤖 How does Roary AI assist me?"):
        st.write("Roary uses structured log data to provide contextual security recommendations, explaining complex telemetry in simple terms.")

    st.markdown("---")
    st.markdown("### 🎓 Panther Guard INIT Team Project")
    st.write("Built with Streamlit, Java IPC Backend, and Gemini AI.")