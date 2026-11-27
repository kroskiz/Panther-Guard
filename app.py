import streamlit as st
from pathlib import Path

import pandas as pd
import json
import subprocess
from datetime import datetime

# ---------------------------------------------------------
# Page Configuration & FIU Custom Styling
# ---------------------------------------------------------
st.set_page_config(
    page_title="Panther Guard Security Dashboard",
    page_icon="🐆",
    layout="wide"
)

PROJECT_DIR = Path(__file__).parent
SCANNER_SOURCE = PROJECT_DIR / "src" / "ProcessScanner.java"
SCANNER_CLASSES = PROJECT_DIR / "bin"
THREAT_LABELS = {"low": "Safe", "medium": "Warning", "high": "Critical"}


@st.cache_resource(show_spinner=False)
def compile_process_scanner(source_path, classes_path, source_mtime_ns):
    source = Path(source_path)
    classes = Path(classes_path)
    classes.mkdir(parents=True, exist_ok=True)
    if source.stat().st_mtime_ns != source_mtime_ns:
        raise RuntimeError("The process scanner source changed during compilation.")
    subprocess.run(
        ["javac", "-d", str(classes), str(source)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


def run_process_scan():
    """Compile the Java scanner when needed and return its process records."""
    if not SCANNER_SOURCE.is_file():
        raise RuntimeError(f"Process scanner source was not found: {SCANNER_SOURCE}")

    try:
        compile_process_scanner(
            str(SCANNER_SOURCE),
            str(SCANNER_CLASSES),
            SCANNER_SOURCE.stat().st_mtime_ns,
        )
        result = subprocess.run(
            ["java", "-cp", str(SCANNER_CLASSES), "ProcessScanner"],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except FileNotFoundError as error:
        raise RuntimeError(f"Required scanner command was not found: {error.filename}") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("The process scanner timed out.") from error
    except subprocess.CalledProcessError as error:
        details = (error.stderr or error.stdout or "").strip()
        message = f"Process scanner failed with exit code {error.returncode}."
        if details:
            message = f"{message} {details}"
        raise RuntimeError(message) from error

    try:
        records = json.loads(result.stdout) # Reads backend output straight from stdout, not from a file (verify if fine)
    except json.JSONDecodeError as error:
        raise RuntimeError("The process scanner returned invalid JSON.") from error

    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise RuntimeError("The process scanner returned an unexpected data format.")
    required_fields = {"status", "process_name", "threat_level", "timestamp"}
    if any(not required_fields.issubset(record) for record in records):
        raise RuntimeError("The process scanner returned records with missing fields.")

    return records

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
    [data-testid="stSidebar"] [data-testid="stBaseButton-primary"] {
        background-color: #C5960C;
        border: 1px solid #C5960C;
        border-radius: 8px;
        color: #001538;
        font-weight: 700;
    }
    [data-testid="stSidebar"] [data-testid="stBaseButton-secondary"] {
        background-color: #002255;
        border: 1px solid #002255;
        border-radius: 8px;
        color: #FFFFFF;
        font-weight: 600;
        text-align: left;
        transition: background-color 140ms ease, border-color 140ms ease, box-shadow 140ms ease;
    }
    [data-testid="stSidebar"] [data-testid="stBaseButton-secondary"]:hover {
        background-color: #0A2250;
        border-color: #C5960C;
        color: #FFFFFF;
        box-shadow: 0 0 0 1px rgba(197, 150, 12, 0.25);
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
st.sidebar.markdown("#### Navigation")

navigation_options = [
    "🛡️ Security Monitor",
    "🤖 Roary AI Assistant",
    "❓ Help & Support",
]
if "navigation_choice" not in st.session_state:
    st.session_state.navigation_choice = navigation_options[0]


def select_navigation(option):
    st.session_state.navigation_choice = option


for index, option in enumerate(navigation_options):
    st.sidebar.button(
        option,
        key=f"navigation_{index}",
        type="primary" if st.session_state.navigation_choice == option else "secondary",
        use_container_width=True,
        on_click=select_navigation,
        args=(option,),
    )

navigation_choice = st.session_state.navigation_choice

st.sidebar.markdown("---")
st.sidebar.info("System Status: **Active Monitoring**")

# ---------------------------------------------------------
# Page 1: Security Monitor (Scanner, Alerts & Quarantine)
# ---------------------------------------------------------
if navigation_choice == "🛡️ Security Monitor":
    st.markdown("<h1 style='color: #C5960C;'>🐆 Panther Guard Security Dashboard</h1>", unsafe_allow_html=True)
    st.write("Real-time system process scanning, telemetry analysis, and threat management.")
    
    st.markdown("---")
    
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("System Process Scanner")
        auto_scan = st.toggle("Auto-scan every 30 seconds", key="auto_scan_enabled")

        @st.fragment(run_every="30s" if auto_scan else None)
        def render_process_scan():
            manual_scan = st.button("Run System Scan", use_container_width=False)

            if auto_scan or manual_scan:
                try:
                    with st.spinner("Scanning running processes..."):
                        records = run_process_scan()
                except RuntimeError as error:
                    st.session_state.process_scan_error = str(error)
                else:
                    st.session_state.process_scan_records = records
                    st.session_state.process_scan_time = datetime.now().astimezone()
                    st.session_state.process_scan_ran = True
                    st.session_state.process_scan_error = None

            scan_error = st.session_state.get("process_scan_error")
            if scan_error:
                st.error(f"Process scan failed: {scan_error}")
                if st.session_state.get("process_scan_ran", False):
                    st.caption("Showing results from the last successful scan.")

            if not st.session_state.get("process_scan_ran", False):
                if not scan_error:
                    st.info("No scan run yet. Select Run System Scan to view process results.")
                return

            last_scan = st.session_state.process_scan_time.strftime("%Y-%m-%d %H:%M:%S %Z")
            st.caption(f"Processes found during the latest scan · {last_scan}")

            df = pd.DataFrame(st.session_state.process_scan_records)
            if df.empty:
                st.info("No running processes were found.")
                return

            df["Threat"] = df["threat_level"].map(THREAT_LABELS).fillna("Unknown")
            df = df.rename(
                columns={"timestamp": "Time", "process_name": "Process", "status": "Status"}
            )

            f1, f2 = st.columns([1, 2], gap="medium")
            search = f1.text_input("Search processes", placeholder="e.g. chrome")
            levels = f2.multiselect(
                "Threat level",
                ["Safe", "Warning", "Critical"],
                default=["Safe", "Warning", "Critical"],
            )

            scan_results = df[df["Status"].astype(str).str.lower().eq("running")]
            filtered = scan_results[scan_results["Threat"].isin(levels)]
            if search:
                filtered = filtered[
                    filtered["Process"].str.contains(search, case=False, regex=False, na=False)
                ]

            if filtered.empty:
                st.info("No processes match your search and filters.")
            else:
                table = filtered[["Time", "Process", "Threat", "Status"]]
                st.dataframe(table.style.map(color_threat, subset=["Threat"]), hide_index=True)

        render_process_scan()

    with col2:
        st.subheader("Quick Health Overview")
        # TODO: Ask team lead what this section should report and how to collect its data.
        # Threat Level can be derived from average threat level of running processes, unsure about rest
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