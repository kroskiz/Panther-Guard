import streamlit as st
from pathlib import Path

import pandas as pd
import json
import subprocess
from datetime import datetime

from src.process_history import classify_scan_status
from src.process_evidence import collect_file_evidence
from src.security_rules import COMMAND_LINE_REASONS, assess_process

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
THREAT_LABELS = {
    "low": "Low",
    "medium": "Medium",
    "high": "High",
}


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


def run_process_scan(previously_seen_processes):
    """Run the Java inventory scanner and add process-instance history statuses."""
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
        records = json.loads(result.stdout)  # The scanner streams its JSON snapshot over stdout.
    except json.JSONDecodeError as error:
        raise RuntimeError("The process scanner returned invalid JSON.") from error

    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise RuntimeError("The process scanner returned an unexpected data format.")
    required_fields = {
        "pid",
        "process_name",
        "executable_path",
        "parent_pid",
        "parent_process_name",
        "started_at",
        "command_line_indicators",
        "timestamp",
    }
    if any(not required_fields.issubset(record) for record in records):
        raise RuntimeError("The process scanner returned records with missing fields.")
    if any(
        isinstance(record["pid"], bool)
        or not isinstance(record["pid"], int)
        or record["pid"] < 0
        for record in records
    ):
        raise RuntimeError("The process scanner returned an invalid process ID.")
    if any(
        not isinstance(record["process_name"], str)
        or (
            record["executable_path"] is not None
            and not isinstance(record["executable_path"], str)
        )
        or (
            record["parent_pid"] is not None
            and (
                isinstance(record["parent_pid"], bool)
                or not isinstance(record["parent_pid"], int)
                or record["parent_pid"] < 0
            )
        )
        or (
            record["parent_process_name"] is not None
            and not isinstance(record["parent_process_name"], str)
        )
        or (
            record["started_at"] is not None
            and not isinstance(record["started_at"], str)
        )
        for record in records
    ):
        raise RuntimeError("The process scanner returned invalid process metadata.")
    if any(
        not isinstance(record["command_line_indicators"], list)
        or any(
            not isinstance(indicator, str) or indicator not in COMMAND_LINE_REASONS
            for indicator in record["command_line_indicators"]
        )
        for record in records
    ):
        raise RuntimeError("The process scanner returned invalid command-line indicators.")

    # Use an initial score to limit signature checks and hashing to review candidates.
    for record in records:
        threat_level, _ = assess_process(record)
        record["preliminary_threat_level"] = threat_level

    evidence_warnings = collect_file_evidence(records)
    # Re-score with any collected signature evidence included.
    for record in records:
        record.pop("preliminary_threat_level", None)
        threat_level, reasons = assess_process(record)
        record["threat_level"] = threat_level
        record["threat_reasons"] = reasons

    return classify_scan_status(records, previously_seen_processes), evidence_warnings

def color_threat(value):
  if value.startswith("High"):
    return "background-color: #B3261E; color: white; font-weight: bold"
  if value.startswith("Medium"):
        return "background-color: #C5960C; color: #001538; font-weight: bold"
  return ""


def color_threat_row(row):
    style = color_threat(row["Threat"])
    return [style] * len(row)


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
    .page-caption {
        color: rgba(255, 255, 255, 0.65);
        font-size: 0.9rem;
        margin-top: -0.5rem;
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
if "auto_scan_enabled" not in st.session_state:
    st.session_state.auto_scan_enabled = True


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
monitoring_status = "Active Monitoring" if st.session_state.auto_scan_enabled else "Monitoring Paused"
st.sidebar.info(f"System Status: **{monitoring_status}**")

# ---------------------------------------------------------
# Page 1: Security Monitor (Scanner & Review)
# ---------------------------------------------------------
if navigation_choice == "🛡️ Security Monitor":
    st.markdown("<h1 style='color: #C5960C;'>🐆 Panther Guard Security Dashboard</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-caption'>Process inventory and PID-based comparison between scans.</p>", unsafe_allow_html=True)
    
    st.markdown("---")
    auto_scan = st.toggle("Auto-scan every 30 seconds", key="auto_scan_enabled")

    @st.fragment(run_every="30s" if auto_scan else None)
    def render_security_monitor():
        show_demo = st.checkbox(
            "Show test-only demo process in Scanner and Active Threat Management",
            key="atm_demo_enabled",
            help="Adds a synthetic display-only row and threat card without changing scan results or summary counts.",
        )
        demo_record = None
        if show_demo:
            demo_severity = st.selectbox(
                "Demo severity",
                ["Medium", "High"],
                key="atm_demo_severity",
            )
            is_high_demo = demo_severity == "High"
            demo_record = {
                "pid": "DEMO",
                "process_name": "powershell.exe" if is_high_demo else "demo_app.exe",
                "executable_path": (
                    r"C:\Users\Example\AppData\Local\Temp\powershell.exe"
                    if is_high_demo
                    else r"C:\Users\Example\AppData\Local\Temp\demo_app.exe"
                ),
                "parent_pid": None,
                "parent_process_name": "winword.exe" if is_high_demo else None,
                "started_at": None,
                "command_line_indicators": (
                    ["powershell_execution_policy_bypass"] if is_high_demo else []
                ),
                "signature_status": "not_checked",
                "signer": None,
                "file_sha256": None,
                "file_hash_status": "not_checked",
            }
            demo_record["threat_level"], demo_record["threat_reasons"] = assess_process(
                demo_record
            )
            st.warning(
                "TEST DEMO ONLY — the synthetic row and threat card are examples, not a running "
                "process or detection. They do not affect scan results or summary counts."
            )

        col1, col2 = st.columns([2, 1])

        with col1:
            st.subheader("System Process Scanner")
            manual_scan = st.button("Run System Scan", use_container_width=False)

            if auto_scan or manual_scan:
                try:
                    with st.spinner("Scanning running processes..."):
                        previous_records = st.session_state.get("process_scan_records", [])
                        previously_seen_processes = {
                            (record["pid"], record.get("started_at"))
                            for record in previous_records
                            if isinstance(record.get("pid"), int)
                        }
                        records, evidence_warnings = run_process_scan(previously_seen_processes)
                except RuntimeError as error:
                    st.session_state.process_scan_error = str(error)
                else:
                    st.session_state.process_scan_records = records
                    st.session_state.process_evidence_warnings = evidence_warnings
                    st.session_state.process_scan_time = datetime.now().astimezone()
                    st.session_state.process_scan_ran = True
                    st.session_state.process_scan_error = None

            scan_error = st.session_state.get("process_scan_error")
            if scan_error:
                st.error(f"Process scan failed: {scan_error}")
                if st.session_state.get("process_scan_ran", False):
                    st.caption("Showing results from the last successful scan.")
            for warning in st.session_state.get("process_evidence_warnings", []):
                st.warning(warning)

            scan_has_run = st.session_state.get("process_scan_ran", False)
            if not scan_has_run:
                if not scan_error:
                    st.info("No scan run yet. Select Run System Scan to view process results.")
            else:
                last_scan = st.session_state.process_scan_time.strftime("%Y-%m-%d %H:%M:%S %Z")
                st.caption(f"Processes found during the latest scan · {last_scan}")

            live_records = (
                st.session_state.get("process_scan_records", []) if scan_has_run else []
            )
            df = pd.DataFrame(live_records)
            if df.empty:
                df = pd.DataFrame(columns=["Time", "PID", "Process", "Threat", "Status"])
            else:
                df["Threat"] = df["threat_level"].map(THREAT_LABELS).fillna("Unknown")
                df = df.rename(
                    columns={
                        "timestamp": "Time",
                        "pid": "PID",
                        "process_name": "Process",
                        "status": "Status",
                    }
                )
                df = df[["Time", "PID", "Process", "Threat", "Status"]]

            if demo_record is not None:
                df.loc[len(df)] = {
                    "Time": "DEMO",
                    "PID": "DEMO",
                    "Process": f"{demo_record['process_name']}",
                    "Threat": THREAT_LABELS[demo_record["threat_level"]],
                    "Status": "—",
                }

            if scan_has_run and not live_records:
                st.info("No live running processes were found in the latest scan.")
            if not df.empty:
                f1, f2 = st.columns([1, 2], gap="medium")
                search = f1.text_input("Search processes", placeholder="e.g. chrome")
                levels = f2.multiselect(
                    "Heuristic assessment",
                    list(THREAT_LABELS.values()),
                    default=list(THREAT_LABELS.values()),
                )

                filtered = df[df["Threat"].isin(levels)]
                if search:
                    filtered = filtered[
                        filtered["Process"].str.contains(search, case=False, regex=False, na=False)
                    ]

                if filtered.empty:
                    st.info("No processes match your search and filters.")
                else:
                    table = filtered[["Time", "PID", "Process", "Threat", "Status"]].copy()
                    parsed_time = pd.to_datetime(table["Time"], errors="coerce")
                    table["Time"] = (
                        parsed_time.dt.strftime("%I:%M %p").str.lstrip("0").fillna(table["Time"])
                    )
                    st.dataframe(
                        table.style.apply(color_threat_row, axis=1),
                        hide_index=True,
                        use_container_width=True,
                    )
                st.caption(
                    "Low means no configured indicators were found; it does not verify that a process is safe. "
                    "Medium and High are heuristic review priorities, not confirmed detections."
                )
                if demo_record is not None:
                    st.caption(
                        "The TEST DEMO row has no real scan time, PID, or New/Previously Seen status."
                    )

        with col2:
            st.subheader("Process Review Summary")
            # TODO: Ask team lead whether additional system-integrity data should be collected.
            if scan_has_run:
                threat_levels = [
                    record["threat_level"]
                    for record in st.session_state.process_scan_records
                ]
                st.metric("High", threat_levels.count("high"))
                st.metric("Medium", threat_levels.count("medium"))
                st.metric("Low", threat_levels.count("low"))
                st.caption("Heuristic review counts from the latest process snapshot.")
            else:
                st.info("Run a process scan to see the review summary.")

        st.markdown("---")
        st.subheader("🛡️ Active Threat Management")
        latest_records = (
            st.session_state.get("process_scan_records", []) if scan_has_run else []
        )
        flagged_processes = [
            record
            for record in latest_records
            if record["threat_level"] in {"medium", "high"}
        ]
        if not scan_has_run:
            if demo_record is None:
                st.info("Run a process scan to populate review candidates.")
            else:
                st.info("No live scan results yet; the displayed process is only a test demo.")
        elif not flagged_processes and demo_record is None:
            st.success("No processes met the current review thresholds in the latest scan.")
        elif flagged_processes:
            st.caption(
                "These processes matched one or more review heuristics. They are candidates for investigation, "
                "not confirmed threats."
            )

        display_processes = [(record, False) for record in flagged_processes]
        if demo_record is not None:
            display_processes.append((demo_record, True))

        signature_labels = {
            "Valid": "Valid signature",
            "NotSigned": "Not signed",
            "HashMismatch": "Signature mismatch",
            "NotTrusted": "Signature not trusted",
            "Unavailable": "Unavailable",
            "not_checked": "Not checked",
        }
        hash_labels = {
            "available": "Available",
            "unavailable": "Unavailable",
            "too_large": "Skipped (file exceeds 100 MiB)",
            "not_checked": "Not checked",
        }
        for record, is_demo in display_processes:
            level_label = THREAT_LABELS[record["threat_level"]]
            demo_prefix = "TEST DEMO · " if is_demo else ""
            process_label = (
                f"{demo_prefix}{level_label} · {record['process_name']} (PID {record['pid']})"
            )
            with st.expander(
                process_label,
                expanded=is_demo or record["threat_level"] == "high",
            ):
                if is_demo:
                    st.caption("TEST DEMO — synthetic example; not a real process.")
                st.markdown("**Why it was flagged**")
                for reason in record["threat_reasons"]:
                    st.markdown(f"- {reason}")

                st.write("Executable path:", record["executable_path"] or "Unavailable")
                parent_name = record["parent_process_name"] or "Unavailable"
                parent_pid = record["parent_pid"]
                if parent_pid is not None:
                    parent_name = f"{parent_name} (PID {parent_pid})"
                st.write("Parent process:", parent_name)

                started_at = pd.to_datetime(record["started_at"], errors="coerce", utc=True)
                started_label = (
                    started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                    if pd.notna(started_at)
                    else "Unavailable"
                )
                st.write("Started:", started_label)

                signature_status = record["signature_status"]
                st.write(
                    "Signature:",
                    signature_labels.get(signature_status, "Unavailable"),
                )
                if record["signer"]:
                    publisher_label = record["signer"]
                elif signature_status == "NotSigned":
                    publisher_label = "No signing certificate (unsigned)"
                elif signature_status == "not_checked":
                    publisher_label = "Not checked"
                else:
                    publisher_label = "Unavailable"
                st.write("Publisher:", publisher_label)
                hash_status = record["file_hash_status"]
                st.write("SHA-256:", hash_labels.get(hash_status, "Unavailable"))
                if record["file_sha256"]:
                    st.code(record["file_sha256"], language=None)
                if record["command_line_indicators"]:
                    st.write(
                        "Command-line indicators:",
                        "; ".join(
                            COMMAND_LINE_REASONS[indicator]
                            for indicator in record["command_line_indicators"]
                        ),
                    )

        st.caption(
            "A valid signature does not guarantee a file is safe. Hashes are shown for manual review; "
            "they are not checked against a threat-intelligence service."
        )

    render_security_monitor()

# ---------------------------------------------------------
# Page 2: Roary AI Assistant
# ---------------------------------------------------------
elif navigation_choice == "🤖 Roary AI Assistant":
    st.markdown("<h1 style='color: #C5960C;'>🤖 Roary AI Security Helper</h1>", unsafe_allow_html=True)
    st.markdown("<p class='page-caption'>Ask Roary about system security, active alerts, or general cybersecurity questions.</p>", unsafe_allow_html=True)

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
    st.markdown("<p class='page-caption'>Find quick answers to common questions and operational guidance.</p>", unsafe_allow_html=True)

    st.markdown("---")

    with st.expander("🔍 How does the System Scanner work?"):
        # TODO: Discuss the limits of snapshot-based heuristic findings and scope with the team lead.
        st.write("The Java scanner collects process IDs, executable paths, parent processes, start times, and selected PowerShell command-line indicators without storing raw command lines. Panther Guard compares PID/start-time pairs between scans, then uses explainable heuristics to assign Low, Medium, or High review priority and shows the reasons. For processes already flagged by another heuristic, it checks the local file signature and computes a SHA-256 hash for manual review; hashes are not sent to a threat-intelligence service. Low means no configured indicators were found, not proof of safety. Snapshot scanning can miss processes that start and stop between scans.")

    with st.expander("🚨 What should I do if a threat is flagged?"):
        st.write("Review flagged processes in **Active Threat Management** for their path, parent, signature status, hash when available, and assessment reasons. The current threat levels are heuristic review priorities, not confirmed detections. Panther Guard does not currently isolate or terminate processes. To preview the layout without a real scan, enable **Show test-only demo process in Scanner and Active Threat Management**; its synthetic record is clearly labeled and excluded from scan results and summary counts.")

    with st.expander("🤖 How does Roary AI assist me?"):
        st.write("Roary uses structured log data to provide contextual security recommendations, explaining complex telemetry in simple terms.")

    st.markdown("---")
    st.markdown("### 🎓 Panther Guard INIT Team Project")
    st.write("Built with Streamlit, Java IPC Backend, and Gemini AI.")