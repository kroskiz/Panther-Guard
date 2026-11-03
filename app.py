import streamlit as st
from pathlib import Path

import pandas as pd
import json



st.set_page_config(page_title="Panther Guard Dashboard", layout="wide")
FIU_BLUE = "#001538"
FIU_GOLD = "#C5960C"

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
        return "background-color: #001538; color: white; font-weight: bold"
    if value == "Warning":
        return "background-color: #C5960C; color: #001538; font-weight: bold"
    return ""




st.markdown("""
<style>


[data-testid="stSidebar"] {
    background-color: #001538;
   
}

[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3,
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] label {
    color: white;
}

div.stButton > button  {
    background-color: #C5960C ;
    border: none;
    
}

div.stButton > button p {
    color: #001538 !important;
    font-weight: 600;
    
}

div.stButton > button: hover{
background-color: #001538;
border: 1px solid #C5960c;
}

div.stButton > button: hover p{
color: #C5960C !important;}

[data-testid="stMetric"] {
    background-color: #FFFFFF;
    border-left: 5px solid #C5960C;
    border-radius: 8px;
    padding: 12px 16px;
}
[data-testid="stMetricLabel"],
[data-testid="stMetricLabel"] p {
    color: #001538;
    font-weight: 600;
}
[data-testid="stMetricValue"] {
    color: #001538;
}

</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.header("Menu")
    choice = st.radio("Go to", ["Dashboard", "Search","Reports", "Roary AI", "Settings"])

    st.divider()

    if st.button("Run Scan", use_container_width=True):
        st.toast("Run Scan: coming soon")
    if st.button("Refresh Logs", use_container_width=True):
        st.toast("Logs refreshed")

st.title("Good Morning, Panther!")
st.subheader(choice)

df = pd.DataFrame(load_logs())
df["Threat"] = df["threat_level"].map(THREAT_LABELS).fillna("Unknown")
df = df.rename(columns={"timestamp": "Time", "process_name": "Process", "status": "Status"})

m1, m2, m3 = st.columns(3)
m1.metric("Total Processes", len(df))
m2.metric("Warnings", int((df["Threat"] == "Warning").sum()))
m3.metric("Critical", int((df["Threat"] == "Critical").sum()))

logs_col, mascot_col = st.columns([3, 1])

with logs_col:
    with st.container(border=True, height=520):
        st.subheader("Security Logs")
        search = st.text_input("Search processes", placeholder="e.g. chrome")
        levels = st.multiselect(
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

with mascot_col:
    with st.container(border=True, height=400):
        st.subheader("Roary")
        st.caption("Mascot and status image will appear here.")
        




