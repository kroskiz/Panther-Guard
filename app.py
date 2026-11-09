import streamlit as st

# ---------------------------------------------------------
# Page Configuration & FIU Custom Styling
# ---------------------------------------------------------
st.set_page_config(
    page_title="Panther Guard Security Dashboard",
    page_icon="🐆",
    layout="wide"
)

st.markdown(
    """
    <style>
    /* FIU Main Theme Colors */
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
    /* Customize Sidebar */
    [data-testid="stSidebar"] {
        background-color: #000F29;
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