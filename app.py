import streamlit as st



st.set_page_config(page_title="Panther Guard Dashboard", layout="wide")
FIU_BLUE = "#001538"
FIU_GOLD = "#C5960C"



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


</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.header("Menu")
    choice = st.radio("Go to", ["Dashboard", "Search","Reports", "Roary AI", "Settings"])

    st.divider()

    if st.button("Run Scan", use_container_width=True):
        st.toast("Run Scan: coming soon")
    if st.button("Refresh Logs", use_container_width=True):
        st.toast("Refresh Logs: coming soon")

st.title("Good Morning, Panther!")
st.subheader(choice)

m1, m2, m3 = st.columns(3)
m1.metric("Threats Detected", "--")
m2.metric("Threats Defended", "--")
m3.metric("Threat Summary", "--")

logs_col, mascot_col = st.columns([3, 1])

with logs_col:
    with st.container(border=True, height=400):
        st.subheader("Security Logs")
        st.caption("Log feed will appear here (data/security_logs.json).")
       

with mascot_col:
    with st.container(border=True, height=400):
        st.subheader("Roary")
        st.caption("Mascot and status image will appear here.")
        




