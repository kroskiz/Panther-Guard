import streamlit as st

st.title("Good Morning, Panther!")

st.set_page_config(page_title="Panther Guard Dashboard", layout="wide")
FIU_BLUE = "#001538"
FIU_GOLD = "#C5960C"

st.markdown("""
<style>


[data-testid="stSidebar"] {
    background-color: #001538;
    color:
}

[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3,
[data-testid="stSidebar"] p {
    color: white;
}

div.stButton > button  {
    background-color: #C5960C ;
    
}

div.stButton > button p {
    color: #001538 ;
    
}


.st.button{ background-color: FIU_GOLD; color: FIU_BLUE; }
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.header("Menu")
    choice = st.radio("Go to", ["Dashboard", "Search","Reports", "Roary AI", "Settings"])

st.title("Dashboard")
if st.button ("Run Scan"):
    st.toast("Work in progress...")

if st.button("Refresh Logs"):
    st.toast("Work in progress..")


left, right = st.columns(2)



left.metric("Threats Detected", "5")
right.metric("Threats Defended", "3")

left, right = st.columns(2)
left.metric("Threat Summary", "Summary")


