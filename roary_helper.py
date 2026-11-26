"""Roary AI Helper - base layout for the Panther-Guard dashboard.

Usage from app.py:
    from roary_helper import render_roary_helper
    render_roary_helper()

Standalone preview:
    streamlit run roary_helper.py

Expects the log format defined in data/ipc_spec.json:
    status, process_name, threat_level, timestamp
"""

import json
from pathlib import Path
from google import genai

import streamlit as st

FIU_BLUE = "#001538"
FIU_GOLD = "#C5960C"
GEMINI_MODEL = "gemini-3.8-flash"

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "assets"
LOG_FILE = ROOT / "data" / "security_logs.json"

# threat_level values come from data/ipc_spec.json: low, medium, high.
MASCOTS = {
    "low": ("roary_safe.png", "All clear. Nothing suspicious is running."),
    "medium": ("roary_warning.png", "Heads up. Something looks unusual."),
    "high": ("roary_alert.png", "Danger! A threat was detected."),
}


def load_events() -> list[dict]:
    """Read security events written by the Java Logger. Returns [] if missing or invalid."""
    try:
        data = json.loads(LOG_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else [data]
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def current_threat_level(events: list[dict]) -> str:
    """Worst threat level seen in the events, defaulting to 'low'."""
    order = ["low", "medium", "high"]
    levels = [str(e.get("threat_level", "low")).lower() for e in events]
    known = [lvl for lvl in levels if lvl in order]
    return max(known, key=order.index) if known else "low"



def get_roary_reply(question: str, events: list[dict]) -> str:
    try:
        client = genai.Client()
        prompt = (
            "You are Roary, a friendly security assistant for a student dashboard. "
            "Answer using only the events below. If there are no events, say so.\n\n"
            f"Events: {json.dumps(events[-20:])}\n\n"
            f"Question: {question}"
        )
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
        )
        return response.text
    except Exception as e:
        print("ROARY ERROR:", e)
        return "Roary is unavailable right now. Please try again shortly." 

    
def render_roary_helper() -> None:
    st.markdown(
        f"""
        <style>
        .roary-card {{
            background: {FIU_BLUE};
            border: 2px solid {FIU_GOLD};
            border-radius: 12px;
            padding: 1rem 1.25rem;
            color: white;
        }}
        .roary-card h3 {{ color: {FIU_GOLD}; margin-top: 0; }}
        </style>
        """,
        unsafe_allow_html=True,
    )

    events = load_events()
    level = current_threat_level(events)
    image_name, message = MASCOTS[level]

    st.markdown('<div class="roary-card"><h3>Roary, your AI helper</h3></div>', unsafe_allow_html=True)

    col_img, col_msg = st.columns([1, 3])
    with col_img:
        image_path = ASSETS / image_name
        if image_path.exists():
            st.image(str(image_path), use_container_width=True)
        else:
            st.caption(f"Missing asset: assets/{image_name}")
    with col_msg:
        st.subheader(level.capitalize())
        st.write(message)
        st.caption(f"{len(events)} event(s) logged")

    st.divider()
    question = st.text_input("Ask Roary about your security status", key="roary_question")
    if st.button("Ask Roary", key="roary_ask") and question.strip():
        st.info(get_roary_reply(question, events))

    with st.expander("Recent events"):
        if events:
            st.dataframe(events[-10:][::-1], use_container_width=True)
        else:
            st.write("No events yet. Run the scanner to generate logs.")


if __name__ == "__main__":
    st.set_page_config(page_title="Roary Helper", layout="wide")
    render_roary_helper()render_roary_helper()
