"""app.py - Streamlit user interface for LoginGuard."""
import os

import streamlit as st

from assessment import RED_MIN, build_assessment
from threat_checker import check_threat
from url_analyzer import analyze_url

st.set_page_config(page_title="LoginGuard", page_icon="🛡️", layout="centered")

COLORS = {"green": "#1e9e5a", "orange": "#e68a00", "red": "#d93025", "unknown": "#6b7280"}
ICONS = {"green": "🟢", "orange": "🟠", "red": "🔴", "unknown": "⚪"}

st.markdown(
    """
    <style>
      .block-container {padding-top: 2rem; max-width: 760px;}
      .lg-title {font-size: 2.2rem; font-weight: 800; margin-bottom: 0;}
      .lg-sub {color: #6b7280; margin-top: 0; font-size: 1.05rem;}
      .lg-card {border-left: 8px solid var(--c); padding: 1rem 1.2rem; border-radius: 8px;
                background: rgba(128,128,128,0.10); margin: 1rem 0;}
      .lg-card h3 {margin: 0 0 .3rem 0;}
      .lg-footer {color: #6b7280; font-size: .85rem; margin-top: 2.5rem;}
    </style>
    <p class="lg-title">🛡️ LoginGuard</p>
    <p class="lg-sub">Intelligent Fake Login Website Detection System</p>
    """,
    unsafe_allow_html=True,
)

st.write(
    "Phishing websites are fake sites that copy trusted ones (like banks or social media) "
    "to steal your login details. Paste a website address below and LoginGuard will look "
    "for warning signs **without opening the website**."
)
st.info("🔒 Safety note: never type your password into a website you are not sure about.")


def get_api_key():
    """Look for the key in Streamlit secrets first, then environment variables."""
    try:
        key = st.secrets.get("GOOGLE_SAFE_BROWSING_API_KEY")
    except Exception:  # no secrets file exists
        key = None
    return key or os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")


with st.form("check_form"):
    url_input = st.text_input("Website URL", placeholder="https://example.com/login",
                              max_chars=2048)
    submitted = st.form_submit_button("Check Website", type="primary", use_container_width=True)

if submitted:
    with st.spinner("Analyzing the address (the website is not being opened)..."):
        analysis = analyze_url(url_input)
        threat = check_threat(analysis.normalized, get_api_key()) if analysis.valid else None
        result = build_assessment(analysis, threat)

    color = COLORS[result.level]
    st.markdown(
        f'<div class="lg-card" style="--c:{color}"><h3>{ICONS[result.level]} {result.headline}</h3></div>',
        unsafe_allow_html=True,
    )
    st.write(result.explanation)

    st.subheader("Submitted URL")
    st.code(analysis.original[:300], language=None)  # shown as plain text, never as a link
    for note in analysis.notes:
        st.caption(note)

    if analysis.valid:
        c1, c2 = st.columns(2)
        c1.metric("Warning score", analysis.score)
        c2.caption("Higher means more warning patterns. Not a probability of phishing.")

        st.subheader("Database check")
        if threat.status == "unavailable":
            st.warning(f"Not performed: {threat.detail} Only local URL-pattern analysis was done.")
        elif threat.simulated:
            st.info(f"SIMULATED test fixture. {threat.detail}")
        elif threat.status == "match":
            st.error(f"{threat.source}: {threat.detail}")
        else:
            st.success(f"{threat.source}: {threat.detail}")

        st.subheader("What we found")
        if analysis.findings:
            for f in analysis.findings:
                with st.expander(f"{f.title}  (+{f.points})", expanded=True):
                    st.write(f.explanation)
        else:
            st.write("No configured warning patterns were detected.")

    st.subheader("Recommended next steps")
    for step in result.next_steps:
        st.markdown(f"- {step}")

with st.expander("How is the score calculated?"):
    st.markdown(
        "Each warning pattern adds points (+1 mild, +2 medium, +3 strong).\n\n"
        f"- **0 points** → 🟢 Green: no obvious warning signs\n"
        f"- **1–{RED_MIN - 1} points** → 🟠 Orange: suspicious signs\n"
        f"- **{RED_MIN}+ points** → 🔴 Red: high caution\n"
        "- A match in the Google Safe Browsing database → 🔴 Red, shown separately\n"
        "- Invalid input → ⚪ Unable to determine"
    )

st.markdown(
    '<div class="lg-footer">LoginGuard uses simple rules and, if configured, one public '
    "threat database. It cannot prove a website is safe or malicious, never opens the "
    "address you enter, and can make mistakes. Always use your own judgement.</div>",
    unsafe_allow_html=True,
)
