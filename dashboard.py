import json
import os
import sys
import subprocess
import streamlit as st
# Pass Streamlit Secrets to backend Python scripts
for key in ["VIRUSTOTAL_API_KEY", "URLHAUS_AUTH_KEY"]:
    if key in st.secrets:
        os.environ[key] = str(st.secrets[key])
# ==========================================
# SESSION STATE
# ==========================================

if "analysis_ready" not in st.session_state:
    st.session_state.analysis_ready = False


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="Phishing Email Forensics",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================
# TITLE
# ==========================================

st.title("🛡️ Phishing Email Forensic Analysis")

st.caption(
    "Automated Phishing Email Forensic Analysis "
    "and Threat Intelligence Correlation"
)


# ==========================================
# UPLOAD PHISHING EMAIL
# ==========================================

st.header("📂 Upload Phishing Email")

uploaded_file = st.file_uploader(
    "Choose an email file (.eml)",
    type=["eml"],
    key="email_uploader"
)

if uploaded_file is not None:
    st.success(f"Selected file: {uploaded_file.name}")

    if st.button("🔍 Analyze Email", type="primary"):
        try:
            # Save the uploaded email
            email_path = os.path.join(
                "samples",
                "phishing_test.eml"
            )

            os.makedirs("samples", exist_ok=True)
            os.makedirs("output", exist_ok=True)

            with open(email_path, "wb") as file:
                file.write(uploaded_file.getbuffer())

            # ------------------------------------------
            # ROLE 1 - FORENSIC ANALYSIS
            # ------------------------------------------

            with st.spinner("Running forensic analysis..."):
                result = subprocess.run(
                    [sys.executable, "main.py"],
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    st.error("Backend analysis failed.")
                    st.code(
                        result.stderr
                        or result.stdout
                        or "No error details returned."
                    )
                    st.stop()

                if result.stdout:
                    st.text(result.stdout)

            # ------------------------------------------
            # ROLE 2 - THREAT INTELLIGENCE
            # ------------------------------------------

            with st.spinner("Running threat intelligence checks..."):
                result = subprocess.run(
                    [
                        sys.executable,
                        "threat_intelligence/threat_intelligence.py"
                    ],
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    st.error("Threat intelligence analysis failed.")
                    st.code(
                        result.stderr
                        or result.stdout
                        or "No error details returned."
                    )
                    st.stop()

                if result.stdout:
                    st.text(result.stdout)

                if result.stderr:
                    st.code(result.stderr)

            # ------------------------------------------
            # ROLE 3 - REPORT GENERATION
            # ------------------------------------------

            with st.spinner("Generating forensic reports..."):
                result = subprocess.run(
                    [
