import json
import os
import sys
import subprocess
import streamlit as st

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
            email_path = os.path.join("samples", "phishing_test.eml")

            os.makedirs("samples", exist_ok=True)

            with open(email_path, "wb") as file:
                file.write(uploaded_file.getbuffer())

            
            with st.spinner("Running forensic analysis..."):
                result = subprocess.run(
                    [sys.executable, "backend/main.py"],
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    st.error("Backend analysis failed. Actual error:")
                    st.code(result.stderr or result.stdout or "No error details returned.")
                    st.stop()

                if result.stdout:
                    st.text(result.stdout)


            with st.spinner("Running threat intelligence checks..."):
                subprocess.run(
                    [sys.executable, "threat_intelligence/threat_intelligence.py"],
                    check=True
                )

            with st.spinner("Generating forensic reports..."):
                subprocess.run(
                    [sys.executable, "reporting/report_generator.py"],
                    check=True
                )

            st.session_state.analysis_ready = True
            st.rerun()

        except subprocess.CalledProcessError as error:
            st.error(f"Analysis failed. Check the terminal output. Error: {error}")

# ==========================================
# CHECK WHETHER ANALYSIS HAS BEEN RUN
# ==========================================

analysis_file = "output/analysis_result.json"
threat_file = "output/threat_intelligence.json"

if not st.session_state.analysis_ready:
    st.info(
        "📭 Upload an .eml email file and click "
        "'Analyze Email' to view the analysis results."
    )
    st.stop()

if not os.path.exists(analysis_file):
    st.error("Analysis file not found. Please analyze the email again.")
    st.stop()

if not os.path.exists(threat_file):
    st.warning("Threat intelligence results are not available yet.")
    st.stop()


# ==========================================
# LOAD LATEST ANALYSIS
# ==========================================

with open(
    analysis_file,
    "r",
    encoding="utf-8"
) as file:

    analysis = json.load(file)


with open(
    threat_file,
    "r",
    encoding="utf-8"
) as file:

    threat_intelligence = json.load(file)


# ==========================================
# EXTRACT DATA
# ==========================================

headers = analysis["email"]["headers"]

authentication = analysis["authentication"]

ip_addresses = analysis["network_indicators"]["ip_addresses"]

domains = analysis["network_indicators"]["domains"]

urls = analysis["content"]["urls"]

attachments = analysis["attachments"]

indicators = analysis["suspicious_indicators"]
ml_analysis = analysis.get("ml_analysis", {})
forensic_risk = analysis.get("forensic_risk", "UNKNOWN")

# ==========================================
# CALCULATE RISK
# ==========================================

high_count = sum(
    1
    for i in indicators
    if i["severity"].upper() == "HIGH"
)

medium_count = sum(
    1
    for i in indicators
    if i["severity"].upper() == "MEDIUM"
)

low_count = sum(
    1
    for i in indicators
    if i["severity"].upper() == "LOW"
)


if high_count >= 2:

    risk_level = "HIGH"

elif high_count == 1 or medium_count >= 2:

    risk_level = "MEDIUM"

else:

    risk_level = "LOW"



# ==========================================
# RISK ASSESSMENT + ML PREDICTION
# ==========================================

st.header("Risk Assessment")

ml_prediction = ml_analysis.get("prediction", "Unavailable")
phishing_probability = ml_analysis.get("phishing_probability")
ml_risk = ml_analysis.get("risk_level", "Unavailable")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Forensic Risk", forensic_risk)

with col2:
    st.metric("ML Prediction", ml_prediction)

with col3:
    if phishing_probability is not None:
        st.metric(
            "Phishing Probability",
            f"{phishing_probability * 100:.2f}%"
        )
    else:
        st.metric("Phishing Probability", "Unavailable")

with col4:
    st.metric("ML Risk Level", ml_risk)

st.caption(
    "ML predictions and forensic risk are separate assessments. "
    "Review the email evidence before making a final decision."
)

# ==========================================
# MACHINE LEARNING EVIDENCE
# ==========================================

st.subheader("🤖 Machine Learning Evidence")

if ml_analysis:
    st.write("**ML Forensic Indicators**")

    ml_indicators = ml_analysis.get("forensic_indicators", [])

    if ml_indicators:
        for item in ml_indicators:
            st.write(f"• {item}")
    else:
        st.info("No ML forensic indicators available.")

    st.write("**Model Evidence**")

    model_evidence = ml_analysis.get("model_evidence", [])

    if model_evidence:
        st.dataframe(model_evidence, use_container_width=True)
    else:
        st.info("No model evidence available.")
else:
    st.info("ML analysis is not available for this email.")




# ==========================================
# EMAIL INFORMATION
# ==========================================

st.header("📧 Email Information")

email_data = {

    "From":
        headers.get("from"),

    "To":
        headers.get("to"),

    "Reply-To":
        headers.get("reply_to"),

    "Subject":
        headers.get("subject"),

    "Date":
        headers.get("date"),

    "Return-Path":
        headers.get("return_path")
}

st.table(email_data)


# ==========================================
# AUTHENTICATION
# ==========================================

st.header("🔐 Email Authentication")

auth_col1, auth_col2, auth_col3 = st.columns(3)


with auth_col1:

    st.subheader("SPF")

    if authentication["spf"].lower() == "pass":

        st.success("PASS")

    else:

        st.error(
            authentication["spf"].upper()
        )


with auth_col2:

    st.subheader("DKIM")

    if authentication["dkim"].lower() == "pass":

        st.success("PASS")

    else:

        st.error(
            authentication["dkim"].upper()
        )


with auth_col3:

    st.subheader("DMARC")

    if authentication["dmarc"].lower() == "pass":

        st.success("PASS")

    else:

        st.error(
            authentication["dmarc"].upper()
        )


# ==========================================
# NETWORK INDICATORS
# ==========================================

st.header("🌐 Network Indicators")

col1, col2 = st.columns(2)


with col1:

    st.subheader("IP Addresses")

    for ip in ip_addresses:

        st.code(ip)


with col2:

    st.subheader("Domains")

    for domain in domains:

        st.code(domain)


# ==========================================
# URL ANALYSIS
# ==========================================

st.header("🔗 URLs")

if urls:

    for url in urls:

        st.write(url)

else:

    st.info("No URLs found.")


# ==========================================
# ATTACHMENTS
# ==========================================

st.header("📎 Attachments")


if attachments:

    for attachment in attachments:

        with st.expander(
            attachment["filename"]
        ):

            st.write(
                "MIME Type:",
                attachment["mime_type"]
            )

            st.write(
                "Size:",
                attachment["size"],
                "bytes"
            )

            st.write("SHA-256:")

            st.code(
                attachment["sha256"]
            )

else:

    st.info("No attachments found.")


# ==========================================
# SUSPICIOUS INDICATORS
# ==========================================

st.header("🚨 Suspicious Indicators")


if indicators:

    for indicator in indicators:

        severity = indicator[
            "severity"
        ].upper()


        if severity == "HIGH":

            st.error(
                f"{indicator['type']} — HIGH\n\n"
                f"{indicator['description']}"
            )


        elif severity == "MEDIUM":

            st.warning(
                f"{indicator['type']} — MEDIUM\n\n"
                f"{indicator['description']}"
            )


        else:

            st.info(
                f"{indicator['type']} — LOW\n\n"
                f"{indicator['description']}"
            )

else:

    st.success(
        "No suspicious indicators found."
    )


# ==========================================
# THREAT INTELLIGENCE
# ==========================================

st.header("🔎 Threat Intelligence")


# ==========================================
# VIRUSTOTAL - URLS
# ==========================================

st.subheader("VirusTotal — URLs")


for result in threat_intelligence[
    "virustotal"
]["urls"]:

    st.write(
        f"URL: {result['url']}"
    )

    st.write(
        f"Malicious: "
        f"{result.get('malicious', 'UNKNOWN')} | "
        f"Suspicious: "
        f"{result.get('suspicious', 'UNKNOWN')} | "
        f"Harmless: "
        f"{result.get('harmless', 'UNKNOWN')} | "
        f"Undetected: "
        f"{result.get('undetected', 'UNKNOWN')}"
    )


# ==========================================
# VIRUSTOTAL - ATTACHMENTS
# ==========================================

st.subheader(
    "VirusTotal — Attachments"
)


for result in threat_intelligence[
    "virustotal"
]["attachments"]:

    st.write(
        f"File: {result['filename']}"
    )

    st.write(
        f"Status: "
        f"{result.get('status', 'Available')}"
    )


# ==========================================
# URLHAUS
# ==========================================

st.subheader("URLhaus")


for result in threat_intelligence[
    "urlhaus"
]:

    query_status = result.get(
        "result",
        {}
    ).get(
        "query_status",
        result.get(
            "status",
            "UNKNOWN"
        )
    )

    st.write(
        f"{result['url']} → {query_status}"
    )


# ==========================================
# ABUSEIPDB
# ==========================================

st.subheader("AbuseIPDB")


for result in threat_intelligence[
    "abuseipdb"
]:

    st.write(
        f"IP: {result['ip']} | "
        f"Abuse Confidence: "
        f"{result.get('abuse_confidence_score', 'UNKNOWN')} | "
        f"Reports: "
        f"{result.get('total_reports', 'UNKNOWN')}"
    )


# ==========================================
# DOWNLOAD REPORTS
# ==========================================

st.divider()

st.header("📥 Download Forensic Reports")


col1, col2 = st.columns(2)


with col1:

    if os.path.exists(
        "output/forensic_report.html"
    ):

        with open(
            "output/forensic_report.html",
            "rb"
        ) as file:

            st.download_button(
                label="📄 Download HTML Report",
                data=file,
                file_name="forensic_report.html",
                mime="text/html"
            )


with col2:

    if os.path.exists(
        "output/forensic_report.pdf"
    ):

        with open(
            "output/forensic_report.pdf",
            "rb"
        ) as file:

            st.download_button(
                label="📑 Download PDF Report",
                data=file,
                file_name="forensic_report.pdf",
                mime="application/pdf"
            )


# ==========================================
# FOOTER
# ==========================================

st.caption(
    "Phishing Email Forensics Project | "
    "Automated Analysis and Threat Intelligence Correlation"
)
