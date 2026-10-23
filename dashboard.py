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
                    if result.stderr:
    st.code(result.stderr)

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

            # ------------------------------------------
            # ROLE 3 - REPORT GENERATION
            # ------------------------------------------

            with st.spinner("Generating forensic reports..."):
                result = subprocess.run(
                    [
                        sys.executable,
                        "reporting/report_generator.py"
                    ],
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    st.error("Report generation failed.")
                    st.code(
                        result.stderr
                        or result.stdout
                        or "No error details returned."
                    )
                    st.stop()

                if result.stdout:
                    st.text(result.stdout)

            st.session_state.analysis_ready = True
            st.success("Analysis completed successfully!")
            st.rerun()

        except OSError as error:
            st.error(f"File or execution error: {error}")

        except Exception as error:
            st.error(f"Analysis failed: {error}")


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
    st.error(
        "Analysis file not found. Please analyze the email again."
    )
    st.stop()

if not os.path.exists(threat_file):
    st.warning(
        "Threat intelligence results are not available yet."
    )
    st.stop()


# ==========================================
# LOAD LATEST ANALYSIS
# ==========================================

try:
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

except (OSError, json.JSONDecodeError) as error:
    st.error(f"Could not load the analysis results: {error}")
    st.stop()


# ==========================================
# EXTRACT DATA
# ==========================================

headers = analysis.get("email", {}).get("headers", {})

authentication = analysis.get("authentication", {})

network_indicators = analysis.get("network_indicators", {})

ip_addresses = network_indicators.get("ip_addresses", [])

domains = network_indicators.get("domains", [])

content = analysis.get("content", {})

urls = content.get("urls", [])

attachments = analysis.get("attachments", [])

indicators = analysis.get("suspicious_indicators", [])

ml_analysis = analysis.get("ml_analysis", {})

forensic_risk = analysis.get("forensic_risk", "UNKNOWN")


# ==========================================
# RISK ASSESSMENT + ML PREDICTION
# ==========================================

st.header("🛡️ Risk Assessment")

ml_prediction = ml_analysis.get("prediction", "Unavailable")

phishing_probability = ml_analysis.get("phishing_probability")

ml_risk = ml_analysis.get("risk_level", "Unavailable")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Forensic Risk",
        forensic_risk
    )

with col2:
    st.metric(
        "ML Prediction",
        ml_prediction
    )

with col3:
    if phishing_probability is not None:
        try:
            probability_value = float(phishing_probability)

            # Support either a probability from 0 to 1
            # or a percentage from 0 to 100.
            if 0 <= probability_value <= 1:
                probability_value *= 100

            st.metric(
                "Phishing Probability",
                f"{probability_value:.2f}%"
            )

        except (TypeError, ValueError):
            st.metric(
                "Phishing Probability",
                "Unavailable"
            )
    else:
        st.metric(
            "Phishing Probability",
            "Unavailable"
        )

with col4:
    st.metric(
        "ML Risk Level",
        ml_risk
    )

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

    ml_indicators = ml_analysis.get(
        "forensic_indicators",
        []
    )

    if ml_indicators:
        for item in ml_indicators:
            st.write(f"• {item}")
    else:
        st.info("No ML forensic indicators available.")

    st.write("**Model Evidence**")

    model_evidence = ml_analysis.get(
        "model_evidence",
        []
    )

    if model_evidence:
        st.dataframe(
            model_evidence,
            use_container_width=True
        )
    else:
        st.info("No model evidence available.")

else:
    st.info("ML analysis is not available for this email.")


# ==========================================
# EMAIL INFORMATION
# ==========================================

st.header("📧 Email Information")

email_data = {
    "From": headers.get("from", "Unavailable"),
    "To": headers.get("to", "Unavailable"),
    "Reply-To": headers.get("reply_to", "Unavailable"),
    "Subject": headers.get("subject", "Unavailable"),
    "Date": headers.get("date", "Unavailable"),
    "Return-Path": headers.get("return_path", "Unavailable")
}

st.table(email_data)


# ==========================================
# EMAIL AUTHENTICATION
# ==========================================

st.header("🔐 Email Authentication")

auth_col1, auth_col2, auth_col3 = st.columns(3)

spf_status = str(
    authentication.get("spf", "UNKNOWN")
).upper()

dkim_status = str(
    authentication.get("dkim", "UNKNOWN")
).upper()

dmarc_status = str(
    authentication.get("dmarc", "UNKNOWN")
).upper()

with auth_col1:
    st.subheader("SPF")

    if spf_status == "PASS":
        st.success("PASS")
    else:
        st.error(spf_status)

with auth_col2:
    st.subheader("DKIM")

    if dkim_status == "PASS":
        st.success("PASS")
    else:
        st.error(dkim_status)

with auth_col3:
    st.subheader("DMARC")

    if dmarc_status == "PASS":
        st.success("PASS")
    else:
        st.error(dmarc_status)


# ==========================================
# NETWORK INDICATORS
# ==========================================

st.header("🌐 Network Indicators")

col1, col2 = st.columns(2)

with col1:
    st.subheader("IP Addresses")

    if ip_addresses:
        for ip in ip_addresses:
            st.code(str(ip))
    else:
        st.info("No IP addresses found.")

with col2:
    st.subheader("Domains")

    if domains:
        for domain in domains:
            st.code(str(domain))
    else:
        st.info("No domains found.")


# ==========================================
# URL ANALYSIS
# ==========================================

st.header("🔗 URLs")

if urls:
    for url in urls:
        st.write(str(url))
else:
    st.info("No URLs found.")


# ==========================================
# ATTACHMENTS
# ==========================================

st.header("📎 Attachments")

if attachments:
    for index, attachment in enumerate(attachments):
        filename = attachment.get(
            "filename",
            f"Attachment {index + 1}"
        )

        with st.expander(str(filename)):
            st.write(
                "MIME Type:",
                attachment.get("mime_type", "Unknown")
            )

            st.write(
                "Size:",
                attachment.get("size", "Unknown"),
                "bytes"
            )

            st.write("SHA-256:")

            st.code(
                str(attachment.get("sha256", "Unavailable"))
            )
else:
    st.info("No attachments found.")


# ==========================================
# SUSPICIOUS INDICATORS
# ==========================================

st.header("🚨 Suspicious Indicators")

if indicators:
    for indicator in indicators:
        severity = str(
            indicator.get("severity", "LOW")
        ).upper()

        indicator_type = indicator.get(
            "type",
            "Unknown indicator"
        )

        description = indicator.get(
            "description",
            "No description available."
        )

        message = (
            f"{indicator_type} — {severity}\n\n"
            f"{description}"
        )

        if severity == "HIGH":
            st.error(message)

        elif severity == "MEDIUM":
            st.warning(message)

        else:
            st.info(message)

else:
    st.success("No suspicious indicators found.")


# ==========================================
# THREAT INTELLIGENCE
# ==========================================

st.header("🔎 Threat Intelligence")


# ==========================================
# VIRUSTOTAL - URLS
# ==========================================

st.subheader("VirusTotal — URLs")

virustotal_data = threat_intelligence.get(
    "virustotal",
    {}
)

virustotal_urls = virustotal_data.get(
    "urls",
    []
)

if virustotal_urls:
    for result in virustotal_urls:
        st.write(
            f"URL: {result.get('url', 'Unknown')}"
        )

        st.write(
            f"Malicious: {result.get('malicious', 'UNKNOWN')} | "
            f"Suspicious: {result.get('suspicious', 'UNKNOWN')} | "
            f"Harmless: {result.get('harmless', 'UNKNOWN')} | "
            f"Undetected: {result.get('undetected', 'UNKNOWN')}"
        )

        st.divider()
else:
    st.info("No VirusTotal URL results available.")


# ==========================================
# VIRUSTOTAL - ATTACHMENTS
# ==========================================

st.subheader("VirusTotal — Attachments")

virustotal_attachments = virustotal_data.get(
    "attachments",
    []
)

if virustotal_attachments:
    for result in virustotal_attachments:
        st.write(
            f"File: {result.get('filename', 'Unknown')}"
        )

        st.write(
            f"Status: {result.get('status', 'Unknown')}"
        )

        st.divider()
else:
    st.info("No VirusTotal attachment results available.")


# ==========================================
# URLHAUS
# ==========================================

st.subheader("URLhaus")

urlhaus_results = threat_intelligence.get(
    "urlhaus",
    []
)

if urlhaus_results:
    for result in urlhaus_results:
        query_status = result.get(
            "result",
            {}
        ).get(
            "query_status",
            result.get("status", "UNKNOWN")
        )

        st.write(
            f"{result.get('url', 'Unknown URL')} → {query_status}"
        )
else:
    st.info("No URLhaus results available.")


# ==========================================
# ABUSEIPDB
# ==========================================

st.subheader("AbuseIPDB")

abuseipdb_results = threat_intelligence.get(
    "abuseipdb",
    []
)

if abuseipdb_results:
    for result in abuseipdb_results:
        st.write(
            f"IP: {result.get('ip', 'Unknown')} | "
            f"Abuse Confidence: "
            f"{result.get('abuse_confidence_score', 'UNKNOWN')} | "
            f"Reports: {result.get('total_reports', 'UNKNOWN')}"
        )
else:
    st.info("No AbuseIPDB results available.")


# ==========================================
# DOWNLOAD REPORTS
# ==========================================

st.divider()

st.header("📥 Download Forensic Reports")

col1, col2 = st.columns(2)

with col1:
    html_report = "output/forensic_report.html"

    if os.path.exists(html_report):
        with open(html_report, "rb") as file:
            html_data = file.read()

        st.download_button(
            label="📄 Download HTML Report",
            data=html_data,
            file_name="forensic_report.html",
            mime="text/html"
        )
    else:
        st.info("HTML report is not available.")

with col2:
    pdf_report = "output/forensic_report.pdf"

    if os.path.exists(pdf_report):
        with open(pdf_report, "rb") as file:
            pdf_data = file.read()

        st.download_button(
            label="📑 Download PDF Report",
            data=pdf_data,
            file_name="forensic_report.pdf",
            mime="application/pdf"
        )
    else:
        st.info("PDF report is not available.")


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.caption(
    "Phishing Email Forensics Project | "
    "Automated Analysis and Threat Intelligence Correlation"
)
