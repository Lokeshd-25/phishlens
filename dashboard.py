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
