import json
import os
from datetime import datetime



# ==========================================
# LOAD ANALYSIS RESULTS
# ==========================================

with open(
    "output/analysis_result.json",
    "r",
    encoding="utf-8"
) as file:

    analysis = json.load(file)


# ==========================================
# LOAD THREAT INTELLIGENCE
# ==========================================

with open(
    "output/threat_intelligence.json",
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

# Extract machine-learning analysis results
ml_analysis = analysis.get("ml_analysis", {})

ml_prediction = ml_analysis.get("prediction", "Unavailable")

ml_probability = ml_analysis.get("phishing_probability")

ml_risk_level = ml_analysis.get("risk_level", "Unavailable")

if ml_probability is not None:
    ml_probability_percent = f"{ml_probability * 100:.2f}%"
else:
    ml_probability_percent = "Unavailable"
# ==========================================
# CALCULATE RISK
# ==========================================

high_count = 0
medium_count = 0
low_count = 0

for indicator in indicators:

    severity = indicator["severity"].upper()

    if severity == "HIGH":
        high_count += 1

    elif severity == "MEDIUM":
        medium_count += 1

    elif severity == "LOW":
        low_count += 1


if high_count >= 2:

    risk_level = "HIGH"

elif high_count == 1 or medium_count >= 2:

    risk_level = "MEDIUM"

else:

    risk_level = "LOW"


# ==========================================
# HTML HELPER FUNCTIONS
# ==========================================

def status_class(value):

    value = str(value).lower()

    if value in ["pass", "passed", "harmless", "clean"]:

        return "safe"

    elif value in ["fail", "failed", "malicious", "suspicious"]:

        return "danger"

    else:

        return "unknown"


def escape_html(value):

    if value is None:
        return ""

    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


# ==========================================
# BUILD INDICATOR TABLE
# ==========================================

indicator_rows = ""

for indicator in indicators:

    severity = indicator["severity"]

    indicator_rows += f"""
    <tr>
        <td>{escape_html(indicator["type"])}</td>
        <td>
            <span class="severity {severity.lower()}">
                {escape_html(severity)}
            </span>
        </td>
        <td>{escape_html(indicator["description"])}</td>
    </tr>
    """


# ==========================================
# BUILD URL TABLE
# ==========================================

url_rows = ""

for url in urls:

    url_rows += f"""
    <tr>
        <td>{escape_html(url)}</td>
    </tr>
    """


# ==========================================
# BUILD ATTACHMENT TABLE
# ==========================================

attachment_rows = ""

if attachments:

    for attachment in attachments:

        attachment_rows += f"""
        <tr>
            <td>{escape_html(attachment["filename"])}</td>
            <td>{escape_html(attachment["mime_type"])}</td>
            <td>{escape_html(attachment["size"])} bytes</td>
            <td class="hash">
                {escape_html(attachment["sha256"])}
            </td>
        </tr>
        """

else:

    attachment_rows = """
    <tr>
        <td colspan="4">No attachments found.</td>
    </tr>
    """


# ==========================================
# BUILD THREAT INTELLIGENCE TABLES
# ==========================================

vt_url_rows = ""

for result in threat_intelligence["virustotal"]["urls"]:

    vt_url_rows += f"""
    <tr>
        <td>{escape_html(result["url"])}</td>
        <td>{result.get("malicious", "UNKNOWN")}</td>
        <td>{result.get("suspicious", "UNKNOWN")}</td>
        <td>{result.get("harmless", "UNKNOWN")}</td>
        <td>{result.get("undetected", "UNKNOWN")}</td>
    </tr>
    """


vt_attachment_rows = ""

for result in threat_intelligence["virustotal"]["attachments"]:

    vt_attachment_rows += f"""
    <tr>
        <td>{escape_html(result["filename"])}</td>
        <td class="hash">
            {escape_html(result["sha256"])}
        </td>
        <td>{escape_html(result.get("status", "Available"))}</td>
    </tr>
    """


urlhaus_rows = ""

for result in threat_intelligence["urlhaus"]:

    query_result = result.get("result", {}).get(
        "query_status",
        result.get("status", "UNKNOWN")
    )

    urlhaus_rows += f"""
    <tr>
        <td>{escape_html(result["url"])}</td>
        <td>{escape_html(query_result)}</td>
    </tr>
    """


abuseipdb_rows = ""

for result in threat_intelligence["abuseipdb"]:

    abuseipdb_rows += f"""
    <tr>
        <td>{escape_html(result["ip"])}</td>
        <td>{escape_html(result.get("abuse_confidence_score", "UNKNOWN"))}</td>
        <td>{escape_html(result.get("total_reports", "UNKNOWN"))}</td>
        <td>{escape_html(result.get("country_code", "UNKNOWN"))}</td>
        <td>{escape_html(result.get("isp", "UNKNOWN"))}</td>
    </tr>
    """


# ==========================================
# CREATE HTML REPORT
# ==========================================

generated_time = datetime.now().strftime(
    "%d %B %Y, %H:%M:%S"
)


html_report = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>Phishing Email Forensic Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 0;
    background: #f4f6f8;
    color: #222;
}}

.container {{
    width: 90%;
    max-width: 1200px;
    margin: 30px auto;
}}

.header {{
    background: #17202a;
    color: white;
    padding: 30px;
    border-radius: 10px;
}}

.header h1 {{
    margin: 0;
}}

.header p {{
    margin-bottom: 0;
    color: #d5d8dc;
}}

.card {{
    background: white;
    margin-top: 20px;
    padding: 25px;
    border-radius: 10px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}}

.card h2 {{
    margin-top: 0;
    color: #17202a;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th {{
    background: #17202a;
    color: white;
    padding: 12px;
    text-align: left;
}}

td {{
    padding: 12px;
    border-bottom: 1px solid #ddd;
    word-break: break-word;
}}

.info-table td:first-child {{
    font-weight: bold;
    width: 180px;
}}

.risk {{
    font-size: 24px;
    font-weight: bold;
    padding: 15px;
    border-radius: 8px;
    display: inline-block;
}}

.risk-high {{
    background: #f8d7da;
    color: #842029;
}}

.risk-medium {{
    background: #fff3cd;
    color: #664d03;
}}

.risk-low {{
    background: #d1e7dd;
    color: #0f5132;
}}

.severity {{
    font-weight: bold;
    padding: 5px 9px;
    border-radius: 5px;
}}

.high {{
    background: #f8d7da;
    color: #842029;
}}

.medium {{
    background: #fff3cd;
    color: #664d03;
}}

.low {{
    background: #d1e7dd;
    color: #0f5132;
}}

.safe {{
    color: #198754;
    font-weight: bold;
}}

.danger {{
    color: #dc3545;
    font-weight: bold;
}}

.unknown {{
    color: #6c757d;
    font-weight: bold;
}}

.hash {{
    font-family: monospace;
    font-size: 13px;
}}

.footer {{
    text-align: center;
    margin: 30px;
    color: #777;
    font-size: 13px;
}}

</style>

</head>


<body>

<div class="container">


<div class="header">

<h1>Phishing Email Forensic Report</h1>

<p>
Automated Phishing Email Forensic Analysis and
Threat Intelligence Correlation
</p>

<p>
Generated: {generated_time}
</p>

</div>


<!-- EXECUTIVE SUMMARY -->

<div class="card">

<h2>1. Executive Summary</h2>

<p>
The email was analyzed using automated forensic parsing
and external threat intelligence sources.
</p>

<p>
Overall Risk Assessment:
</p>

<div class="risk risk-{risk_level.lower()}">
{risk_level} SUSPICION
</div>

<p>
The analysis identified
<strong>{high_count}</strong> high-severity indicators,
<strong>{medium_count}</strong> medium-severity indicators,
and <strong>{low_count}</strong> low-severity indicators.
</p>
<div class="ml-summary">
    <h3>Machine Learning Assessment</h3>
    <p><strong>Prediction:</strong> {ml_prediction}</p>
    <p><strong>Phishing Probability:</strong> {ml_probability_percent}</p>
    <p><strong>ML Risk Level:</strong> {ml_risk_level}</p>
</div>



<!-- EMAIL INFORMATION -->

<div class="card">

<h2>2. Email Information</h2>

<table class="info-table">

<tr>
<td>From</td>
<td>{escape_html(headers.get("from"))}</td>
</tr>

<tr>
<td>To</td>
<td>{escape_html(headers.get("to"))}</td>
</tr>

<tr>
<td>Reply-To</td>
<td>{escape_html(headers.get("reply_to"))}</td>
</tr>

<tr>
<td>Return-Path</td>
<td>{escape_html(headers.get("return_path"))}</td>
</tr>

<tr>
<td>Subject</td>
<td>{escape_html(headers.get("subject"))}</td>
</tr>

<tr>
<td>Date</td>
<td>{escape_html(headers.get("date"))}</td>
</tr>

<tr>
<td>Message-ID</td>
<td>{escape_html(headers.get("message_id"))}</td>
</tr>

</table>

</div>


<!-- AUTHENTICATION -->

<div class="card">

<h2>3. Email Authentication</h2>

<table>

<tr>
<th>Mechanism</th>
<th>Result</th>
</tr>

<tr>
<td>SPF</td>
<td class="{status_class(authentication["spf"])}">
{escape_html(authentication["spf"]).upper()}
</td>
</tr>

<tr>
<td>DKIM</td>
<td class="{status_class(authentication["dkim"])}">
{escape_html(authentication["dkim"]).upper()}
</td>
</tr>

<tr>
<td>DMARC</td>
<td class="{status_class(authentication["dmarc"])}">
{escape_html(authentication["dmarc"]).upper()}
</td>
</tr>

</table>

</div>


<!-- NETWORK -->

<div class="card">

<h2>4. Network Indicators</h2>

<table>

<tr>
<th>Indicator Type</th>
<th>Value</th>
</tr>

<tr>
<td>IP Addresses</td>
<td>{escape_html(", ".join(ip_addresses))}</td>
</tr>

<tr>
<td>Domains</td>
<td>{escape_html(", ".join(domains))}</td>
</tr>

</table>

</div>


<!-- URL -->

<div class="card">

<h2>5. URLs</h2>

<table>

<tr>
<th>URL</th>
</tr>

{url_rows}

</table>

</div>


<!-- ATTACHMENTS -->

<div class="card">

<h2>6. Attachments</h2>

<table>

<tr>
<th>Filename</th>
<th>MIME Type</th>
<th>Size</th>
<th>SHA-256</th>
</tr>

{attachment_rows}

</table>

</div>


<!-- INDICATORS -->

<div class="card">

<h2>7. Suspicious Indicators</h2>

<table>

<tr>
<th>Indicator</th>
<th>Severity</th>
<th>Description</th>
</tr>

{indicator_rows}

</table>

</div>


<!-- VIRUSTOTAL URL -->

<div class="card">

<h2>8. VirusTotal URL Analysis</h2>

<table>

<tr>
<th>URL</th>
<th>Malicious</th>
<th>Suspicious</th>
<th>Harmless</th>
<th>Undetected</th>
</tr>

{vt_url_rows}

</table>

</div>


<!-- VIRUSTOTAL ATTACHMENT -->

<div class="card">

<h2>9. VirusTotal Attachment Analysis</h2>

<table>

<tr>
<th>Filename</th>
<th>SHA-256</th>
<th>Status</th>
</tr>

{vt_attachment_rows}

</table>

</div>


<!-- URLHAUS -->

<div class="card">

<h2>10. URLhaus Analysis</h2>

<table>

<tr>
<th>URL</th>
<th>Result</th>
</tr>

{urlhaus_rows}

</table>

</div>


<!-- ABUSEIPDB -->

<div class="card">

<h2>11. AbuseIPDB Analysis</h2>

<table>

<tr>
<th>IP Address</th>
<th>Abuse Confidence</th>
<th>Total Reports</th>
<th>Country</th>
<th>ISP</th>
</tr>

{abuseipdb_rows}

</table>

</div>


<!-- CONCLUSION -->

<div class="card">

<h2>12. Forensic Conclusion</h2>

<p>
The automated analysis identified suspicious
characteristics in the email, including a mismatch
between the sender and Reply-To address and the
presence of a URL. SPF, DKIM, and DMARC authentication
results were unavailable in the analyzed email.
</p>

<p>
Threat intelligence results are reported separately and
should be interpreted together with the email forensic
indicators.
</p>

<p>
<strong>Final Assessment:</strong>
{risk_level} suspicion based on the detected forensic indicators.
</p>

</div>


<div class="footer">

Phishing Email Forensics Project<br>
Automated Forensic Analysis and Threat Intelligence Correlation

</div>


</div>

</body>

</html>
"""


# ==========================================
# SAVE REPORT
# ==========================================

os.makedirs("output", exist_ok=True)

output_file = "output/forensic_report.html"

with open(
    output_file,
    "w",
    encoding="utf-8"
) as file:

    file.write(html_report)


print("\n======================================")
print("FORENSIC HTML REPORT GENERATED")
print("======================================")

print("Report saved to:", output_file)


# ==========================================
# GENERATE PDF REPORT
# ==========================================

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


pdf_file = "output/forensic_report.pdf"


# Create PDF document

doc = SimpleDocTemplate(
    pdf_file,
    pagesize=A4,
    rightMargin=40,
    leftMargin=40,
    topMargin=40,
    bottomMargin=40
)


# Styles

styles = getSampleStyleSheet()

title_style = ParagraphStyle(
    "ReportTitle",
    parent=styles["Title"],
    alignment=TA_CENTER,
    fontSize=20,
    spaceAfter=20
)

heading_style = ParagraphStyle(
    "Heading",
    parent=styles["Heading2"],
    fontSize=14,
    spaceBefore=15,
    spaceAfter=10
)

normal_style = ParagraphStyle(
    "NormalText",
    parent=styles["Normal"],
    fontSize=9,
    leading=13
)


story = []


# ------------------------------------------
# TITLE
# ------------------------------------------

story.append(
    Paragraph(
        "Phishing Email Forensic Report",
        title_style
    )
)

story.append(
    Paragraph(
        "Automated Phishing Email Forensic Analysis "
        "and Threat Intelligence Correlation",
        normal_style
    )
)

story.append(Spacer(1, 15))


# ------------------------------------------
# EXECUTIVE SUMMARY
# ------------------------------------------

story.append(
    Paragraph(
        "1. Executive Summary",
        heading_style
    )
)

summary_data = [
    ["Forensic Risk Level", risk_level],
    ["ML Prediction", ml_prediction],
    ["Phishing Probability", ml_probability_percent],
    ["ML Risk Level", ml_risk_level],
    ["High Indicators", str(high_count)],
    ["Medium Indicators", str(medium_count)],
    ["Low Indicators", str(low_count)]
]

summary_table = Table(
    summary_data,
    colWidths=[180, 280]
)

summary_table.setStyle(
    TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold")
    ])
)

story.append(summary_table)


# ------------------------------------------
# EMAIL INFORMATION
# ------------------------------------------

story.append(
    Paragraph(
        "2. Email Information",
        heading_style
    )
)

email_data = [
    ["From", headers.get("from", "")],
    ["To", headers.get("to", "")],
    ["Reply-To", headers.get("reply_to", "")],
    ["Return-Path", headers.get("return_path", "")],
    ["Subject", headers.get("subject", "")],
    ["Date", headers.get("date", "")],
    ["Message-ID", headers.get("message_id", "")]
]

email_table = Table(
    email_data,
    colWidths=[120, 340]
)

email_table.setStyle(
    TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold")
    ])
)

story.append(email_table)


# ------------------------------------------
# AUTHENTICATION
# ------------------------------------------

story.append(
    Paragraph(
        "3. Email Authentication",
        heading_style
    )
)

auth_data = [
    ["Mechanism", "Result"],
    ["SPF", authentication["spf"].upper()],
    ["DKIM", authentication["dkim"].upper()],
    ["DMARC", authentication["dmarc"].upper()]
]

auth_table = Table(
    auth_data,
    colWidths=[180, 280]
)

auth_table.setStyle(
    TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7)
    ])
)

story.append(auth_table)


# ------------------------------------------
# NETWORK INDICATORS
# ------------------------------------------

story.append(
    Paragraph(
        "4. Network Indicators",
        heading_style
    )
)

network_data = [
    ["Type", "Value"],
    ["IP Addresses", ", ".join(ip_addresses)],
    ["Domains", ", ".join(domains)]
]

network_table = Table(
    network_data,
    colWidths=[180, 280]
)

network_table.setStyle(
    TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7)
    ])
)

story.append(network_table)


# ------------------------------------------
# URLS
# ------------------------------------------

story.append(
    Paragraph(
        "5. URLs",
        heading_style
    )
)

url_data = [["URL"]]

for url in urls:
    url_data.append([url])

url_table = Table(
    url_data,
    colWidths=[460]
)

url_table.setStyle(
    TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7)
    ])
)

story.append(url_table)


# ------------------------------------------
# ATTACHMENTS
# ------------------------------------------

story.append(
    Paragraph(
        "6. Attachments",
        heading_style
    )
)

attachment_data = [
    ["Filename", "Size", "SHA-256"]
]

for attachment in attachments:

    attachment_data.append([
        attachment["filename"],
        str(attachment["size"]) + " bytes",
        attachment["sha256"]
    ])

attachment_table = Table(
    attachment_data,
    colWidths=[100, 80, 280]
)

attachment_table.setStyle(
    TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE", (0, 0), (-1, -1), 7)
    ])
)

story.append(attachment_table)


# ------------------------------------------
# SUSPICIOUS INDICATORS
# ------------------------------------------

story.append(
    Paragraph(
        "7. Suspicious Indicators",
        heading_style
    )
)

indicator_data = [
    ["Indicator", "Severity", "Description"]
]

for indicator in indicators:

    indicator_data.append([
        indicator["type"],
        indicator["severity"],
        indicator["description"]
    ])

indicator_table = Table(
    indicator_data,
    colWidths=[130, 70, 260]
)

indicator_table.setStyle(
    TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE", (0, 0), (-1, -1), 7)
    ])
)

story.append(indicator_table)


# ------------------------------------------
# THREAT INTELLIGENCE
# ------------------------------------------

story.append(
    Paragraph(
        "8. Threat Intelligence Summary",
        heading_style
    )
)

for result in threat_intelligence["virustotal"]["urls"]:

    story.append(
        Paragraph(
            f"VirusTotal URL: {result['url']}",
            normal_style
        )
    )

    story.append(
        Paragraph(
            f"Malicious: {result.get('malicious', 'UNKNOWN')} | "
            f"Suspicious: {result.get('suspicious', 'UNKNOWN')} | "
            f"Harmless: {result.get('harmless', 'UNKNOWN')} | "
            f"Undetected: {result.get('undetected', 'UNKNOWN')}",
            normal_style
        )
    )

    story.append(Spacer(1, 8))


for result in threat_intelligence["virustotal"]["attachments"]:

    story.append(
        Paragraph(
            f"VirusTotal Attachment: {result['filename']}",
            normal_style
        )
    )

    story.append(
        Paragraph(
            f"SHA-256: {result['sha256']} | "
            f"Status: {result.get('status', 'Available')}",
            normal_style
        )
    )

    story.append(Spacer(1, 8))


for result in threat_intelligence["urlhaus"]:

    query_status = result.get(
        "result", {}
    ).get(
        "query_status",
        result.get("status", "UNKNOWN")
    )

    story.append(
        Paragraph(
            f"URLhaus: {result['url']} | "
            f"Result: {query_status}",
            normal_style
        )
    )


for result in threat_intelligence["abuseipdb"]:

    story.append(
        Paragraph(
            f"AbuseIPDB: {result['ip']} | "
            f"Abuse Confidence: "
            f"{result.get('abuse_confidence_score', 'UNKNOWN')} | "
            f"Reports: "
            f"{result.get('total_reports', 'UNKNOWN')}",
            normal_style
        )
    )


# ------------------------------------------
# CONCLUSION
# ------------------------------------------

story.append(
    Paragraph(
        "9. Forensic Conclusion",
        heading_style
    )
)

story.append(
    Paragraph(
        "The automated analysis identified suspicious "
        "characteristics, including a mismatch between the "
        "sender and Reply-To address and the presence of a URL. "
        "SPF, DKIM, and DMARC authentication results were "
        "unavailable in the analyzed email.",
        normal_style
    )
)

story.append(Spacer(1, 8))

story.append(
    Paragraph(
        f"Final Assessment: {risk_level} suspicion based on "
        "the detected forensic indicators.",
        normal_style
    )
)

# ------------------------------------------
# BUILD PDF
# ------------------------------------------

doc.build(story)


print("\n======================================")
print("FORENSIC PDF REPORT GENERATED")
print("======================================")

print("PDF saved to:", pdf_file)
