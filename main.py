import json
import os
import uuid
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml_predictor import analyze_email
from datetime import datetime
from parser.indicator_parser import detect_indicators
from parser.attachment_parser import extract_attachments
from parser.url_parser import (
    extract_urls,
    extract_domains,
    extract_html_urls
)
from parser.body_parser import extract_body
from parser.email_parser import load_email
from parser.header_parser import (
    extract_headers,
    extract_received_headers,
    extract_ip_addresses
)
from parser.auth_parser import parse_authentication


file_path = "samples/phishing_test.eml"

message = load_email(file_path)

headers = extract_headers(message)

received_headers = extract_received_headers(message)
ip_addresses = extract_ip_addresses(received_headers)

authentication = parse_authentication(message)
body = extract_body(message)
# ===== MACHINE LEARNING ANALYSIS =====

subject = headers.get("subject", "")
email_body = body["plain_text"] or body["html"] or ""

ml_result = analyze_email(subject, email_body)

print("\n===== ML PHISHING PREDICTION =====")
print("Prediction:", ml_result["prediction"])
print("Phishing Probability:", ml_result["phishing_probability"])
print("Risk Level:", ml_result["risk_level"])
plain_urls = extract_urls(body["plain_text"])

html_urls = extract_html_urls(body["html"])

all_urls = list(set(plain_urls + html_urls))

domains = extract_domains(all_urls)
attachments = extract_attachments(message)
indicators = detect_indicators(
    headers,
    authentication,
    all_urls,
    ip_addresses
)
# ===== COMBINED FORENSIC RISK ASSESSMENT =====

high_severity_count = sum(
    1 for indicator in indicators
    if indicator.get("severity", "").upper() == "HIGH"
)

if high_severity_count >= 2:
    forensic_risk = "HIGH"
elif high_severity_count == 1:
    forensic_risk = "MEDIUM"
else:
    forensic_risk = "LOW"
print("\n===== EMAIL HEADERS =====")

for key, value in headers.items():
    print(f"{key}: {value}")


print("\n===== RECEIVED HEADERS =====")

for received in received_headers:
    print(received)
    print("\n===== IP ADDRESSES =====")

for ip in ip_addresses:
    print(ip)


print("\n===== EMAIL AUTHENTICATION =====")

print("SPF :", authentication["spf"])
print("DKIM:", authentication["dkim"])
print("DMARC:", authentication["dmarc"])

print("\n===== EMAIL BODY =====")

print("Plain Text:")
print(body["plain_text"])

print("\nHTML:")
print(body["html"])
print("\n===== URL ANALYSIS =====")

print("URLs:")

for url in all_urls:
    print(url)

print("\nDomains:")

for domain in domains:
    print(domain)
    print("\n===== ATTACHMENT ANALYSIS =====")

if attachments:

    for attachment in attachments:

        print("Filename :", attachment["filename"])
        print("MIME Type:", attachment["mime_type"])
        print("Size     :", attachment["size"], "bytes")
        print("SHA-256  :", attachment["sha256"])
        print()

else:

    print("No attachments found.")
   
print("\n===== SUSPICIOUS INDICATORS =====")
if indicators:


    for indicator in indicators:

        print("Type       :", indicator["type"])
        print("Severity   :", indicator["severity"])
        print("Description:", indicator["description"])
        print()

else:

    print("No suspicious indicators found.")
    # Create final structured result

analysis_result = {
    "analysis_id": str(uuid.uuid4()),
    "analysis_timestamp": datetime.now().isoformat(),

    "email": {
        "headers": headers,
        "received_headers": received_headers
    },

    "authentication": authentication,

    "network_indicators": {
        "ip_addresses": ip_addresses,
        "domains": domains
    },

    "content": {
        "plain_text": body["plain_text"],
        "html": body["html"],
        "urls": all_urls
    },

       "attachments": attachments,

    "suspicious_indicators": indicators,
  "forensic_risk": forensic_risk,
    "ml_analysis": {
        "prediction": ml_result["prediction"],
        "phishing_probability": ml_result["phishing_probability"],
        "risk_level": ml_result["risk_level"],
        "forensic_indicators": ml_result["forensic_indicators"],
        "model_evidence": ml_result["model_evidence"],
        "forensic_features": ml_result["forensic_features"]
    }
}

# Create output directory if it does not exist

os.makedirs("output", exist_ok=True)


# Save result as JSON

output_file = "output/analysis_result.json"

with open(output_file, "w", encoding="utf-8") as file:

    json.dump(
        analysis_result,
        file,
        indent=4,
        ensure_ascii=False
    )


print("\n===== JSON OUTPUT =====")
print(f"Analysis saved to: {output_file}")