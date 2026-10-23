import json
import requests

from virustotal import check_url, check_hash
from urlhaus import check_url as urlhaus_check_url
from abuseipdb import check_ip


def safe_api_call(function, value):

    try:
        return function(value)

    except requests.exceptions.Timeout:
        print("API request timed out.")
        return None

    except requests.exceptions.ConnectionError:
        print("API connection error.")
        return None

    except requests.exceptions.RequestException as error:
        print("API request error:", error)
        return None

    except Exception as error:
        print("Unexpected error:", error)
        return None


def load_analysis_result():

    with open(
        "output/analysis_result.json",
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def analyze_threat_intelligence():

    analysis = load_analysis_result()

    urls = analysis["content"]["urls"]
    ip_addresses = analysis["network_indicators"]["ip_addresses"]
    attachments = analysis["attachments"]

    results = {
        "virustotal": {
            "urls": [],
            "attachments": []
        },
        "urlhaus": [],
        "abuseipdb": []
    }

    # -----------------------------
    # VirusTotal URL Analysis
    # -----------------------------

    for url in urls:

        print("\n===== VirusTotal URL =====")
        print("Checking:", url)

        result = safe_api_call(check_url, url)

        if result:

            stats = result["data"]["attributes"]["last_analysis_stats"]

            results["virustotal"]["urls"].append({
                "url": url,
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "harmless": stats["harmless"],
                "undetected": stats["undetected"]
            })

        else:

            results["virustotal"]["urls"].append({
                "url": url,
                "status": "UNKNOWN"
            })


    # -----------------------------
    # VirusTotal Attachment Analysis
    # -----------------------------

    for attachment in attachments:

        filename = attachment["filename"]
        file_hash = attachment["sha256"]

        print("\n===== VirusTotal Attachment =====")
        print("Checking:", filename)
        print("SHA-256:", file_hash)

        result = safe_api_call(check_hash, file_hash)

        if result:

            stats = result["data"]["attributes"]["last_analysis_stats"]

            results["virustotal"]["attachments"].append({
                "filename": filename,
                "sha256": file_hash,
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "harmless": stats["harmless"],
                "undetected": stats["undetected"]
            })

        else:

            results["virustotal"]["attachments"].append({
                "filename": filename,
                "sha256": file_hash,
                "status": "UNKNOWN"
            })


    # -----------------------------
    # URLhaus Analysis
    # -----------------------------

    for url in urls:

        print("\n===== URLhaus =====")
        print("Checking:", url)

        result = safe_api_call(urlhaus_check_url, url)

        if result:

            results["urlhaus"].append({
                "url": url,
                "result": result
            })

        else:

            results["urlhaus"].append({
                "url": url,
                "status": "UNKNOWN"
            })


    # -----------------------------
    # AbuseIPDB Analysis
    # -----------------------------

    for ip in ip_addresses:

        print("\n===== AbuseIPDB =====")
        print("Checking:", ip)

        result = safe_api_call(check_ip, ip)

        if result:

            data = result["data"]

            results["abuseipdb"].append({
                "ip": ip,
                "abuse_confidence_score": data["abuseConfidenceScore"],
                "country_code": data["countryCode"],
                "isp": data["isp"],
                "domain": data["domain"],
                "is_tor": data["isTor"],
                "total_reports": data["totalReports"]
            })

        else:

            results["abuseipdb"].append({
                "ip": ip,
                "status": "UNKNOWN"
            })


    return results


if __name__ == "__main__":

    threat_results = analyze_threat_intelligence()

    print("\n===================================")
    print("THREAT INTELLIGENCE SUMMARY")
    print("===================================")

    print(json.dumps(
        threat_results,
        indent=4
    ))

    output_file = "output/threat_intelligence.json"

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            threat_results,
            file,
            indent=4,
            ensure_ascii=False
        )

    print("\nThreat intelligence saved to:", output_file)