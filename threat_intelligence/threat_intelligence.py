
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

    urls = analysis.get("content", {}).get("urls", [])
    ip_addresses = analysis.get(
        "network_indicators", {}
    ).get("ip_addresses", [])
    attachments = analysis.get("attachments", [])

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

      
        if isinstance(result, dict) and "data" in result:
            stats = result["data"]["attributes"].get(
                "last_analysis_stats", {}
            )

            results["virustotal"]["urls"].append({
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            })

        elif isinstance(result, dict):
            status = result.get("status", "UNKNOWN")

            results["virustotal"]["urls"].append({
                "url": url,
                "status": (
                    "NOT_ANALYZED"
                    if status == "NOT_FOUND"
                    else status
                )
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
        filename = attachment.get("filename", "unknown")
        file_hash = attachment.get("sha256", "")

        print("\n===== VirusTotal Attachment =====")
        print("Checking:", filename)
        print("SHA-256:", file_hash)

        result = safe_api_call(check_hash, file_hash) if file_hash else None

        if isinstance(result, dict) and "data" in result:
            stats = result["data"]["attributes"]["last_analysis_stats"]

            results["virustotal"]["attachments"].append({
                "filename": filename,
                "sha256": file_hash,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
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

        if isinstance(result, dict):
            query_status = result.get("query_status", "")

            if query_status == "no_results":
                status = "NO_LISTING_FOUND"
            elif query_status == "ok":
                status = "LISTED"
            elif "error" in result:
                status = "ERROR"
            else:
                status = "UNKNOWN"

            results["urlhaus"].append({
                "url": url,
                "status": status,
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

        if isinstance(result, dict) and isinstance(result.get("data"), dict):
            data = result["data"]

            results["abuseipdb"].append({
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_tor": data.get("isTor"),
                "total_reports": data.get("totalReports")
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

    print(json.dumps(threat_results, indent=4))

    output_file = "output/threat_intelligence.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(
            threat_results,
            file,
            indent=4,
            ensure_ascii=False
        )

    print("\nThreat intelligence saved to:", output_file)
