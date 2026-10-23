
import os
import json
import requests
import base64
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
BASE_URL = "https://www.virustotal.com/api/v3"


def make_headers():
    if not API_KEY:
        raise RuntimeError(
            "VIRUSTOTAL_API_KEY is missing from the environment."
        )

    return {"x-apikey": API_KEY}


def check_hash(file_hash):
    if not file_hash:
        return {"status": "INVALID_HASH"}

    try:
        response = requests.get(
            f"{BASE_URL}/files/{file_hash}",
            headers=make_headers(),
            timeout=20
        )

        print("VirusTotal hash HTTP Status:", response.status_code)

        if response.status_code == 200:
            return response.json()

        if response.status_code == 404:
            return {"status": "NOT_FOUND"}

        print("VirusTotal response:", response.text[:1000])
        return {
            "status": "API_ERROR",
            "http_status": response.status_code
        }

    except requests.RequestException as error:
        print("VirusTotal request failed:", error)
        return {"status": "REQUEST_ERROR"}


def check_url(url):
    try:
        url_id = base64.urlsafe_b64encode(
            url.encode("utf-8")
        ).decode("ascii").rstrip("=")

        response = requests.get(
            f"{BASE_URL}/urls/{url_id}",
            headers=make_headers(),
            timeout=20
        )

        print("VirusTotal URL HTTP Status:", response.status_code)

        if response.status_code == 200:
            return response.json()

        if response.status_code == 404:
            print("VirusTotal: URL has no existing analysis.")
            return {"status": "NOT_FOUND"}

        print("VirusTotal response:", response.text[:1000])
        return {
            "status": "API_ERROR",
            "http_status": response.status_code
        }

    except requests.RequestException as error:
        print("VirusTotal request failed:", error)
        return {"status": "REQUEST_ERROR"}


def load_analysis_result():
    with open(
        "output/analysis_result.json",
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


if __name__ == "__main__":
    analysis = load_analysis_result()
    attachments = analysis.get("attachments", [])

    print("\n===== ATTACHMENT HASHES FROM ROLE 1 =====")

    for attachment in attachments:
        filename = attachment.get("filename", "unknown")
        file_hash = attachment.get("sha256", "")

        print("\nChecking:", filename)
        print("SHA-256:", file_hash)

        result = check_hash(file_hash)

        if isinstance(result, dict) and "data" in result:
            stats = result["data"]["attributes"].get(
                "last_analysis_stats", {}
            )

            print("Malicious :", stats.get("malicious", 0))
            print("Suspicious:", stats.get("suspicious", 0))
            print("Harmless  :", stats.get("harmless", 0))
            print("Undetected:", stats.get("undetected", 0))
        else:
            print("Status:", result.get("status", "UNKNOWN"))
