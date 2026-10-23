import os
import json
import requests
import base64
from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

BASE_URL = "https://www.virustotal.com/api/v3"

def check_hash(file_hash):

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(
        f"{BASE_URL}/files/{file_hash}",
        headers=headers
    )

    print("HTTP Status:", response.status_code)

    if response.status_code == 200:
        return response.json()

    if response.status_code == 404:
        print("VirusTotal: Hash not found in database")
        return None

    print("VirusTotal response:")
    print(response.text)

    return None


def check_url(url):

    headers = {
        "x-apikey": API_KEY
    }

    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    response = requests.get(
        f"{BASE_URL}/urls/{url_id}",
        headers=headers
    )

    print("HTTP Status:", response.status_code)

    if response.status_code == 200:
        return response.json()

    print("VirusTotal response:")
    print(response.text)

    return None


def load_analysis_result():

    with open(
        "output/analysis_result.json",
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


if __name__ == "__main__":

    analysis = load_analysis_result()

    attachments = analysis["attachments"]

    print("\n===== ATTACHMENT HASHES FROM ROLE 1 =====")

    for attachment in attachments:

        filename = attachment["filename"]
        file_hash = attachment["sha256"]

        print("\nChecking:", filename)
        print("SHA-256:", file_hash)

        result = check_hash(file_hash)

        if result:

            stats = result["data"]["attributes"]["last_analysis_stats"]

            print("Malicious :", stats["malicious"])
            print("Suspicious:", stats["suspicious"])
            print("Harmless  :", stats["harmless"])
            print("Undetected:", stats["undetected"])

    