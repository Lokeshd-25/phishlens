import os
import json
import requests
from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"


def check_ip(ip):

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(
        ABUSEIPDB_API,
        headers=headers,
        params=params
    )

    print("HTTP Status:", response.status_code)

    if response.status_code == 200:
        return response.json()

    print("AbuseIPDB response:")
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

    ip_addresses = analysis["network_indicators"]["ip_addresses"]

    print("\n===== IP ADDRESSES FROM ROLE 1 =====")

    for ip in ip_addresses:

        print("\nChecking:", ip)

        result = check_ip(ip)

        if result:
            print("AbuseIPDB Result:")
            print(result)