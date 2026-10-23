
import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"


def check_url(url):
    if not AUTH_KEY:
        return {
            "error": "URLHAUS_AUTH_KEY is missing from the environment."
        }

    headers = {
        "Auth-Key": AUTH_KEY
    }

    data = {
        "url": url
    }

    try:
        response = requests.post(
            URLHAUS_API,
            headers=headers,
            data=data,
            timeout=20
        )

        print("URLhaus HTTP Status:", response.status_code)

        if response.status_code != 200:
            print("URLhaus response:", response.text[:1000])
            return {
                "error": f"URLhaus HTTP {response.status_code}",
                "details": response.text[:500]
            }

        try:
            result = response.json()
        except ValueError:
            return {
                "error": "URLhaus returned invalid JSON."
            }

        print("URLhaus Result:", result)
        return result

    except requests.RequestException as exc:
        print("URLhaus request failed:", str(exc))
        return {
            "error": f"URLhaus request failed: {exc}"
        }


def load_analysis_result():
    with open(
        "output/analysis_result.json",
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


if __name__ == "__main__":
    analysis = load_analysis_result()
    urls = analysis.get("content", {}).get("urls", [])

    print("\n===== URLS FROM ROLE 1 =====")

    if not urls:
        print("No URLs found in the analysis result.")

    for url in urls:
        print("\nChecking:", url)
        result = check_url(url)
        print("URLhaus Result:")
        print(json.dumps(result, indent=2))
