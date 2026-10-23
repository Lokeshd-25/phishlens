import os
import json
import requests
from dotenv import load_dotenv


load_dotenv()

AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"


def check_url(url):

    headers = {
        "Auth-Key": AUTH_KEY
    }

    data = {
        "url": url
    }

    response = requests.post(
        URLHAUS_API,
        headers=headers,
        data=data
    )

    print("HTTP Status:", response.status_code)

    if response.status_code == 200:
        return response.json()

    print("URLhaus response:")
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

    urls = analysis["content"]["urls"]

    print("\n===== URLS FROM ROLE 1 =====")

    for url in urls:

        print("\nChecking:", url)

        result = check_url(url)

        if result:

            print("URLhaus Result:")
            print(result)