import requests


PHISHTANK_API = "https://checkurl.phishtank.com/checkurl/"


def check_url(url):

    data = {
        "url": url,
        "format": "json"
    }

    headers = {
        "User-Agent": "PhishingEmailForensics/1.0"
    }

    response = requests.post(
        PHISHTANK_API,
        data=data,
        headers=headers
    )

    print("HTTP Status:", response.status_code)

    if response.status_code == 200:
        return response.json()

    print("PhishTank response:")
    print(response.text)

    return None


if __name__ == "__main__":

    test_url = "https://example.com"

    print("\n===== PHISHTANK RESULT =====")

    result = check_url(test_url)

    if result:
        print(result)