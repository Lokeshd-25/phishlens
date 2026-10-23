import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup


URL_PATTERN = r'https?://[^\s<>"\']+'


def extract_urls(text):

    if not text:
        return []

    return re.findall(URL_PATTERN, text)


def extract_domains(urls):

    domains = []

    for url in urls:

        try:
            domain = urlparse(url).netloc

            if domain:
                domains.append(domain)

        except Exception:
            pass

    return list(set(domains))


def extract_html_urls(html):

    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")

    urls = []

    for tag in soup.find_all("a", href=True):

        href = tag["href"]

        if href.startswith(("http://", "https://")):
            urls.append(href)

    return urls