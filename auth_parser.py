import re


def parse_authentication(message):

    authentication_headers = message.get_all(
        "Authentication-Results", []
    )

    authentication = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown"
    }

    text = " ".join(authentication_headers).lower()

    spf = re.search(
        r"\bspf=(pass|fail|neutral|softfail|temperror|permerror)\b",
        text
    )

    dkim = re.search(
        r"\bdkim=(pass|fail|neutral|temperror|permerror)\b",
        text
    )

    dmarc = re.search(
        r"\bdmarc=(pass|fail|neutral|temperror|softfail|temperror|permerror)\b",
        text
    )

    if spf:
        authentication["spf"] = spf.group(1)

    if dkim:
        authentication["dkim"] = dkim.group(1)

    if dmarc:
        authentication["dmarc"] = dmarc.group(1)

    return authentication