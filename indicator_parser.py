def detect_indicators(headers, authentication, urls, ip_addresses):

    indicators = []

    # 1. Reply-To mismatch
    from_email = headers.get("from")
    reply_to = headers.get("reply_to")

    if from_email and reply_to:

        from_domain = from_email.split("@")[-1].replace(">", "")
        reply_domain = reply_to.split("@")[-1].replace(">", "")

        if from_domain.lower() != reply_domain.lower():
            indicators.append({
                "type": "Reply-To Mismatch",
                "severity": "HIGH",
                "description": "Reply-To domain differs from the From domain."
            })

    # 2. SPF failure
    if authentication.get("spf") == "fail":

        indicators.append({
            "type": "SPF Failure",
            "severity": "HIGH",
            "description": "SPF authentication failed."
        })

    # 3. DKIM failure
    if authentication.get("dkim") == "fail":

        indicators.append({
            "type": "DKIM Failure",
            "severity": "HIGH",
            "description": "DKIM authentication failed."
        })

    # 4. DMARC failure
    if authentication.get("dmarc") == "fail":

        indicators.append({
            "type": "DMARC Failure",
            "severity": "HIGH",
            "description": "DMARC authentication failed."
        })

    # 5. URLs found
    if urls:

        indicators.append({
            "type": "URLs Found",
            "severity": "MEDIUM",
            "description": f"{len(urls)} URL(s) found in the email."
        })

    # 6. IP addresses found
    if ip_addresses:

        indicators.append({
            "type": "IP Address Found",
            "severity": "LOW",
            "description": f"{len(ip_addresses)} IP address(es) found in Received headers."
        })

    return indicators