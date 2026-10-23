def extract_headers(message):

    headers = {
        "from": message.get("From"),
        "to": message.get("To"),
        "cc": message.get("Cc"),
        "bcc": message.get("Bcc"),
        "reply_to": message.get("Reply-To"),
        "return_path": message.get("Return-Path"),
        "subject": message.get("Subject"),
        "date": message.get("Date"),
        "message_id": message.get("Message-ID")
    }

    return headers


import re


def extract_received_headers(message):

    return message.get_all("Received", [])


def extract_ip_addresses(received_headers):

    ip_addresses = []

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    for received in received_headers:

        ips = re.findall(ip_pattern, received)

        for ip in ips:

            if ip not in ip_addresses:
                ip_addresses.append(ip)

    return ip_addresses
