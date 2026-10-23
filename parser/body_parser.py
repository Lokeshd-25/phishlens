def extract_body(message):

    plain_text = ""
    html_text = ""

    if message.is_multipart():

        for part in message.walk():

            # Skip attachments
            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()

            if content_type == "text/plain":
                plain_text += part.get_content()

            elif content_type == "text/html":
                html_text += part.get_content()

    else:

        content_type = message.get_content_type()

        if content_type == "text/plain":
            plain_text = message.get_content()

        elif content_type == "text/html":
            html_text = message.get_content()

    return {
        "plain_text": plain_text,
        "html": html_text
    }
