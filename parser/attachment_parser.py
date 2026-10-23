import hashlib


def calculate_sha256(data):

    return hashlib.sha256(data).hexdigest()


def extract_attachments(message):

    attachments = []

    for part in message.walk():

        if part.get_content_disposition() == "attachment":

            filename = part.get_filename()

            data = part.get_payload(decode=True)

            if data:

                attachment = {
                    "filename": filename,
                    "mime_type": part.get_content_type(),
                    "size": len(data),
                    "sha256": calculate_sha256(data)
                }

                attachments.append(attachment)

    return attachments
