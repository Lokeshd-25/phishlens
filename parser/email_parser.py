from email import policy
from email.parser import BytesParser


def load_email(file_path):

    with open(file_path, "rb") as file:
        message = BytesParser(
            policy=policy.default
        ).parse(file)

    return message
