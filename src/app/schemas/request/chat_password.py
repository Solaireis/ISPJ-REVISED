# import third-party libraries
from pydantic import Field

# import local Python libraries
from .recaptcha_token import RecaptchaToken

class ChatPassword(RecaptchaToken):
    """The privacy request JSON schema."""
    password: str = Field(
        title="The password for chat sessions.",
        description="Used for enabling or disabling password protection for the user's chat sessions.\nUsers will be prompted for the password when they try to start a chat session with any user or existing chat sessions.\nPassword security is also less strict here than the user's logon password for better user's experience and usability.",
        example="p@ssw0rd",
    )