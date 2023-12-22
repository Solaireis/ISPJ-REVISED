# import third-party libraries
from pydantic import Field

# import local Python libraries
from .recaptcha_token import RecaptchaToken

class Login(RecaptchaToken):
    """The login request JSON schema."""
    user_identifier: str = Field(
        title="The user's email or username",
        description="The email address of the user or the username.",
        min_length=1,
    )
    password: str = Field(
        min_length=8,
        max_length=64,
        title="User Password",
        description="The password of the user.",
        example="P@ssw0rd!",
    )
    stay_signed_in: bool = Field(
        default=False,
        description="If enabled, the user session will last for 14 days, otherwise it will last for 1 day or until the user closes the browser.",
    )
    email_token: str | None = Field(
        description="For user without 2FA and when the user is logging in from a different location, they will receive an email with a token in order to login.",
        example="123456",
        min_length=6,
        max_length=6,
        regex=r"^[0-9]+$",
    )