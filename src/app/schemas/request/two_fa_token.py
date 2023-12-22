# import third-party libraries
from pydantic import Field

# import local Python libraries
from .recaptcha_token import RecaptchaToken

# import Python's standard libraries
import enum

class TwoFaMethods(enum.Enum):
    SMS = "sms"
    AUTHENTICATOR = "authenticator"

class TwoFAToken(RecaptchaToken):
    """The 2FA token request JSON schema."""
    two_fa_token: str = Field(
        title="2FA Token",
        description="The 2FA token of the user that is retrieved via SMS or from an authenticator app.",
        example="123456",
        min_length=6,
        max_length=6,
    )
    purpose: TwoFaMethods