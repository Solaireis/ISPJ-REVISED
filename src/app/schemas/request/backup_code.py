# import third-party libraries
from pydantic import Field

# import local Python libraries
from .recaptcha_token import RecaptchaToken

class BackupCode(RecaptchaToken):
    """The backup code for 2FA removal request JSON schema."""
    backup_code: str = Field(
        title="Backup Code",
        description="The backup code of the user that the user should have saved beforehand. In the event that user cannot complete the 2FA verification, they can use the one-time backup code to disable the 2FA.",
        example="3Fu#j-F2z4FFZ$WNZ9",
        min_length=18,
        max_length=18,
    )