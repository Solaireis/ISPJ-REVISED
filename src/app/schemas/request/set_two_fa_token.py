# import third-party libraries
from pydantic import BaseModel, Field

class SetTwoFAToken(BaseModel):
    """The 2FA token request JSON schema."""
    two_fa_token: str = Field(
        title="2FA Token",
        description="The 2FA token of the user that is retrieved vai email or from an authenticator app.",
        example="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        min_length=32,
        max_length=32,
        regex=r"^[A-Z2-7]+$",
    )
    two_fa_code: str = Field(
        title="2FA Token",
        description="The 2FA token of the user that is retrieved vai email or from an authenticator app.",
        example="123456",
        min_length=6,
        max_length=6,
        regex=r"^[0-9]+$",
    )