# import third-party libraries
from pydantic import BaseModel, Field

class VerifySmsSetup(BaseModel):
    """The verify SMS setup request JSON schema."""
    code: str = Field(
        title="Verification Code",
        description="The verification code that was sent to the phone number.",
        example="123456",
        min_length=6,
        max_length=6,
    )