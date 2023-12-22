# import third-party libraries
from pydantic import Field, EmailStr

# import local Python libraries
from .recaptcha_token import RecaptchaToken

class CreateAdmin(RecaptchaToken):
    """The register request JSON schema."""
    username: str = Field (
        title="Username",
        description="The username of the user.",
        example="John Doe",
        min_length=1,
    )
    email: EmailStr = Field(
        title="User Email",
        description="The email address of the user.",
    )