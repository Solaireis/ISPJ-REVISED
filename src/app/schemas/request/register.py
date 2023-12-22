# import third-party libraries
from pydantic import Field, EmailStr

# import local Python libraries
from .recaptcha_token import RecaptchaToken

class Register(RecaptchaToken):
    """The register request JSON schema."""
    username: str = Field(
        title="Username",
        description="The username of the user.",
        example="John Doe",
        min_length=1,
    )
    email: EmailStr = Field(
        title="User Email",
        description="The email address of the user.",
    )
    password: str = Field(
        min_length=8,
        max_length=64,
        title="User Password",
        description="The password entered by the user to hash using Argon2 before saving it into the database.",
        example="P@ssw0rd!",
    )