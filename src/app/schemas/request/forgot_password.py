# import third-party libraries
from pydantic import Field, EmailStr

# import local Python libraries
from .recaptcha_token import RecaptchaToken

class ForgotPassword(RecaptchaToken):
    email: EmailStr = Field(
        title="User Email",
        description="The email address of the user.",
    )