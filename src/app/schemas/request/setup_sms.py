# import local Python libraries
from .recaptcha_token import RecaptchaToken
from .phone_number import Phone

class SetupSMS(RecaptchaToken, Phone):
    """The setup SMS request JSON schema."""