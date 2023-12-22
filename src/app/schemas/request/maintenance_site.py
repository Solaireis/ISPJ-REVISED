# import third-party libraries
from pydantic import Field, EmailStr, BaseModel

# import local Python libraries
from utils.constants import BSON_OBJECTID_REGEX
from .recaptcha_token import RecaptchaToken

class MaintenanceSite(RecaptchaToken):
    """The register request JSON schema."""
    username: str = Field (
        title="Username",
        description="The username of the user.",
        example="John Doe",
        min_length=1,
    )