# import third-party libraries
from pydantic import Field, EmailStr, BaseModel

# import local Python libraries
from utils.constants import BSON_OBJECTID_REGEX
from .recaptcha_token import RecaptchaToken

class Ban(BaseModel):
    """The register request JSON schema."""
    id: str = Field (
        title="id of the user",
        description="The id of the user.",
        example="63cf9a0eeddca6e26e96baec",
        min_length=24,
        max_length=24,
        regex=BSON_OBJECTID_REGEX,
    )
    reason: str = Field(
        title="Reasons",
        description="Reasons for ban",
    )
    # expiry_date: str = Field(
    #     title="Expiry Date",
    #     description="The date the ban will expire.",
    #     example="2021-12-31",
    # )