# import third-party libraries
from pydantic import BaseModel, Field

class APIResponse(BaseModel):
    """The general response JSON schema."""
    message: str = Field(
        title="The response message.",
        description="If there was an error during the processing of the user's request, this will be the error message displayed to the client.",
        example="The username or password is incorrect.",
    )