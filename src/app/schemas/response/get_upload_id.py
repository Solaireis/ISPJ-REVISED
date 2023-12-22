# import third-party libraries
from pydantic import Field

# import local Python libraries
from .api_response import APIResponse

class UploadIdResponse(APIResponse):
    upload_token: str | None = Field(
        min_length=1,
        description="The upload token that will be used to upload the file to the cloud storage.",
    )