# import third-party libraries
from pydantic import BaseModel, Field

# import local Python libraries
from utils import constants as C

# import Python's standard libraries
import enum

class UploadPurpose(enum.Enum):
    CHAT = "chat"
    POST = "post"

class GetUploadId(BaseModel):
    """The Get Upload Id request JSON schema."""
    author: str = Field(
        min_length=24, 
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
    )
    receiver: str | None = Field(
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
    )
    text: str | None = Field(
        min_length=1,
    )
    purpose: UploadPurpose
    number_of_files: int = Field(
        ge=1,
        description="The number of files that will be uploaded.",
    )
    md5_checksum: str | None = Field(
        min_length=32,
        max_length=32,
    )
    crc32c_checksum: int | None = Field(
        ge=0,
    )

__all__ = [
    "UploadPurpose",
    "GetUploadId",
]