# import third-party libraries
from pydantic import Field, BaseModel

from utils import constants as C

class PostText(BaseModel):
    """The PostText request JSON schema."""
    text: str = Field(
        title="Post Text",
        description="The text of the post",
    )
    md5_checksum: str = Field(
        title="Text md5 checksum",
        description="The md5 checksum of the text",
    )
    crc32c_checksum: int = Field(
        title="Text crc32c checksum",
        description="The crc32c checksum of the text",
    )
    post_id: str | None = Field(
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
        description="The offset of the post results using a post's ID",
    )
