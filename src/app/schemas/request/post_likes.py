# import third-party libraries
from pydantic import Field, BaseModel

# import local Python libraries
from utils import constants as C

class PostLikes(BaseModel):
    """The PostText request JSON schema."""
    post_id: str = Field(
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
        description="The offset of the search results using a user's ID",
    )
