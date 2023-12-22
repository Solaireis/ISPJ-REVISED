# import third-party libraries
from pydantic import BaseModel, Field

class Followers(BaseModel):
    followers: list[dict] | None = Field(
        default=None
    )
    following: list[dict] | None = Field(
        default=None
    )
    pending: list[dict] | None = Field(
        default=None
    )
    requests: list[dict] | None = Field(
        default=None
    )
