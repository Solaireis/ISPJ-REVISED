# import third-party libraries
from pydantic import BaseModel, Field

class RevokeSession(BaseModel):
    session_id: str = Field(
        title="Session ID",
        description="The ID of the session to revoke.",
        example=r"w%gvMkv!Cx)BRI5Q-oze_)NVVqMWnU$^vnLR%UsW",
        min_length=40,
        max_length=40,
    )