# import third-party libraries
from pydantic import BaseModel, Field

# import Python's standard libraries
import enum

class MessageTimer(str, enum.Enum):
    """The message timer settings."""
    DISABLED = "disabled"
    ONE_HOUR = "1h"
    ONE_DAY = "24h"
    ONE_WEEK = "7d"
    ONE_MONTH = "1m"
    SIX_MONTHS = "6m"
    ONE_YEAR = "1y"

class ChatPrivacy(BaseModel):
    message_timer: MessageTimer | None = Field(
        title="The message timer setting.",
        description="For the disappearing messages feature, this is the setting for how long messages will be visible for.\nThis only affects the new messages sent after the setting is changed and for both parties.",
        example="1h",
    )
    hide_online_status: bool | None = Field(
        title="Hide online status setting.",
        description="For the hide online status feature, this is the setting for whether the user's online status will be hidden from other users in chat sessions.",
        example=True,
    )

__all__ = [
    "ChatPrivacy",
]