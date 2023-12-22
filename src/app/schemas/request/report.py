# import third-party libraries
from pydantic import Field, BaseModel

# import Python's standard libraries
from enum import Enum

class Affected(Enum):
    MYSELF = "Myself"
    OTHER = "Someone else"
    GROUP = "A specific group of people"
    EVERYONE = "Everyone on Mirai"

class Reason(Enum):
    SPAM = "Spammed"
    IDENTITY = "Attacked because of identity"
    HARASSMENT = "Harassed or intimidated with violence"
    IMPERSONATION = "Impersonated or shown a deceptive identity"
    SELF_HARM = "Content that encourages self-harm"
    DISTURBING = "Sensitive or disturbing content"
    DECEPTIVE = "Dangerous deceptive information"

class Report(BaseModel):
    affected: Affected
    reason: Reason
    method: str = Field(
        min_length=50,
        max_length=500,
    )