# import third-party libraries
from pydantic import Field, BaseModel

""" Settings Authentication """
class EnterPassword(BaseModel):
    """The Enter Password request JSON schema."""
    password: str = Field(
        min_length=8,
        max_length=64,
        title="User Password",
        description="The password of the user.",
        example="P@ssw0rd!",
    )

class SetPassword(BaseModel):
    """The Enter Password request JSON schema."""
    old_password: str | None = Field(
        min_length=8,
        max_length=64,
        title="User Password",
        description="The password of the user.",
        example="P@ssw0rd!",
    )
    new_password: str = Field(
        min_length=8,
        max_length=64,
        title="User Password",
        description="The password of the user.",
        example="P@ssw0rd!",
    )
    cfm_password: str = Field(
        min_length=8,
        max_length=64,
        title="User Password",
        description="The password of the user.",
        example="P@ssw0rd!",
    )

""" Information Settings """
class EditEmail(BaseModel):
    """The Edit Profile request JSON schema."""
    email: str = Field(
        title="The user's email",
        description="The username of the user",
    )

class EditUsername(BaseModel):
    """The Edit Username request JSON schema."""
    username: str = Field(
        title="The user's username",
        description="The username of the user",
    )

""" User Page Settings"""
class EditProfile(BaseModel):
    """The Edit Profile request JSON schema."""
    username: str = Field(
        title="The user's username",
        description="The username of the user",
    )
    description: str = Field(
        title="User Bio",
        description="The Description of the user",
    )
    location: str = Field(
        title="User Location",
        description="The Location of the user",
    )
    website: str = Field(
        title="User Website",
        description="The Website of the user",
    )