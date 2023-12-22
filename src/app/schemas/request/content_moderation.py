# import third-party libraries
from pydantic import BaseModel, Field

class ContentModeration(BaseModel):
    """The content moderation settings."""
    sexual_images: bool = Field(
        description="This will blur any sexual images on Mirai including videos.",
    )
    violent_images: bool = Field(
        description="This will blur any violent images on Mirai.",
    )
    meme_images: bool = Field(
        description="This will blur any meme images on Mirai.",
    )