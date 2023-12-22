# import third-party libraries
from pydantic import BaseModel, Field

# import local Python libraries
from utils.constants import FRIENDSHIP_TYPE as FRIEND

# import Python's standard libraries
from enum import Enum

class Send_Direct_Messages_Friendship(Enum):
    public = FRIEND.PUBLIC
    followers = FRIEND.FOLLOWERS
    disabled = FRIEND.DISABLED
    close_friend = FRIEND.CLOSE_FRIEND

class Be_Follower_Friendship(Enum):
    public = FRIEND.PUBLIC
    request_needed = FRIEND.REQUEST_NEEDED

class See_Posts_Friendship(Enum):
    public = FRIEND.PUBLIC
    followers = FRIEND.FOLLOWERS
    close_friend = FRIEND.CLOSE_FRIEND

class Search_Indexed_Friendship(Enum):
    public = FRIEND.PUBLIC
    followers = FRIEND.FOLLOWERS
    disabled = FRIEND.DISABLED
    close_friend = FRIEND.CLOSE_FRIEND

class See_Profile_Friendship(Enum):
    public = FRIEND.PUBLIC
    followers = FRIEND.FOLLOWERS

class Permission(BaseModel):
    send_direct_messages: Send_Direct_Messages_Friendship | None = Field(
        default=None,
        title="Send Direct Messages",
        description="""
        \rWho can send you DMs?
        \r - Public (Everyone)
        \r - Followers Only
        \r - Disabled (No one)
        \r - Close Friends Only
        """,
    )
    be_follower: Be_Follower_Friendship | None = Field(
        default=None,
        title="Be Follower",
        description="""
        \rWho can follow you?
        \r - Public (Everyone)
        \r - Request Needed
        \r
        \r[Inherits "See_Profile_Friendship"]
        """
    )
    see_posts: See_Posts_Friendship | None = Field(
        default=None,
        title="See Posts",
        description="""
        \rWho can see your posts?
        \r - Public (Everyone)
        \r - Followers Only
        \r
        \r[Inherits "See_Profile_Friendship"]
        """
    )
    search_indexed: Search_Indexed_Friendship | None = Field(
        default=None,
        title="Send Direct Messages",
        description="""
        \rWho can find you in search?
        \r - Public (Everyone)
        \r - Followers Only
        \r - Disabled (No one)
        \r - Close Friends Only
        """,
    )
    profile_location: See_Profile_Friendship | None = Field(
        default=None,
        title="See Profile",
        description="""
        \rWho can see your location (in profile)?
        \r - Public (Everyone)
        \r - Followers Only
        """
    )
    profile_url: See_Profile_Friendship | None = Field(
        default=None,
        title="See Profile",
        description="""
        \rWho can see your link (in profile)?
        \r - Public (Everyone)
        \r - Followers Only
        """
    )
    profile_banner: See_Profile_Friendship | None = Field(
        default=None,
        title="See Profile",
        description="""
        \rWho can see your banner (in profile)?
        \r - Public (Everyone)
        \r - Followers Only
        """
    )

__all__ = [
    "Permission",
]