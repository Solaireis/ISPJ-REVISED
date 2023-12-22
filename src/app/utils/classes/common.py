# import third-party libraries
import bson

# import Python's standard libraries
from datetime import datetime

class Common:
    def __init__(self, doc: dict):
        self.id: bson.ObjectId = doc["_id"]
        self.email: str = doc["email"]
        self.username: str = doc["username"]
        self.display_name: str = doc["display_name"]
        self.verified: bool = doc["verified"]
        self.created_at: datetime = doc["created_at"]

        # Profile Settings
        self.profile_image: str = doc["profile"]["image"]["url"]
        self.profile_banner_image: str = doc["profile"]["banner"]["url"] 

        # Sessions
        self.sessions: list[dict] = doc.get("sessions", [])

        # Ban Status
        self.banned: bool = doc["banned"]

        # OAuth2 settings
        self.oauth2: list[str] = doc.get("oauth2", [])
        self.linked_google = ("google" in self.oauth2)
        self.linked_facebook = ("facebook" in self.oauth2)

        #add whether is admin or is root attributes get the role from the security attribute
        self.role: list[str] = doc.get("security", {}).get("role", [])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Common):
            return NotImplemented
        return self.id == other.id

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, Common):
            return NotImplemented
        return self.id != other.id