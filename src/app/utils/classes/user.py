# import third-party libraries
import bson
from pymongo.database import Database

# import local Python libraries
from .common import Common
from utils import constants as C

# import Python's standard libraries
import asyncio
from typing import Self

class User(Common):
    def __init__(self, doc: dict) -> None:
        super().__init__(doc)
        self.bio: str = doc["profile"]["bio"]
        self.location: str = doc["profile"]["location"]
        self.url: str = doc["profile"]["url"]

        # Membership and content moderation settings
        self.mirai_plus: bool = doc["mirai_plus"]
        self.blur_sexual_images: bool = doc["content_moderation"]["sexual_images"]
        self.blur_violent_images: bool = doc["content_moderation"]["violent_images"]
        self.blur_meme_images: bool = doc["content_moderation"]["meme_images"]

        # Security Settings
        security_info: dict = doc["security"]
        self.sms_2fa: bool = security_info.get("sms_2fa", False)
        self.backup_code: str | None = None # needs to be set manually due to the need to decrypt it
        self.has_totp = security_info.get("secret_totp_token") is not None
        self.has_backup_code = security_info.get("backup_code") is not None

        # Data export
        self.has_exported_data = "exported_data" in security_info
        exported_data_info: dict = security_info.get("exported_data", {})
        self.requested_date: int = exported_data_info.get("requested_at")
        self.exported_date: int = exported_data_info.get("exported_at")
        self.exported_data_url: str = exported_data_info.get("signed_url")

        # Privacy Settings
        self.privacy = C.PERMISSIONS(**doc["privacy"])

        # Followers
        self.follower_list: list[bson.ObjectId] = doc["social"][C.FOLLOWER_TYPE.FOLLOWERS]
        self.following_list: list[bson.ObjectId] = doc["social"][C.FOLLOWER_TYPE.FOLLOWING]
        self.pending_list: list[bson.ObjectId] = doc["social"][C.FOLLOWER_TYPE.PENDING]
        self.requests_list: list[bson.ObjectId] = doc["social"][C.FOLLOWER_TYPE.REQUESTS]

        # Chat Settings
        self.online: bool = doc["chat"]["online"]
        self.message_timer: int = doc["chat"]["message_timer"]
        self.has_password_protection: bool = (doc["chat"]["password_protection"] is not None)
        self.hide_online_status: bool = doc["chat"]["hide_online_status"]

    @classmethod
    async def init(cls, doc: dict, db: Database) -> Self:
        """Initialize the user object.

        Args:
            doc (dict):
                The user document.
            db (Database):
                The database to use.

        Returns:
            User:
                The user object.
        """
        user_obj = cls(doc)

        # Notifications
        user_obj.notifications_count = await user_obj.get_notifications(db)
        return user_obj

    async def get_notifications(self, db: Database) -> str:
        """Get the notifications for the user.

        Args:
            db (Database):
                The database to use.

        Returns:
            str:
                The notifications count.
        """
        tasks = [
            db[C.CHAT_COLLECTION].find_one(
                filter={
                    "receiver": self.id,
                    "read": False,
                },
                projection={
                    "_id": 1,
                },
            ),
            db[C.NOTIFICATION_COLLECTION].count_documents({
                "user_id": self.id,
                "read": False,
            }),
        ]
        unread_msg, notifications = await asyncio.gather(*tasks)
        notifications_count = 0 if unread_msg is None else 1
        total_count = notifications_count + notifications
        if total_count > 9:
            return "9+"
        return str(total_count)