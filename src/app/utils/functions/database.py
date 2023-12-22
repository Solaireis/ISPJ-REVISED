# import third-party libraries
import orjson
import pymongo
import bson
from fastapi import (
    Request, 
    WebSocket,
)
from pymongo.collection import Collection
from pymongo.database import Database
import motor.motor_asyncio as mongodb

# import local Python libraries
from utils import constants as C
from .useful import get_location_str
from gcp import SecretManager
from utils.classes import (
    Locks,
    Bans,
)

# import Python's standard libraries
import time
import warnings
from datetime import (
    datetime, 
    timedelta,
)
import urllib.parse as urlparse

# docs: https://github.com/mongodb/motor/blob/master/doc/tutorial-asyncio.rst
__secret_manager = SecretManager()
USER_CONN_STR = (
    f"""
        mongodb+srv://
        {urlparse.quote_plus(__secret_manager.get_secret_payload(secret_id=C.DB_USERNAME_SECRET_ID))}
        :
        {urlparse.quote_plus(__secret_manager.get_secret_payload(secret_id=C.DB_PASSWORD_SECRET_ID))}
        @mirai.v8xh4.mongodb.net/?retryWrites=true&w=majority
    """.replace("\n", "").replace(" ", ""),
    "mongodb://localhost:27017",
)
ADMIN_CONN_STR = (
    f"""
        mongodb+srv://
        {urlparse.quote_plus(__secret_manager.get_secret_payload(secret_id=C.ADMIN_DB_USERNAME_SECRET_ID))}
        :
        {urlparse.quote_plus(__secret_manager.get_secret_payload(secret_id=C.ADMIN_DB_PASSWORD_SECRET_ID))}
        @mirai-admin.oi3011m.mongodb.net/?retryWrites=true&w=majority
    """.replace("\n", "").replace(" ", ""),
    "mongodb://localhost:27017",
)

def get_default_user_doc(
    email: str, 
    username: str, 
    is_registering: bool | None = False,
    is_admin: bool | None = False,
    password_hash: bytes | None = None, 
    session_info: dict | None = None,
    **kwargs,
    ) -> dict:
    """Returns the default user document to be inserted into the database for a new user.

    Args:
        email (str):
            The user's email address. Must be lowercase.
        username (str):
            The user's username. Must be lowercase.
        is_registering (bool | None):
            Whether the user is registering or not such that 
            the user won't have to verify their login location after registering.
            Note: A location str must be passed in as the "location" keyword argument.
        is-admin (bool | None):
            Whether the user is an admin or not and return the corresponding user document.
        password_hash (bytes | None):
            The user's password hash. If None, the user will be created without a password.
        session_info (dict | None):
            The user's session information. Must contain the following
            keys: "id" (str), "expiry" (datetime).
        **kwargs:
            Any other key-value pairs to be added to the user document.

    Returns:
        dict: 
            The default user document.
    """
    current_datetime = datetime.utcnow()
    if is_admin:
        user_doc = {
            "email": email,
            "username": username,
            "display_name": username,
            "verified": True,
            "banned": False,
            "security": {
                "role": [C.ADMIN],
            },
            "profile": {
                "image": {
                    "url": f"https://api.dicebear.com/5.x/initials/svg?seed={username}",
                },
                "banner": {
                    "url": C.DEFAULT_BANNER,
                },
            },
            "inactive": {
                "status": False,
                "last_updated": current_datetime,
            },
            "created_at": current_datetime,
        }
    else:
        user_doc = {
            "created_at": current_datetime,
            "email": email,
            "display_name": username,
            "username": username,
            "mirai_plus": False,
            "banned": False,
            "content_moderation": {
                "sexual_images": True,
                "violent_images": True,
                "meme_images": False,
            },
            "verified": False,
            "profile": {
                "image": {
                    "url": f"https://api.dicebear.com/5.x/initials/svg?seed={username}",
                },
                "banner": {
                    "url": C.DEFAULT_BANNER,
                },
                "bio": "Hello! I'm new to Mirai!",
                "location": "Earth",
                "url": "https://mirai.network",
            },
            "setup_incomplete": True,
            "privacy": {
                "send_direct_messages": C.FRIENDSHIP_TYPE.FOLLOWERS,
                "be_follower": C.FRIENDSHIP_TYPE.REQUEST_NEEDED,
                "see_posts": C.FRIENDSHIP_TYPE.FOLLOWERS,
                "search_indexed": C.FRIENDSHIP_TYPE.FOLLOWERS,
                "profile_location": C.FRIENDSHIP_TYPE.FOLLOWERS,
                "profile_url": C.FRIENDSHIP_TYPE.FOLLOWERS,
                "last_updated": None,
            },
            "social": {
                follower_type: [] for follower_type in C.FOLLOWER_TYPE
            },
            "security": {
                "role": [C.USER],
            },
            "chat": {
                "online": False,
                "message_timer": 0,
                "password_protection": None,
                "hide_online_status": False,
            },
        }

    if is_registering:
        user_doc["security"]["last_accessed"] = [{
            "location": kwargs.pop("location"),
            "datetime": time.time(),
        }]

    if password_hash is not None:
        user_doc["password"] = bson.Binary(password_hash)

    if session_info is not None:
        user_doc["sessions"] = [
            {"session_id": session_info["id"], "expiry_date": session_info["expiry"]},
        ]

    user_doc.update(kwargs)
    return user_doc

def get_db_client(
    get_default: bool | None = True, 
    get_admin_db: bool | None = False, 
    get_async: bool | None = True, 
    debug: bool = (C.DEBUG_MODE and not C.USE_REMOTE_DB), 
    use_root_acc: bool | None = False,
) -> pymongo.MongoClient | Database:
    """Get a MongoDB client or the database connection.

    Args:
        get_default (bool, optional): 
            Get the default database object. Defaults to True.
            Otherwise, get the client to connect to other databases.
        get_admin_db (bool, optional):
            Get the admin database server client. Defaults to False.
        get_async (bool, optional):
            Get the async client. Defaults to True.
            Otherwise, get the normal/synchronous client.
        debug_mode (bool):
            True if debug mode is enabled which will
            connect to the local database instead of a remote instance/cluster.
            Defaults to the value in constants.py.
        use_root_acc (bool, optional):
            Use the root account to connect to the remote databases.
            Defaults to False.
            Note: This is only for development purposes and 
            using it in production mode will raise a ValueError.

    Returns:
        pymongo.MongoClient | Database:
            The MongoDB client or database connection.
    """
    if use_root_acc and not C.DEBUG_MODE:
        raise ValueError("Cannot use root account in production mode.")

    if use_root_acc:
        root_credentials = orjson.loads(
            SecretManager().get_secret_payload(
                secret_id="mongodb-root-credentials",
            ),
        )
        warnings.warn(
            "Using root account to connect to remote databases.\n" \
            "IMPORTANT: This is only for development purposes and should not be used in production mode.",
            UserWarning,
        )
        if not get_admin_db:
            conn_str = f"mongodb+srv://{root_credentials['username']}:{root_credentials['password']}@mirai.v8xh4.mongodb.net/?retryWrites=true&w=majority"
        else:
            conn_str = f"mongodb+srv://{root_credentials['username']}:{root_credentials['password']}@mirai-admin.oi3011m.mongodb.net/?retryWrites=true&w=majority"
    else:
        conn_str = USER_CONN_STR[debug] \
                if not get_admin_db else ADMIN_CONN_STR[debug]

    kwargs = {
        "host": conn_str,
        "tls": not debug,
    }
    if get_async:
        client = mongodb.AsyncIOMotorClient(
            **kwargs,
        )
    else:
        client = pymongo.MongoClient(
            **kwargs,
        )
    db_name = C.ADMIN_DB_NAME if get_admin_db else C.DB_NAME
    return client[db_name] if get_default else client

def __get_notification_url(_type: str, **kwargs) -> str:
    """Get the notification URL.

    Args:
        _type (str):
            The notification type.
        **kwargs:
            The notification data.

    Returns:
        str:
            The notification URL.

    Raises:
        ValueError:
            If the notification type is invalid.
    """
    if _type == C.FOLLOW_TYPE and kwargs["username"] is not None:
        return f"/profile/{kwargs['username']}"
    elif _type == C.LIKE_POST_TYPE and kwargs["post_id"] is not None:
        return f"/post/{kwargs['post_id']}"
    else:
        raise ValueError(f"Invalid notification type: {_type}")

async def get_user_notifications(user_id: bson.ObjectId, db: Database, offset: bson.ObjectId | str | None = None) -> list[dict]:
    """Get the user's notifications.

    Args:
        user_id (bson.ObjectId):
            The user's ID.
        db (Database):
            The database connection.
        offset (bson.ObjectId | str, optional):
            The offset ID to start from. Defaults to None.

    Returns:
        list[dict]:
            The user's notifications.
    """
    if not isinstance(offset, bson.ObjectId):
        offset = bson.ObjectId(offset)

    query = {
        "user_id": user_id,
    }
    if offset is not None:
        query["_id"] = {"$lt": offset}

    cursor = db[C.NOTIFICATION_COLLECTION].find(query).sort("_id", pymongo.DESCENDING).limit(10)
    notifications = [notification async for notification in cursor]

    # Get the other user's profile image and username for the notification.
    other_user_ids = set(notification["other_user"] for notification in notifications)
    cursor = db[C.USER_COLLECTION].find({
        "_id": {
            "$in": list(other_user_ids),
        },
    })
    other_users = {
        user["_id"]: {
            "username": user["username"],
            "display_name": user["display_name"],
            "profile_image": user["profile"]["image"]["url"],
        }
        async for user in cursor
    }

    # Add the other user's profile image and username to the notification.
    for notification in notifications:
        other_user_info = other_users[notification["other_user"]]
        notification["profile_image"] = other_user_info["profile_image"]
        notification["username"] = other_user_info["username"]
        notification["message"] = f"{other_user_info['display_name']} {notification['partial_message']}"
        notification["link"] = __get_notification_url(notification["type"], **{
            "username": notification.get("username"),
            "post_id": notification.get("post_id"),
        })
    return notifications

ALLOWED_NOTIFICATION_TYPES = (
    C.FOLLOW_TYPE, 
    C.LIKE_POST_TYPE,
)
async def write_notification(
    db: Database, 
    user_id: bson.ObjectId | str, 
    notif_type: str, 
    partial_msg: str,
    **kwargs,
) -> None:
    """
    Write a notification to the MongoDB database.

    Args:
        db (Database):
            The MongoDB database.
        user_id (str):
            The user the notification belongs to.
        notif_type (str):
            A notif type of "C.NOTIFICATION_TYPE".
        partial_msg (str):
            The partial message to be used for constructing the notification message.
            E.g. "followed you" => will be constructed to "<user> followed you"
        **kwargs:
            Any other data

    Returns:
        None
    """
    if notif_type not in ALLOWED_NOTIFICATION_TYPES:
        raise ValueError(f"Invalid notification type: {notif_type}")

    if isinstance(user_id, str):
        user_id = bson.ObjectId(user_id)

    notif_col = db[C.NOTIFICATION_COLLECTION]
    _kwargs = {}
    _filter = {
        "created_at": {
            "$gte": datetime.utcnow() - timedelta(days=1),
        },
    }
    if notif_type == C.FOLLOW_TYPE:
        _kwargs["other_user"] = bson.ObjectId(kwargs.pop("other_user"))
        _filter.update({
            "user_id": user_id,
            "type": notif_type,
            "other_user": _kwargs["other_user"],
            "partial_message": partial_msg,
        })
    elif notif_type == C.LIKE_POST_TYPE:
        _kwargs["other_user"] = bson.ObjectId(kwargs.pop("other_user"))
        if user_id == _kwargs["other_user"]:
            return

        _kwargs["post_id"] = bson.ObjectId(kwargs.pop("post_id"))
        _filter.update({
            "user_id": user_id,
            "type": notif_type,
            "other_user": _kwargs["other_user"],
            "post_id": _kwargs["post_id"],
            "partial_message": partial_msg,
        })
    else:
        # This should never happen due to 
        # the check at the start of the function but just in case.
        raise ValueError(f"Invalid notification type: {notif_type}")

    existing_notif = await notif_col.find_one(
        filter=_filter,
        projection={"_id": 1},
    )
    if existing_notif is not None:
        return

    await notif_col.insert_one({
        "user_id": user_id,
        "type": notif_type,
        "created_at": datetime.utcnow(),
        "read": False,
        "partial_message": partial_msg,
        **_kwargs,
    })

async def get_user_from_session(request: Request | WebSocket, session_id: str, col: Collection = None) -> dict | None:
    """Get the user document from the session ID.

    Args:
        request (Request | WebSocket):
            The request or websocket object.
        session_id (str):
            The session ID.
        col (Collection, optional):
            The collection to search in. Defaults to None.
            If None, a new client to the database will be created and 
            will search in both the user collection and the admin collection.

    Returns:
        dict | None:
            The user document if found, otherwise None.
    """
    col_is_none = (col is None)
    if col_is_none:
        db = get_db_client()
        col = db[C.USER_COLLECTION]

    time_now = datetime.utcnow()
    user_location = await get_location_str(request)
    _filter = {
        "sessions.session_id": session_id, 
        "sessions.expiry_date": {"$gt": time_now},
        "sessions.location": user_location,
        "sessions.user_agent": request.headers.get("User-Agent", "Unknown"),
    }
    kwargs = {
        "filter": _filter,
        "projection": {
            "blocked_users": 0,
        },
    }

    user_doc: dict | None = await col.find_one(**kwargs)
    if user_doc is None and not col_is_none:
        # The session ID is invalid
        return None
    elif user_doc is not None:
        return user_doc

    # check admin db
    db = get_db_client(get_admin_db=True)
    admin_col = db[C.ADMIN_COLLECTION]
    admin_doc: dict | None = await admin_col.find_one(**kwargs)
    if admin_doc is None:
        # The session ID is invalid
        return None
    return admin_doc

async def get_user_role(
    request: Request, session_id: str, 
    col: Collection | None = None, 
    clear_session_if_invalid: bool | None = True,
) -> tuple[dict | None, list[str]]:
    """Get the role of the user from the session ID.

    Args:
        request (Request):
            The request object.
        session_id (str): 
            The session ID.
        col (Collection, optional):
            Collection to search in. Defaults to None.
            If None, a new client to the database will be created.
        clear_session_if_invalid (bool, optional):
            Whether to clear the session if the session ID is invalid.
            Defaults to True.

    Returns:
        tuple[dict | None, list[str]]:
            The user document and the role of the user.
    """
    default = [C.GUEST]
    if session_id is None:
        return None, default

    user_doc = await get_user_from_session(
        request=request,
        session_id=session_id, 
        col=col,
    )
    if user_doc is None:
        if clear_session_if_invalid:
            # The session ID is invalid
            request.session.clear()
        return None, default

    return user_doc, user_doc["security"]["role"]

async def get_account_count(db: Database, acc_type: str) -> str:
    db = get_db_client(get_default=True, get_admin_db=False)
    admin_db = get_db_client(get_admin_db=True)
    if acc_type == "user":
        user_count = await db[C.USER_COLLECTION].count_documents({
            "security.role": {
                "$elemMatch": {
                    "$eq": C.USER,
                },
            },
        })

    elif acc_type == "admin":
        user_count = await admin_db[C.ADMIN_COLLECTION].count_documents({
            "security.role": {
                "$elemMatch": {
                    "$eq": C.ADMIN,
                },
            },
        })

    elif acc_type == "all":
        user_count = await db[C.USER_COLLECTION].count_documents({
            "username": {
                "$regex": r"^(User|Admin|Maintenance|Super Root) \d+$"
            }
        })

    elif acc_type == "fake_reporter":
        user_count = await db[C.USER_COLLECTION].count_documents({
            "username": {
                "$regex": r"^Fakereporter \d+$"
            }
        })

    elif acc_type == "victim99":
        user_count = await db[C.USER_COLLECTION].count_documents({
            "username": {
                "$regex": r"^Victim99 \d+$"
            }
        })
    else:
        raise ValueError("Invalid account type")
    return user_count

async def get_report_count(db: Database) -> int:
    report_count = await db[C.REPORT_COLLECTION].count_documents(
        {"status": "open"},
    )
    if report_count == 0:
        return 0
    return report_count 

# retrieve all users in the databases
async def get_all_users(db: Database, acc_type: str) -> list[dict]:
    if acc_type == "user":
        users =  db[C.USER_COLLECTION].find({
            "security.role": {
                "$elemMatch": {
                    "$eq": C.USER,
                },
            },
        })                          
    elif acc_type == "admin":
        users = db[C.ADMIN_COLLECTION].find({
            "security.role": {
                "$elemMatch": {
                    "$eq": C.ADMIN,
                },
            },
        })

    elif acc_type == "root":
        users =  db[C.ADMIN_COLLECTION].find({
            "security.role": {
                "$elemMatch": {
                    "$eq": C.ROOT,
                },
            },
        })
    else:
        raise ValueError("Invalid account type")
    return await users.to_list(None)

async def get_all_locks(db: Database) -> list[Locks]:
    cusor = db[C.LOCK_COLLECTION].find({}).sort("done_at",pymongo.DESCENDING)
    return [Locks(doc) async for doc in cusor]

async def get_all_bans(db: Database) -> list[Bans]:
    cusor = db[C.BAN_COLLECTION].find({}).sort("done_at",pymongo.DESCENDING)
    return [Bans(doc) async for doc in cusor]

async def get_ban_logs_counts(db: Database) -> dict:
    """Get the number of locked accounts.

    Args:
        db (Database):
            The MongoDB database.

    Returns:
        dict:
            The number of locked accounts.
    """
    return await db[C.BAN_COLLECTION].count_documents({})

async def get_locked_logs_counts(db: Database) -> dict:
    """Get the number of locked accounts.

    Args:
        db (Database):
            The MongoDB database.

    Returns:
        dict:
            The number of locked accounts.
    """
    return  await db[C.LOCK_COLLECTION].count_documents({})

async def get_report_logs_counts(db: Database) -> dict:
    """Get the number of locked accounts.

    Args:
        db (Database):
            The MongoDB database.

    Returns:
        dict:
            The number of locked accounts.
    """
    return await db[C.REPORT_COLLECTION].count_documents({})

async def get_banned_users_counts(db: Database) -> dict:
    """Get the number of banned accounts.

    Args:
        db (Database):
            The MongoDB database.

    Returns:
        dict:
            The number of banned accounts.
    """
    return await db[C.USER_COLLECTION].count_documents({
        "banned": True,
    })


async def get_locked_admins_counts(db: Database) -> dict:
    """Get the number of banned accounts.

    Args:
        db (Database):
            The MongoDB database.

    Returns:
        dict:
            The number of banned accounts.
    """
    return await db[C.ADMIN_COLLECTION].count_documents({
        "inactive.status": True,
    })

async def get_open_reports_counts(db: Database) -> dict:
    """Get the number of banned accounts.

    Args:
        db (Database):
            The MongoDB database.

    Returns:
        dict:
            The number of banned accounts.
    """
    return await db[C.REPORT_COLLECTION].count_documents({
        "status": "open",
    })

async def get_maintenance_mode(db: Database) -> bool:
    """Get the maintenance mode status.

    Args:
        db (Database):
            The MongoDB database.

    Returns:
        bool:
            The maintenance mode status.
    """
    #check if the database is in maintenance mode
    maintenance = await db[C.MIRAI_SYSTEM_COLLECTION].find_one(
        filter={"_id": "maintenance_mode"},
        projection={"status": 1},
    )
    if maintenance is None:
        return False
    return maintenance["status"]