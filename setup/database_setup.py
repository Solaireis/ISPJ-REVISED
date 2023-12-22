# import third-party libraries
from pymongo.mongo_client import MongoClient
from pymongo.database import Database
import pymongo.collection as MongoCollection
from pymongo.collation import Collation, CollationStrength # info: https://stackoverflow.com/questions/33736192/mongo-unique-index-case-insensitive

# import Python's standard libraries
import sys
import pathlib

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()
PYTHON_FILES_PATH = FILE_PATH.parent.joinpath("src", "app")
sys.path.append(str(PYTHON_FILES_PATH))
from utils import constants as C # type: ignore
from utils.functions import database as mongo # type: ignore

def create_user_collection(db: Database) -> None:
    db.create_collection(
        name=C.USER_COLLECTION,
    )
    db[C.USER_COLLECTION].create_indexes([
        MongoCollection.IndexModel(
            keys="email",
            unique=True,
            collation=Collation("en", strength=CollationStrength.PRIMARY),
        ),
        MongoCollection.IndexModel(
            keys="username",
            unique=True,
            collation=Collation("en", strength=CollationStrength.PRIMARY),
        ),
        MongoCollection.IndexModel(
            keys="display_name",
            collation=Collation("en", strength=CollationStrength.PRIMARY),
        ),
        MongoCollection.IndexModel(
            keys="sessions.session_id",
            unique=True,
            sparse=True,
        ),
        MongoCollection.IndexModel(
            keys="sessions.expiry_date",
        ),
        MongoCollection.IndexModel(
            keys="sessions.user_agent",
        ),
        MongoCollection.IndexModel(
            keys="blocked_users",
            sparse=True,
        ),
        MongoCollection.IndexModel(
            keys="setup_incomplete",
            sparse=True,
        ),
    ])

def create_one_time_token_collection(db: Database) -> None:
    db.create_collection(
        name=C.ONE_TIME_TOKEN_COLLECTION,
    )
    db[C.ONE_TIME_TOKEN_COLLECTION].create_indexes([
        MongoCollection.IndexModel(
            keys="created_at",
            expireAfterSeconds=12 * 60 * 60, # 12 hour
        ),
    ])

def create_post_collection(db: Database) -> None:
    db.create_collection(
        name=C.POST_COLLECTION,
    )
    db[C.POST_COLLECTION].create_indexes([
        MongoCollection.IndexModel(
            keys="user_id",
        ),
        MongoCollection.IndexModel(
            keys="images.blob_id",
            unique=True,
            sparse=True,
        ),
        MongoCollection.IndexModel(
            keys="video.blob_id",
            unique=True,
            sparse=True,
        ),
        MongoCollection.IndexModel(
            keys="description",
            sparse=True,
            collation=Collation("en", strength=CollationStrength.PRIMARY),
        ),
    ])

def create_comments_collection(db: Database) -> None:
    db.create_collection(
        name=C.COMMENTS_COLLECTION,
    )
    db[C.COMMENTS_COLLECTION].create_indexes([
        MongoCollection.IndexModel(
            keys="user_id",
        ),
        MongoCollection.IndexModel(
            keys="post_id",
        ),
    ])

def create_chat_collection(db: Database) -> None:
    db.create_collection(
        name=C.CHAT_COLLECTION,
    )
    db[C.CHAT_COLLECTION].create_indexes([
        MongoCollection.IndexModel(
            keys="sender",
        ),
        MongoCollection.IndexModel(
            keys="receiver",
        ),
        MongoCollection.IndexModel(
            keys="timestamp",
        ),
        # For the cloud function to filter 
        # out messages that of type "files".
        MongoCollection.IndexModel(
            keys="type",
        ),
        # For getting the individual file in the files array.
        MongoCollection.IndexModel(
            keys="files.blob_id",
            unique=True,
            sparse=True,
        ),
        # For the cloud function to delete any 
        # GCS blobs that are not in the database.
        MongoCollection.IndexModel(
            keys="files.blob_name",
            unique=True,
            sparse=True,
        ),
        MongoCollection.IndexModel(
            keys="files.compressed_blob_name",
            unique=True,
            sparse=True,
        ),
    ])

def create_delete_chat_collection(db: Database) -> None:
    db.create_collection(
        name=C.DELETED_CHAT_COLLECTION,
    )
    db[C.DELETED_CHAT_COLLECTION].create_indexes([
        MongoCollection.IndexModel(
            keys="deleted_at",
            expireAfterSeconds=30 * 60, # 30 minutes
        ),
    ])

def create_notifications_collection(db: Database) -> None:
    db.create_collection(
        name=C.NOTIFICATION_COLLECTION,
    )
    db[C.NOTIFICATION_COLLECTION].create_indexes([
        MongoCollection.IndexModel(
            keys="user_id",
        ),
        MongoCollection.IndexModel(
            keys="created_at",
            expireAfterSeconds=7 * 24 * 60 * 60, # 7 days
        ),
        # below are indexes to speed up the checking of duplicate notifications
        MongoCollection.IndexModel(
            keys="type",
        ),
        MongoCollection.IndexModel(
            keys="other_user",
            sparse=True,
        ),
        MongoCollection.IndexModel(
            keys="partial_message",
        ),
        MongoCollection.IndexModel(
            keys="post_id",
            sparse=True,
        ),
    ])

def create_file_analysis_collection(db: Database) -> None:
    db.create_collection(
        name=C.FILE_ANALYSIS_COLLECTION,
    )
    db[C.FILE_ANALYSIS_COLLECTION].create_indexes([
        MongoCollection.IndexModel(
            keys="identifier",
            unique=True,
        ),
    ])

def create_upload_ids_collection(db: Database) -> None:
    db.create_collection(
        name=C.UPLOAD_IDS_COLLECTION,
    )
    db[C.UPLOAD_IDS_COLLECTION].create_indexes([
        MongoCollection.IndexModel(
            keys="created_at",
            expireAfterSeconds=30 * 60, # 30 minutes
        ),
    ])

def ban_logs(db: Database) -> None:
    db.create_collection(
        name=C.BAN_COLLECTION,
    )
    db[C.BAN_COLLECTION].create_indexes([
        MongoCollection.IndexModel(
            keys="user_id", # the user id which is banned
        ),
        MongoCollection.IndexModel(
            keys="banned_by", # FK to the user who banned the user
        ),
        MongoCollection.IndexModel(
            keys="created_at", # search 
        ),
    ])

def report_logs(db: Database) -> None:
    db.create_collection(
        name=C.REPORT_COLLECTION,
    )

    db[C.REPORT_COLLECTION].create_indexes([
        MongoCollection.IndexModel(
            keys="reported_by", # reported by which user
        ),
        MongoCollection.IndexModel(
            keys="created_at", # for search
        ),
        MongoCollection.IndexModel(
            keys="category", # for searching
        ),
        MongoCollection.IndexModel(
            keys="user_id", # who got reported
        ),
    ])

def create_admin_collection(db: Database) -> None:
    db.create_collection(
        name=C.ADMIN_COLLECTION,
    )
    db[C.ADMIN_COLLECTION].create_indexes([
        MongoCollection.IndexModel(
            keys="email",
            unique=True,
            collation=Collation("en", strength=CollationStrength.PRIMARY),
        ),
    ])

def seed_super_admin(db: Database) -> None:
    email = C.ROOT_EMAIL
    username = email.split("@")[0]
    db[C.ADMIN_COLLECTION].insert_one(
        mongo.get_default_user_doc(
            email=email,
            username=username,
            is_admin=True,
            display_name=username,
            password_hash=None,
            session_info=None,
            verified=True,
            security={
                "role": [C.ROOT],
            },
            oauth2=["google"],
        ),
    )

def seed_admin(db: Database) -> None:
    email = C.ADMIN_EMAIL
    username = email.split("@")[0]
    db[C.ADMIN_COLLECTION].insert_one(
        mongo.get_default_user_doc(
            email=email,
            username=username,
            is_admin=True,
            display_name=username,
            password_hash=None,
            session_info=None,
            verified=True,
            security={
                "role": [C.ADMIN],
            },
            oauth2=["google"],
        ),
    )

def seed_mirai_system(db: Database) -> None:
    db.create_collection(
        name=C.MIRAI_SYSTEM_COLLECTION,
    )
    db[C.MIRAI_SYSTEM_COLLECTION].insert_one({
        "_id": "maintenance_mode",
        "status": False,
    })

def locking_logs(db: Database) -> None:
    db.create_collection(
        name=C.LOCK_COLLECTION,
    )


def main() -> None:
    while True:
        debug_prompt = input("Debug mode? (Y/n): ").lower().strip()
        if debug_prompt not in ("y", "n", ""):
            print("Invalid input", end="\n\n")
            continue
        else:
            debug_flag = (debug_prompt != "n")
            break

    user_client: MongoClient
    admin_client: MongoClient
    with (
        mongo.get_db_client(get_default=False, get_async=False, debug=debug_flag, use_root_acc=not debug_flag) as user_client,
        mongo.get_db_client(get_default=False, get_async=False, debug=debug_flag, get_admin_db=True, use_root_acc=not debug_flag) as admin_client,
    ):
        user_client.drop_database(C.DB_NAME)
        admin_client.drop_database(C.ADMIN_DB_NAME)

        client_db = user_client[C.DB_NAME]
        create_user_collection(client_db)
        create_one_time_token_collection(client_db)
        create_chat_collection(client_db)
        create_notifications_collection(client_db)
        create_delete_chat_collection(client_db)
        create_file_analysis_collection(client_db)
        create_post_collection(client_db)
        create_comments_collection(client_db)
        create_upload_ids_collection(client_db)

        admin_db = admin_client[C.ADMIN_DB_NAME]
        ban_logs(admin_db)
        report_logs(admin_db)
        locking_logs(admin_db)
        create_admin_collection(admin_db)
        seed_super_admin(admin_db)
        seed_admin(admin_db)
        seed_mirai_system(admin_db)

if __name__ == "__main__":
    main()
    print("Done", end="\n\n")