# import third-party libraries
import bson
from pymongo.database import Database
from pymongo.collection import Collection
from fastapi import (
    WebSocket, 
    Request,
)
from fastapi.responses import ORJSONResponse

# import local Python libraries
from utils import constants as C
from gcp import GcpAesGcm
import utils.functions.useful as useful

# import Python's standard libraries
import asyncio

chat_mutex = asyncio.Lock()
async def add_user_to_connected_list(websocket: WebSocket, user_id: bson.ObjectId) -> None:
    """Add the user to the list of connected users for cleanup.

    Args:
        websocket (WebSocket):
            The websocket object that will be used to get the FastAPI app.
        user_id (bson.ObjectId):
            The user's id.

    Returns:
        None:
    """
    async with chat_mutex:
        # add the user to the list of connected users
        websocket.app.state.chat_connected_users.add(user_id)

async def remove_user_from_connected_list(websocket: WebSocket, user_id: bson.ObjectId) -> None:
    """Removes the user to the list of connected users.

    Args:
        websocket (WebSocket):
            The websocket object that will be used to get the FastAPI app.
        user_id (bson.ObjectId):
            The user's id.

    Returns:
        None:
    """
    async with chat_mutex:
        # remove the user from the list of connected users
        websocket.app.state.chat_connected_users.remove(user_id)

async def decrypt_message(request: Request | WebSocket, encrypted_message: dict) -> dict:
    """Decrypt the message that is encrypted.

    Args:
        request (Request | WebSocket):
            The request object that will be used to get the "get_chat_file" API route.
        encrypted_message (dict):
            The message that is encrypted.

    Returns:
        dict:
            The same dictionary but with the message decrypted.
            For images, the message key will contain a signed URL to the image.
    """
    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    decrypted_message = ""
    if encrypted_message["type"] != "text":
        if encrypted_message["message"]:
            decrypted_message = await aes_gcm.symmetric_decrypt(
                ciphertext=encrypted_message["message"],
                key_id=C.DATABASE_KEY,
            )

        # get the API route that will call the 
        # cloud function to get a signed url and redirect to it.
        for file in encrypted_message["files"]:
            file["url"] = useful.url_for(
                request=request,
                name="get_chat_file",
                blob_id=file["blob_id"],
            )
    else:
        decrypted_message = await aes_gcm.symmetric_decrypt(
            ciphertext=encrypted_message["message"],
            key_id=C.DATABASE_KEY,
        )

    encrypted_message["message"] = decrypted_message
    return encrypted_message

async def decrypt_messages(request: Request | WebSocket, encrypted_messages: list[dict]) -> list[dict]:
    """Decrypt the messages that are encrypted.

    Args:
        request (Request | WebSocket):
            The request object that will be used to get the "get_chat_file" API route.
        encrypted_messages (list[dict]):
            The list of messages that are encrypted.

    Returns:
        list[dict]:
            The list of messages that are decrypted.
            For images, the message key will contain a signed URL to the image.
    """
    # Could use threading here but can be
    # quite slow when there are a lot of messages
    # since spawning a new thread can take a while.
    decrypted_messages = await asyncio.gather(*[
        decrypt_message(
            request=request,
            encrypted_message=message,
        ) for message in encrypted_messages
    ])
    return decrypted_messages

async def get_chat_notifications(user_id: bson.ObjectId, db: Database) -> list[dict]:
    """Get all the unread chats for the user.

    Args:
        user_id (bson.ObjectId):
            The user id.
        db (Database):
            The MongoDB database object.

    Returns:
        list[dict]:
            The list of unread chats.
    """
    sender_ids = await db[C.CHAT_COLLECTION].distinct(
        key="sender",
        filter={
            "receiver": user_id,
            "read": False,
        },
    )
    sender_docs = db[C.USER_COLLECTION].find(
        filter={
            "_id": {
                "$in": sender_ids,
            },
        },
        projection={
            "username": 1,
            "display_name": 1,
            "profile.image.url": 1,
        },
    )
    return [
        {
            "username": sender["username"],
            "display_name": sender["display_name"],
            "profile_image": sender["profile"]["image"]["url"],
        } 
        async for sender in sender_docs
    ]

async def send_chat_list(ws: WebSocket, user_doc: dict, chat_col: Collection, user_col: Collection) -> None:
    """Sends the chat list to the user.

    Args:
        ws (WebSocket):
            The websocket connection to the user.
        user_doc (dict):
            The user document.
        chat_col (Collection):
            The chat collection.
        user_col (Collection):
            The user collection.

    Returns:
        None:
    """
    # find all the unique chats session that the user has or has received messages from and sort them by timestamp
    chats = chat_col.aggregate([
        {
            "$match": {
                "$or": [
                    {"sender": user_doc["_id"]},
                    {"receiver": user_doc["_id"]},
                ],
            },
        },
        {
            "$group": {
                "_id": {
                    "sender": "$sender",
                    "receiver": "$receiver",
                },
                "last_message": {
                    "$last": "$$ROOT",
                },
            },
        },
        {
            "$project": {
                "_id": 0,
                "last_message": 1,
            },
        },
        {
            "$sort": {
                "last_message.timestamp": -1,
            },
        },
    ])

    # Get rid of the duplicate chats with the same sender and receiver or vice versa but keep the latest message
    # e.g. [{current_user, receiver1, 1/2/2022}, {receiver1, current_user, 2/2/2022}, {receiver2, current_user, 3/3/2022}]
    # ->
    # [{receiver, current_user, 2/2/2022}, {receiver2, current_user, 3/3/2022}]
    user_ids = set()
    chat_ids = set()
    filtered_chats = []
    async for chat in chats:
        sender, receiver = chat["last_message"]["sender"], chat["last_message"]["receiver"]
        if sender == user_doc["_id"]:
            chat_id = f"{sender}{receiver}"
        else:
            chat_id = f"{receiver}{sender}"

        if chat_id not in chat_ids:
            chat_ids.add(chat_id)
            filtered_chats.append(chat)

        if user_doc["_id"] == sender:
            user_ids.add(receiver)
        else:
            user_ids.add(sender)

    chats = filtered_chats

    # get all the sender and receiver's name and profile picture
    user_docs: list[dict] = await user_col.find({
        "_id": {
            "$in": list(user_ids),
        }
    }).to_list(length=None)

    # decrypt the latest message
    aes_gcm: GcpAesGcm = ws.app.state.obj_map[GcpAesGcm]
    async_tasks = [None] * len(chats)
    for idx in range(len(chats)):
        encrypted_msg = chats[idx]["last_message"]["message"]
        if encrypted_msg is not None:
            async_tasks[idx] = aes_gcm.symmetric_decrypt(
                ciphertext=encrypted_msg,
                key_id=C.DATABASE_KEY,
            )
        else:
            async_tasks[idx] = useful.filler_task()

    formatted_chats = [None] * len(chats)
    decrypted_messages = await asyncio.gather(*async_tasks)
    for idx in range(len(chats)):
        chat = chats[idx]["last_message"]
        formatted_dict = {}
        opposite_user_doc = {}
        receiver_username = ""
        if chat["sender"] != user_doc["_id"]:
            # current user is the receiver of the latest message
            for found_user_doc in user_docs:
                if found_user_doc["_id"] == chat["sender"]:
                    formatted_dict["_id"] = str(chat["sender"])
                    formatted_dict["read"] = chat["read"]
                    opposite_user_doc = found_user_doc
                    break
            else:
                return ORJSONResponse(
                    status_code=500,
                    content={
                        "message": "Something went wrong"
                    }
                )
            receiver_username = opposite_user_doc["username"]
        else:
            # current user is the sender of the latest message
            formatted_dict["_id"] = str(chat["receiver"])
            for found_user_doc in user_docs:
                if found_user_doc["_id"] == chat["receiver"]:
                    formatted_dict["read"] = True
                    opposite_user_doc = found_user_doc
                    break
            else:
                return ORJSONResponse(
                    status_code=500,
                    content={
                        "message": "Something went wrong"
                    }
                )
            receiver_username = "You"

        decrypted_msg = decrypted_messages[idx]
        if chat["type"] == "text":
            formatted_dict["message"] = f"{receiver_username}: {decrypted_msg}"
        else:
            if chat["message"] and decrypted_msg is not None:
                formatted_dict["message"] = f"{receiver_username}: {decrypted_msg}"
            else:
                formatted_dict["message"] = f"{receiver_username} sent {'a file' if len(chat['files']) == 1 else 'multiple files'}."

        formatted_dict["display_name"] = opposite_user_doc["display_name"]
        formatted_dict["username"] = opposite_user_doc["username"]
        formatted_dict["profile"] = opposite_user_doc["profile"]["image"]["url"]
        formatted_dict["online"] = opposite_user_doc.get("chat", {"online": False})["online"]
        formatted_dict["chat_id"] = str(chat["_id"])
        formatted_dict["timestamp"] = chat["timestamp"]
        formatted_chats[idx] = useful.format_json_response(formatted_dict)

    await ws.send_json({"chats": formatted_chats})