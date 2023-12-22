# import third-party libraries
import bson
from fastapi import (
    APIRouter, 
    Request, 
    Query,
    Path,
    Depends,
)
from fastapi.responses import RedirectResponse, ORJSONResponse

# import local Python libraries
from utils import constants as C
from utils.functions import (
    rbac,
    security as sec,
)
from gcp import ( 
    CloudFunction,
)

# import Python's standard libraries
import logging

# API routes that has a lenient rate limit
lenient_api = APIRouter(
    include_in_schema=True,
    prefix=C.API_PREFIX,
    dependencies=sec.get_rate_limiter_dependency(C.LENIENT_ROUTER),
    tags=["lenient"],
)

@lenient_api.get(
    path="/posts/file/{blob_id}",
    description="Get a signed URL to a post file stored in Google Cloud Storage.",
)
async def get_post_file(
    request: Request,
    blob_id: str = Path(
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
    ),
    compress: bool = Query(
        default=False,
        description="Whether to return the signed URL to the compressed version of the (image) file.",
    ),
    rbac_res: rbac.RBACResults | RedirectResponse = Depends(rbac.GENERAL_RBAC, use_cache=False),
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database

    blob_id = bson.ObjectId(blob_id)
    chat_col = db[C.POST_COLLECTION]
    post_doc = await chat_col.find_one({
        "$or": [
            {"images.blob_id": blob_id},
            {"video.blob_id": blob_id},
        ]
    })
    if post_doc is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "Post does not exist.",
            },
        )

    # user_doc = db[C.USER_COLLECTION].find_one({
    #     "_id": post_doc["user_id"],
    # })
    # if user_doc.get("privacy") and user_doc["privacy"]["see_posts"] == "followers":
    #     # TODO: check if user is following the user who posted the message
    #     # of course, guests can't see posts from private accounts.
    #     return ORJSONResponse(
    #         status_code=403,
    #         content={
    #             "message": "You are not authorised to access this file.",
    #         },
    #     )

    if post_doc.get("images") is None and post_doc.get("video") is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "Posts does not contain file.",
            },
        )

    matched_file = None
    for file in post_doc.get("images") or post_doc["video"]:
        if file["blob_id"] == blob_id:
            matched_file = file
            break
    else:
        # shouldn't happen but just in case
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "Message does not exist.",
            },
        )

    blob_name = matched_file["blob_name"]
    if compress and matched_file.get("compressed_blob_name") is not None:
        blob_name = matched_file["compressed_blob_name"]

    cloud_function: CloudFunction = request.app.state.obj_map[CloudFunction]
    signed_url_json = await cloud_function.invoke_instance(
        url=C.CREATE_SIGNED_URL_FUNCTION,
        json={
            "bucket_name": C.PRIVATE_BUCKET,
            "object_name": blob_name,
            "expiry": C.POSTS_SIGNED_URL_EXPIRY,
        },
    )
    signed_url = signed_url_json.get("signed_url")
    if signed_url is None:
        return ORJSONResponse(
            status_code=500,
            content={
                "message": "Failed to get signed URL. Please try again later.",
            },
        )
    return RedirectResponse(
        url=signed_url,
    )

@lenient_api.get(
    path="/chat/file/{blob_id}",
    description="Get a signed URL to a chat file stored in Google Cloud Storage.",
)
async def get_chat_file(
    request: Request,
    blob_id: str = Path(
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
    ),
    compress: bool = Query(
        default=False,
        description="Whether to return the signed URL to the compressed version of the (image) file.",
    ),
    rbac_res: rbac.RBACResults | RedirectResponse = Depends(rbac.USER_RBAC, use_cache=False),
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_doc = rbac_res.user_doc

    blob_id = bson.ObjectId(blob_id)
    chat_col = db[C.CHAT_COLLECTION]
    chat_msg_doc = await chat_col.find_one({
        "files.blob_id": blob_id,
    })
    if chat_msg_doc is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "Message does not exist.",
            },
        )

    if not ((chat_msg_doc["sender"] == user_doc["_id"]) ^ (chat_msg_doc["receiver"] == user_doc["_id"])):
        logging.info(f"User {user_doc['_id']} tried to access file #{blob_id}, in chat message #{chat_msg_doc['_id']}.")
        return ORJSONResponse(
            status_code=403,
            content={
                "message": "You are not authorised to access this file.",
            },
        )

    if chat_msg_doc["type"] == "text":
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "Message is not a file.",
            },
        )

    matched_file = None
    for file in chat_msg_doc["files"]:
        if file["blob_id"] == blob_id:
            matched_file = file
            break
    else:
        # shouldn't happen but just in case
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "Message does not exist.",
            },
        )

    blob_name = matched_file["blob_name"]
    if compress and matched_file.get("compressed_blob_name") is not None:
        blob_name = matched_file["compressed_blob_name"]

    cloud_function = await CloudFunction.init()
    signed_url_json = await cloud_function.invoke_instance(
        url=C.CREATE_SIGNED_URL_FUNCTION,
        json={
            "bucket_name": C.PRIVATE_BUCKET,
            "object_name": blob_name,
            "expiry": C.SIGNED_URL_EXPIRY,
        },
    )
    signed_url = signed_url_json.get("signed_url")
    if signed_url is None:
        return ORJSONResponse(
            status_code=500,
            content={
                "message": "Failed to get signed URL. Please try again later.",
            },
        )

    return RedirectResponse(
        url=signed_url,
    )