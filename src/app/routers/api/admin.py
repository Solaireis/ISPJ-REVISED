# import third-party libraries
import bson
from fastapi import (
    APIRouter, 
    Request,
    Depends,
    Query,
)
from fastapi.responses import (
    RedirectResponse, 
    ORJSONResponse,
)
import pymongo

# import local Python libraries
from utils import constants as C
from utils.functions import (
    rbac,
    security as sec,
    useful,
)
import schemas
import logging

# import Python's standard libraries
from datetime import datetime

admin_api = APIRouter(
    include_in_schema=True,
    prefix=C.API_PREFIX,
    dependencies=sec.get_rate_limiter_dependency(C.ADMIN_ROUTER),
    tags=["admins"],
)
RBAC_DEPENDENCY = Depends(rbac.ADMIN_RBAC, use_cache=False)

@admin_api.post(
    path="/ban",
    description="bans users",
    summary="bans the user",
    response_model=schemas.APIResponse,
)
async def api_ban_user(request: Request, data: schemas.Ban, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    _id = data.id
    reason = data.reason 
    db = rbac_res.database
    col = db[C.USER_COLLECTION]

    bson_id = bson.ObjectId(_id)
    user_doc = await col.find_one({
        "_id":bson_id 
    })
    if user_doc is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "User not found",
            },
        )
    if user_doc["banned"]:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "User is already banned",
            },
        )

    await col.update_one({"_id": bson_id}, {"$set": {"banned":True}})

    # open the admin database
    admin_db = rbac_res.admin_database
    admin_col = admin_db[C.BAN_COLLECTION]

    # create the ban document
    ban_doc = {
        "user_id": _id,
        "username": user_doc["username"],
        "reason": reason,
        "done_by": rbac_res.user_doc["username"],
        "done_at": datetime.now(),
        "banned_type": "ban"
    }
    await admin_col.insert_one(ban_doc)
    logging.warning(f"{rbac_res.user_doc['username']} banned user {_id}")
    return {
        "message": "User banned",
    }

@admin_api.post(
    path="/unban",
    description="bans users",
    summary="bans the user",
    response_model=schemas.APIResponse,
)
async def api_unban_user(request: Request, data: schemas.Ban, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    _id = data.id
    reason = data.reason 
    db = rbac_res.database
    col = db[C.USER_COLLECTION]

    bson_id = bson.ObjectId(_id)
    user_doc = await col.find_one({
        "_id":bson_id 
    })
    if user_doc is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "User not found",
            },
        )
    if user_doc["banned"] == False:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "User is already unbanned",
            },
        )

    await col.update_one({"_id": bson_id}, {"$set": {"banned":False}})

    # open the admin database
    admin_db = rbac_res.admin_database
    admin_col = admin_db[C.BAN_COLLECTION]

    # create the ban document
    ban_doc = {
        "user_id": _id,
        "username": user_doc["username"],
        "reason": reason,
        "done_by": rbac_res.user_doc["username"],
        "done_at": datetime.now(),
        "banned_type": "unban"
    }
    await admin_col.insert_one(ban_doc)
    logging.warning(f"{rbac_res.user_doc['username']} unbanned user {_id}")
    return {
        "message": "User unbanned",
    }

@admin_api.get(
    path="/get/users",
    description="Returns a list of users. pagination",
    summary="Return a list of users",
)
async def api_get_users(
    request: Request,
    offset: str | None = Query(
        default=None,
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
        description="The offset of the post results using a post's ID",
    ),
    user_id: str | None = Query(
        default=None,
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
        description="The offset of the post results using a post's ID",
    ),
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    db = rbac_res.database
    user_col = db[C.USER_COLLECTION]
    _filter = {}
    if offset is not None:
        _filter.update({
            "_id": {
                "$lt": bson.ObjectId(offset),
            },
        })

    if user_id is not None:
        _filter.update({"_id": bson.ObjectId(user_id)})

    user_col = db[C.USER_COLLECTION]
    limit = 7
    user_list = []
    cached_user_info = {}

    async with user_col.find(_filter).sort("_id", pymongo.DESCENDING) as cursor:
        async for doc in cursor:
            if len(user_list) >= limit:
                break

            user_id_str = str(doc["_id"])
            if user_id_str not in cached_user_info:
                matched_user = await user_col.find_one({"_id": doc["_id"]})
                if matched_user is None:
                    continue

                cached_user_info[user_id_str] = {
                    "id": user_id_str,
                    "verified": matched_user["verified"],
                    "banned": matched_user["banned"],
                    "username": matched_user["username"],
                    "display_name": matched_user["display_name"],
                    "profile_image": matched_user["profile"]["image"]["url"],
                }
            doc.update(cached_user_info[user_id_str])
            user_list.append(
                useful.format_json_response(doc)
            )

    if not user_list:
        return []

    logging.info(f"the admin {rbac_res.user_doc['username']} is fetching users")
    return user_list