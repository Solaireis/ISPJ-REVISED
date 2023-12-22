# import third-party libraries
import bson
import pymongo
from fastapi import APIRouter, Request, Depends
from fastapi.responses import RedirectResponse
from pymongo.collation import (
    Collation, 
    CollationStrength,
)

# import local Python libraries
from utils import constants as C
from utils.classes import User
from utils.functions import (
    security as sec,
    useful,
    rbac,
)
from gcp import (
    GcpAesGcm,
    CloudTasks,
)
from .web_utils import render_template
from middleware import csp

# import Python's standard libraries
from datetime import datetime

user_router = APIRouter(
    include_in_schema=False,
    prefix="",
    dependencies=sec.get_rate_limiter_dependency(C.USER_ROUTER),
    tags=["users"],
)
RBAC_DEPENDENCY = Depends(rbac.USER_RBAC, use_cache=False)

@user_router.get("/notifications")
async def notifications(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user = await User.init(rbac_res.user_doc, rbac_res.database)
    return await render_template(
        name="users/notifications.html",
        context={
            "request": request,
            "user": user,
            "csp_nonce": csp.get_nonce(request),
        },
    )

@user_router.get("/chat/{receiver}")
async def chat_1_to_1(request: Request, receiver: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    if not bson.ObjectId.is_valid(receiver):
        receiver_doc = await col.find_one(
            filter={"username": receiver},
            collation=Collation(locale="en", strength=CollationStrength.PRIMARY),
        )
        if receiver_doc is None:
            return RedirectResponse(url=useful.url_for(request, "chat"))
        receiver_uid = receiver_doc["_id"]
    else:
        receiver_uid = bson.ObjectId(receiver)
        receiver_doc = await col.find_one({"_id": receiver_uid})
        if receiver_doc is None: # no such user
            return RedirectResponse(url=useful.url_for(request, "chat"))

    sender_doc = rbac_res.user_doc
    sender_uid = sender_doc["_id"]
    if sender_uid == receiver_uid: # cannot chat with yourself
        return RedirectResponse(url=useful.url_for(request, "chat"))

    receiver_obj = User(receiver_doc)
    sender = User(sender_doc)
    return await render_template(
        name="users/chat_ws.html",
        context={
            "request": request,
            "sender": sender,
            "receiver": receiver_obj,
            "csp_nonce": csp.get_nonce(request),
            "max_msg_len": C.MAX_CHAT_MSG_LENGTH[sender_doc["mirai_plus"]],
        }
    )

@user_router.get("/chat")
async def chat(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc

    # get the latest chat sessions that the user has to redirect to
    col = db[C.CHAT_COLLECTION]
    user_id = user_doc["_id"]
    latest_chat = await col.find({
        "$or": [
            {"sender": user_id},
            {"receiver": user_id},
        ]
    }).sort("timestamp", pymongo.DESCENDING).limit(1).to_list(None)
    if len(latest_chat) > 0:
        latest_chat = latest_chat[0]
        if latest_chat["sender"] == user_id:
            receiver_uid = latest_chat["receiver"]
        else:
            receiver_uid = latest_chat["sender"]

        return RedirectResponse(
            url=useful.url_for(
                request=request,
                name="chat_1_to_1",
                receiver=receiver_uid
            )
        )

    sender = await User.init(user_doc, rbac_res.database)
    return await render_template(
        name="users/chat.html",
        context={
            "request": request,
            "sender": sender,
            "csp_nonce": csp.get_nonce(request),
        }
    )

@user_router.get("/feed")
async def feed(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res
    user_doc = rbac_res.user_doc

    return await render_template(
        name="users/post.html",
        context={
            "request": request,
            "csp_nonce": csp.get_nonce(request),
            "is_admin": user_doc["security"]["is_admin"],
            "is_root": user_doc["security"]["is_root"],
            "user":user_doc,
        }
    )

@user_router.get("/social")
async def followers_redirect(request: Request):
    return RedirectResponse(
        useful.url_for(request, "followers", follower_type=C.FOLLOWER_TYPE.FOLLOWERS)
    )

@user_router.get("/social/{follower_type}")
async def followers(request: Request, follower_type: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    followers_route = useful.url_for(request, "followers", follower_type=C.FOLLOWER_TYPE.FOLLOWERS)
    if follower_type not in C.FOLLOWER_TYPE:
        return RedirectResponse(followers_route)

    user_doc = rbac_res.user_doc
    user = await User.init(user_doc, rbac_res.database)

    if user.privacy.be_follower == C.FRIENDSHIP_TYPE.REQUEST_NEEDED:
        titles = C.FOLLOWER_TYPE
    elif follower_type == C.FOLLOWER_TYPE.PENDING:
        return RedirectResponse(followers_route)
    else:
        titles = (C.FOLLOWER_TYPE.FOLLOWERS, C.FOLLOWER_TYPE.FOLLOWING, C.FOLLOWER_TYPE.REQUESTS)

    return await render_template(
        name="users/followers.html",
        context={
            "request": request,
            "user": user,
            "current": follower_type,
            "titles": titles,
            "csp_nonce": csp.get_nonce(request),
        }
    )

@user_router.get("/settings")
async def settings(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user_doc = rbac_res.user_doc
    user = await User.init(user_doc, rbac_res.database)
    has_password = bool(user_doc.get("password"))
    user_col = rbac_res.database[C.USER_COLLECTION]

    blocked_users = await user_col.find_one(
        filter={
            "_id": user.id,
            "blocked_users": {"$exists": True},
        },
        projection={"_id": True}
    )
    if blocked_users:
        blocked_users = len(blocked_users)

    return await render_template(
        name="users/main_settings.html",
        context={
            "request": request,
            "user": user,
            "blocked_users": blocked_users,
            "csp_nonce": csp.get_nonce(request),
            "has_password": has_password,
        }
    )

@user_router.get("/settings/account-information")
async def account_info_settings(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user_doc = rbac_res.user_doc
    user = await User.init(user_doc, rbac_res.database)
    authenticated = useful.get_authenticated_status(request, user_doc)

    if not authenticated:
        return RedirectResponse(url=useful.url_for(request, "settings"))

    is_still_exporting = False
    exported_data_info = user_doc["security"].get("exported_data")
    if exported_data_info is not None:
        task_name = exported_data_info["task_name"]
        cloud_tasks: CloudTasks = request.app.state.obj_map[CloudTasks]
        task_info = await cloud_tasks.find_task(
            task_name=task_name, 
        )
        is_still_exporting = task_info is not None
        if not is_still_exporting and user.has_exported_data and user.exported_data_url is None:
            await rbac_res.database[C.USER_COLLECTION].update_one(
                {"_id": user_doc["_id"]},
                {"$unset": {"security.exported_data": ""}}
            )

    return await render_template(
        name="users/account_settings.html",
        context={
            "request": request,
            "user": user,
            "is_still_exporting": is_still_exporting,
            "csp_nonce": csp.get_nonce(request),
        }
    )
    # return RedirectResponse(url=useful.url_for(request, "settings"))

@user_router.get("/settings/sessions")
async def sessions_settings(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user = await User.init(rbac_res.user_doc, rbac_res.database)
    return await render_template(
        name="users/sessions_settings.html",
        context={
            "request": request,
            "user": user,
            "current_datetime": datetime.utcnow(),
            "csp_nonce": csp.get_nonce(request),
        },
    )

@user_router.get("/settings/2fa")
async def two_fa_settings(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user_doc = rbac_res.user_doc
    user = await User.init(user_doc, rbac_res.database)
    if user.has_backup_code:
        aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
        user.backup_code = await aes_gcm.symmetric_decrypt(
            ciphertext=user_doc["security"]["backup_code"],
            key_id=C.DATABASE_KEY,
        )

    _, user_country, _ = await useful.get_location_str(request, get_parts=True)
    return await render_template(
        name="users/2fa_settings.html",
        context={
            "request": request,
            "user": user,
            "user_country": user_country.lower() if user_country != "Unknown" else "sg",
            "csp_nonce": csp.get_nonce(request),
        },
    )

@user_router.get("/settings/privacy")
async def privacy_settings(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user = await User.init(rbac_res.user_doc, rbac_res.database)

    since_last_update = 0
    if user.privacy.last_updated is not None:
        since_last_update = (datetime.utcnow() - user.privacy.last_updated).days


    return await render_template(
        name="users/privacy_settings.html",
        context={
            "request": request,
            "setup_incomplete": rbac_res.user_doc.get("setup_incomplete"),
            "since_last_update": since_last_update,
            "csp_nonce": csp.get_nonce(request),
            "user": user
        }
    )

@user_router.get("/settings/blocked-users")
async def blocked_users(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user = await User.init(rbac_res.user_doc, rbac_res.database)
    user_col = rbac_res.database[C.USER_COLLECTION]

    blocked_users = await user_col.find_one(
        filter={
            "_id": user.id,
            "blocked_users": {"$exists": True},
        },
        projection={"_id": True}
    )
    if not blocked_users:
        return RedirectResponse(
            url=useful.url_for(request, "settings")
        )

    return await render_template(
        name="users/blocked_users.html",
        context={
            "request": request,
            "csp_nonce": csp.get_nonce(request),
            "user": user
        }
    )

@user_router.get("/settings/mirai-plus")
async def mirai_plus(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user = await User.init(rbac_res.user_doc, rbac_res.database)
    end_date = None

    if user.mirai_plus:
        payment_col = rbac_res.database[C.PAYMENT_COLLECTION]
        payment = await payment_col.find_one(
            filter = {
                "user_id": user.id,
                "$or": [
                    {"end_date": None}, 
                    {"end_date": {"$gte": datetime.utcnow()}},
                ],
            },
            projection={"end_date": True}
        )
        if payment:
            end_date = payment["end_date"]

    return await render_template(
        name="users/mirai_plus.html",
        context={
            "request": request,
            "csp_nonce": csp.get_nonce(request),
            "user": user,
            "end_date": end_date,
        },
    )