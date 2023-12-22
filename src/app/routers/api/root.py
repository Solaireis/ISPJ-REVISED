# import third-party libraries
import bson
import pymongo.errors as mongo_e
import pymongo
from fastapi import (
    APIRouter, 
    Request, 
    Depends,
    Query
)
from fastapi.responses import (
    ORJSONResponse,
    RedirectResponse,
)

# import local Python libraries
from utils import constants as C
from utils.functions import (
    database as mongo,
    rbac,
    security as sec,
    useful,
)
from gcp import RecaptchaEnterprise
import schemas

# import Python's standard libraries
import logging
from datetime import datetime

root_api = APIRouter(
    include_in_schema=True,
    prefix=C.API_PREFIX,
    dependencies=sec.get_rate_limiter_dependency(C.ROOT_ROUTER),
    tags=["root"],
)
RBAC_DEPENDENCY = Depends(rbac.ROOT_RBAC, use_cache=False)

@root_api.post(
    path="/maintenance-create-admin",
    description="Create a user account and login to get authentication token cookie to access other API endpoints.",
    summary="Create an account to login to the API.",
    response_model=schemas.APIResponse,
)
async def api_create_admins(request: Request, data: schemas.CreateAdmin, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="maintenance_create_admins",
        min_threshold=0.75,
    ) 
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    email = data.email.lower()
    if not email.endswith("@miraisocial.live"):
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "The email must end with @miraisocial.live",
            }
        )
    username = data.username 

    db = rbac_res.admin_database
    col = db[C.ADMIN_COLLECTION]

    # check if username is already in use
    user_doc = await col.find_one({
        "username":username
    })
    if user_doc is not None:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "The username is already in use.",
            }
        )
    user_doc = mongo.get_default_user_doc(
        email=email,
        username=username,
        is_admin=True,
        session_info=None,
        oauth2=["google"],
    )
    try:
        await col.insert_one(user_doc)
    except (mongo_e.DuplicateKeyError):
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "The username or email is already in use.",
            }
        )
    logging.warning(f"Created a new admin account: {username} ({email})")
    return {
        "message": "Successfully registered a new account on Mirai.",
    }

@root_api.post(
    path="/lock-admin",
    description="bans users",
    summary="bans the user",
    response_model=schemas.APIResponse,
)
async def api_lock_admin(request: Request, data: schemas.Ban, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    _id = bson.ObjectId(data.id)
    reason = data.reason 
    db = rbac_res.admin_database
    col = db[C.ADMIN_COLLECTION]

    user_doc = await col.find_one({
        "_id":_id 
    })
    if user_doc is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "User not found",
            },
        )
    if user_doc["inactive"]["status"]:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "User is already locked",
            },
        )

    # Values to be updated.
    current_time = datetime.utcnow()
    await col.update_one(
        {"_id": _id},
        {"$set": {
            "inactive.status": True,
            "inactive.last_updated": current_time,
        }},
    )

    # open the admin database
    admin_db = rbac_res.admin_database
    admin_col = admin_db[C.LOCK_COLLECTION]

    # create the ban document
    ban_doc = {
        "user_id": _id,
        "username": user_doc["username"],
        "reason": reason,
        "done_by": rbac_res.user_doc["username"],
        "done_at": current_time,
        "lock_type": "lock"
    }
    await admin_col.insert_one(ban_doc)
    logging.warning(f"{rbac_res.user_doc['username']} locked admin {_id}")
    return {
        "message": "Admin locked",
    }

@root_api.post(
    path="/unlock-admin",
    description="bans users",
    summary="bans the user",
    response_model=schemas.APIResponse,
)
async def api_unlock_admin(request: Request, data: schemas.Ban, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    _id = bson.ObjectId(data.id)
    reason = data.reason 
    db = rbac_res.admin_database
    col = db[C.ADMIN_COLLECTION]

    user_doc = await col.find_one({
        "_id":_id 
    })
    if user_doc is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "User not found",
            },
        )
    if not user_doc["inactive"]["status"]:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "User is already unlocked",
            },
        )

    # Values to be updated.
    current_time = datetime.utcnow()
    await col.update_one(
        {"_id": _id}, 
        {"$set": {
            "inactive.status": False,
            "inactive.last_updated": current_time,
        }},
    )

    # open the admin database
    admin_db = rbac_res.admin_database
    admin_col = admin_db[C.LOCK_COLLECTION]

    # create the ban document
    ban_doc = {
        "user_id": _id,
        "username": user_doc["username"],
        "reason": reason,
        "done_by": rbac_res.user_doc["username"],
        "done_at": current_time,
        "lock_type": "unlock"
    }
    await admin_col.insert_one(ban_doc)
    logging.warning(f"{rbac_res.user_doc['username']} unlocked admin {_id}")
    return {
        "message": "Admin unlocked",
    }

@root_api.get(
    path="/get/admins",
    description="Returns a list of users. pagination",
    summary="Return a list of users",
)
async def api_get_admins(
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
    db = rbac_res.admin_database
    admin_col = db[C.ADMIN_COLLECTION]
    _filter = {}
    if offset is not None:
        _filter.update({
            "_id": {
                "$lt": bson.ObjectId(offset),
            },
        })

    if user_id is not None:
        _filter.update({"_id": bson.ObjectId(user_id)})

    admin_col = db[C.ADMIN_COLLECTION]
    limit = 7
    admin_list = []
    cached_user_info = {}

    async with admin_col.find(_filter).sort("_id", pymongo.DESCENDING) as cursor:
        async for doc in cursor:
            if len(admin_list) >= limit:
                break

            user_id_str = str(doc["_id"])
            if user_id_str not in cached_user_info:
                matched_user = await admin_col.find_one({"_id": doc["_id"]})
                if matched_user is None:
                    continue
                
                if matched_user["username"] == "notify.mirai":
                    continue

                cached_user_info[user_id_str] = {
                    "id": user_id_str,
                    "username": matched_user["username"],
                    "display_name": matched_user["display_name"],
                    "profile_image": matched_user["profile"]["image"]["url"],
                    "inactive": matched_user["inactive"]["status"],
                }
            doc.update(cached_user_info[user_id_str])
            admin_list.append(
                useful.format_json_response(doc),
            )

    if not admin_list:
        return []

    logging.info("notify.mirai is fetching the admin list")
    return admin_list

@root_api.post(
    path="/enable-maintenance",
    description="set the website to be maintenance",
    summary="set the website to be maintenance",
    response_model=schemas.APIResponse,
)
async def api_enable_maintenance(
    request: Request, 
    data: schemas.MaintenanceSite, 
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY
): 
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="maintenance_mode_enable",
        min_threshold=0.75,
    ) 
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    username = data.username
    if username != "notify.mirai":
        return ORJSONResponse(
            status_code=400, 
            content={"message": "Incorrect username! Please enter a valid username"},
        )

    db = rbac_res.admin_database
    maintenance_col = db[C.MIRAI_SYSTEM_COLLECTION]
    # get the current maintenance status
    maintenance = await maintenance_col.find_one(
        filter={"_id": "maintenance_mode"},
        projection={"status": 1},
    )
    if maintenance is not None and maintenance["status"]:
        return ORJSONResponse(
            status_code=400, 
            content={"message": "Maintenance mode is already enabled"},
        )

    await maintenance_col.update_one(
        {"_id": "maintenance_mode"}, 
        {"$set": {"status": True}},
    )
    logging.info(f"The website is now in live mode, set by {rbac_res.user_doc['username']} , root account")
    return {
        "message": "Maintenance mode enabled",
    }

@root_api.post(
    path="/disable-maintenance",
    description="set the website to be maintenance",
    summary="set the website to be maintenance",
    response_model=schemas.APIResponse,
)
async def api_disable_maintenance(
    request: Request, 
    data: schemas.MaintenanceSite, 
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY
    
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="maintenance_mode_disable",
        min_threshold=0.75,
    ) 
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    db = rbac_res.admin_database
    username = data.username
    if username != "notify.mirai":
        return ORJSONResponse(
            status_code=400, 
            content={"message": "Incorrect username! Please enter a valid username"},
        )

    maintenance_col = db[C.MIRAI_SYSTEM_COLLECTION]
    # get the current maintenance status
    maintenance = await maintenance_col.find_one(
        filter={"_id": "maintenance_mode"},
        projection={"status": 1},
    )
    if maintenance is not None and not maintenance["status"]:
        return ORJSONResponse(
            status_code=400, 
            content={"message": "Maintenance mode is already disabled"},
        )

    await maintenance_col.update_one(
        {"_id": "maintenance_mode"}, 
        {"$set": {"status": False}},
    )
    logging.info(f"The website is now in live mode, set by {rbac_res.user_doc['username']} , root account")
    return {
        "message": "Maintenance mode disabled",
    }

