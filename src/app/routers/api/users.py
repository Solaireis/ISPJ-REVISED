# import third-party libraries
import bson
import pyotp
import pymongo
import pypdf
from pypdf.errors import (
    PdfReadError,
    WrongPasswordError as PdfWrongPasswordError,
)
from pymongo.results import UpdateResult
from pymongo.collation import Collation, CollationStrength
from fastapi import (
    APIRouter,
    Request,
    Form,
    Query,
    Depends,
    WebSocket,
    WebSocketDisconnect,
    UploadFile,
)
from fastapi.responses import (
    RedirectResponse,
    ORJSONResponse,
)
import PIL
from PIL import Image
import argon2.exceptions as argon2_e
from websockets.exceptions import WebSocketException

# import local Python libraries
import schemas
from utils import constants as C
from utils.classes.hmac import get_hmac_signer
from utils.classes.stripe import StripeSubscription
import utils.functions.useful as useful
from utils.functions import (
    file_uploads,
    database as mongo,
    rbac,
    security as sec,
    chat,
    oauth2,
)
from utils.exceptions import UserBannedException
from utils.functions.data_masking import (
    mask_sensitive_info,
    call_ai_api_and_analyse_text,
)
from utils.functions.security import (
    send_verify_email,
)
from utils.classes import (
    User,
    TwilioAPI,
    VtAnalysis,
)
from gcp import (
    RecaptchaEnterprise,
    GcpAesGcm,
    CloudStorage,
    WebRisk,
    CloudTasks,
    crc32c,
)

# import Python's standard libraries
import time
import html
import logging
import asyncio
import hashlib
import warnings
from datetime import datetime

warnings.simplefilter("error", Image.DecompressionBombWarning)
user_api = APIRouter(
    include_in_schema=True,
    prefix=C.API_PREFIX,
    dependencies=sec.get_rate_limiter_dependency(C.USER_ROUTER),
    tags=["users"],
)
RBAC_DEPENDENCY = Depends(rbac.USER_RBAC, use_cache=False)

@user_api.delete(
    path="/revoke/session/all",
    description="Revoke all sessions except the current one.",
    response_model=schemas.APIResponse,
)
async def revoke_all_sessions(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    session_id = request.session[C.SESSION_COOKIE]
    user_doc = rbac_res.user_doc

    await col.update_one(
        {"_id": user_doc["_id"]},
        {"$pull":
            {"sessions":
                {"session_id": {"$ne": session_id}},
            },
        },
    )
    return {
        "message": "Revoked all sessions except the current one.",
    }

@user_api.delete(
    path="/revoke/session",
    description="Revoke all sessions except the current one.",
    response_model=schemas.APIResponse,
)
async def revoke_session(request: Request, data: schemas.RevokeSession, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_doc = rbac_res.user_doc
    col = db[C.USER_COLLECTION]
    session_id = data.session_id
    if session_id == request.session[C.SESSION_COOKIE]:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Cannot revoke current session.",
            },
        )

    await col.update_one(
        {"_id": user_doc["_id"]},
        {"$pull":
            {"sessions":
                {"session_id": session_id},
            },
        },
    )
    return {
        "message": "Revoked session.",
    }

@user_api.get(
    path="/get/notifications",
    description="Retrieve the list of notifications for the current user.",
)
async def get_notifications(
    request: Request,
    offset: str | None = Query(
        default=None,
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
        description="A notification ID to use as offset for pagination when retrieving the next few notifications.",
    ),
    get_chat: bool | None = Query(
        default=True,
        description="Whether to retrieve chat notifications or not.",
    ),
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_doc = rbac_res.user_doc

    tasks = [
        chat.get_chat_notifications(
            user_id=user_doc["_id"],
            db=db,
        ) if get_chat else useful.filler_task(),
        mongo.get_user_notifications(
            user_id=user_doc["_id"],
            db=db,
            offset=offset,
        ),
    ]
    unread_msg, notifications = await asyncio.gather(*tasks)

    num_of_unread = 0
    if get_chat:
        num_of_unread = len(unread_msg)
        if num_of_unread > 1:
            msg_suffix = msg_suffix = unread_msg[0]["display_name"] + f" and {num_of_unread - 1} other"
        elif num_of_unread == 1:
            msg_suffix = unread_msg[0]["display_name"]

    if notifications:
        unread_notifications = [
            notification for notification in notifications if not notification["read"]
        ]
        if unread_notifications:
            await db[C.NOTIFICATION_COLLECTION].update_many(
                filter={
                    "_id": {
                        "$in": [
                            notification["_id"] for notification in unread_notifications
                        ],
                    },
                },
                update={
                    "$set": {
                        "read": True,
                    },
                },
            )

    data = {
        "notifications": notifications,
    }
    if get_chat:
        data["unread_messages"] = {
            "users": unread_msg,
            "message": f"You have unread messages from {msg_suffix}" if num_of_unread > 0 else "You have no unread messages",
        }
    return useful.format_json_response(data)

@user_api.post(
    path="/edit/profile",
    description="Edit User profile details.",
    response_model=schemas.APIResponse,
)
async def edit_profile(request: Request, data: schemas.EditProfile, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc

    user = await User.init(user_doc, rbac_res.database)
    if data.username is not None and user.display_name != data.username:
        if len(data.username) > C.MAX_USERNAME_LENGTH:
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": f"Username exceeds the {C.MAX_USERNAME_LENGTH} character Limit",
                },
            )
        for char in data.username:
            if char not in C.USERNAME_CHAR_WHITELIST:
                data.username = data.username.replace(char, "_")

        await col.update_one(
            {"_id": user.id},
            {"$set": {
                "display_name": data.username,
            }}
        )

    if data.description is not None and user.bio != data.description:
        if len(data.description) > C.MAX_BIO_LENGTH:
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": f"Bio exceeds the {C.MAX_BIO_LENGTH} character Limit",
                },
            )
        data.description = useful.limit_newlines(
            text=data.description.strip(),
            max_nl=9,
        )
        info = await mask_sensitive_info(request, data.description)
        await col.update_one(
            {"_id": user.id},
            {"$set": {
                "profile.bio": html.escape(info, quote=False),
            }}
        )

    if data.location is not None and user.location != data.location:
        if len(data.location) > C.MAX_LOCATION_LENGTH:
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": f"Location exceeds the {C.MAX_LOCATION_LENGTH} character Limit",
                },
            )
        if await call_ai_api_and_analyse_text(request, data.location):
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": "Location contains sensitive information which is not allowed",
                },
            )
        await col.update_one(
            {"_id": user.id},
            {"$set": {
                "profile.location": html.escape(data.location),
            }}
        )

    if data.website is not None and data.website != user.url:
        data.website = data.website.strip()
        if len(data.website) > C.MAX_WEBSITE_LENGTH:
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": f"URL exceeds the {C.MAX_WEBSITE_LENGTH} character Limit",
                },
            )
        if useful.check_if_str_is_url(data.website):
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": "URL is not valid.",
                },
            )

        url_to_check = data.website.rsplit(sep="#", maxsplit=1)[0]
        col = db[C.FILE_ANALYSIS_COLLECTION]
        analysis_doc = await col.find_one(
            {"identifier": url_to_check},
        )

        # If a result is found : Check what the result states
        if analysis_doc is not None:
            if analysis_doc["malicious"]:
                return ORJSONResponse(
                    status_code=422,
                    content={
                        "message": "URL is not safe.",
                    },
                )

            col = db[C.USER_COLLECTION]
            await col.update_one(
                {"_id": user.id},
                {"$set": {
                    "profile.url": data.website,
                }}
            )
            return ORJSONResponse(
                status_code=200,
                content={
                    "message": "Update Succesful",
                },
            )

        web_risk: WebRisk = request.app.state.obj_map[WebRisk]
        vt_api_key: str = request.app.state.vt_api_key
        async with VtAnalysis(vt_api_key) as vt_client:
            url_checks = await asyncio.gather(*[
                web_risk.search_uri(url_to_check),
                vt_client.check_link(url_to_check, col),
            ])
        if any(url_checks):
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": "URL is not safe.",
                },
            )

        col = db[C.USER_COLLECTION]
        await col.update_one(
            {"_id": user.id},
            {"$set": {
                "profile.url": data.website,
            }}
        )
    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Update Succesful",
        },
    )

@user_api.post(
    path="/settings/authenticate",
    description="Authenticate to settings",
    response_model=schemas.APIResponse,
)
async def settings_authentication(request: Request, data: schemas.EnterPassword, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user_doc = rbac_res.user_doc
    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    password_hash = await aes_gcm.symmetric_decrypt(
        ciphertext=user_doc["password"],
        key_id=C.DATABASE_KEY,
    )
    try:
        C.HASHER.verify(password_hash, data.password)
    except (argon2_e.VerifyMismatchError):
        return ORJSONResponse(
            status_code=401,
            content={
                "message": "The password is incorrect.",
            },
        )
    except:
        return ORJSONResponse(
            status_code=500,
            content={
                "message": C.ERROR_MSG,
            },
        )

    request.session["authenticated"] = {
        "status": True,
        "expiry": time.time() + (30 * 60) # 30 mins 
    }
    return {
        "message": "Password successful.",
    }

@user_api.post(
    path="/settings/password/set",
    description="Change Password",
    response_model=schemas.APIResponse,
)
async def set_password(request: Request, data: schemas.SetPassword, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc
    session_id = request.session[C.SESSION_COOKIE]
    password_hash = None
    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    if user_doc.get("password") is not None and data.old_password is None:
        return ORJSONResponse(
            status_code=401,
            content={
                "message": "You need to enter your old password to change your password.",
            }
        )

    if data.cfm_password != data.new_password:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Your new password and confirm password do not match.",
            }
        )

    if data.old_password:
        password_hash = await aes_gcm.symmetric_decrypt(
            ciphertext=user_doc["password"],
            key_id=C.DATABASE_KEY,
        )
        try:
            C.HASHER.verify(password_hash, data.old_password)
        except (argon2_e.VerifyMismatchError):
            return ORJSONResponse(
                status_code=401,
                content={
                    "message": "The password is incorrect.",
                },
            )
        except:
            return ORJSONResponse(
                status_code=500,
                content={
                    "message": C.ERROR_MSG,
                },
            )

    password_validation_response = await sec.main_password_validations(
        request=request,
        email=user_doc["email"],
        password=data.new_password,
    )
    if password_validation_response is not None:
        return password_validation_response

    new_encrypted_password_hash = await sec.secure_password(data.new_password)
    if isinstance(new_encrypted_password_hash, ORJSONResponse):
        return new_encrypted_password_hash
    await col.update_one(
        {"_id": user_doc["_id"]},
        {
            "$set": {
                "password": new_encrypted_password_hash,
            },
            "$pull": {
                "sessions": {
                    "session_id": {
                        "$ne": session_id,
                    },
                },
            },
        },
    )
    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Your Password has been changed.",
        },
    )

@user_api.post(
    path="/settings/edit-username",
    description="Edit User username.",
    response_model=schemas.APIResponse,
)
async def edit_username(request: Request, data: schemas.EditUsername, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc
    for char in data.username:
        if char not in C.USERNAME_CHAR_WHITELIST:
            data.username = data.username.replace(char, "_")

    matched_doc: dict | None = await col.find_one(
        filter={
            "$or": [
                {"username": data.username},
            ]
        },
        collation=Collation(locale="en", strength=CollationStrength.PRIMARY),
    )
    if matched_doc is None:
        await col.update_one(
            {"_id": user_doc["_id"]},
            {"$set": {
                "username": data.username,
            }}
        )
        return ORJSONResponse(
            status_code=200,
            content={
                "message": "Your username has been changed.",
            },
        )

    return ORJSONResponse(
        status_code=400,
        content={
            "error": "The username is already in use.",
        }
    )

@user_api.post(
    path="/settings/edit-email",
    description="Edit User Email.",
    # response_model=schemas.APIResponse,
)
async def edit_email(request: Request, data: schemas.EditEmail, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    # TODO: Flash Message
    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    session_id = request.session[C.SESSION_COOKIE]
    user_doc = rbac_res.user_doc
    matched_doc: dict | None = await col.find_one(
        filter={
            {"email": data.email},
        },
        collation=Collation(locale="en", strength=CollationStrength.PRIMARY),
    )
    if matched_doc is not None:
        return ORJSONResponse(
            status_code=400,
            content={
                "error": "The Email is already in use.",
            }
        )

    await col.update_one(
        {"_id": user_doc["_id"]},
        {"$set": {
            "email": data.email,
            "verified": False,
        }}
    )

    # Send email verification
    await send_verify_email(
        request=request,
        user_doc=user_doc,
    )

    await col.update_one(
        {"sessions.session_id": session_id},
        {"$set":
            {"sessions": []},
        },
    )
    request.session.clear()
    useful.flash(
        request=request,
        message="Your email has been changed. Please verify your email and login again.",
        category="success",
    )
    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Your email has been changed. Please verify your email and login again.",
        },
    )

@user_api.post(
    path="/edit/profile-picture",
    description="Edit User profile picture.",
)
async def edit_profile_picture(
    request: Request,
    file: UploadFile,
    file_hash: str = Form(
        min_length=64,
        max_length=64,
    ),
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user = rbac_res.user_doc
    user_id = user["_id"]

    image_bytes = await file.read()

    # Check if file hash matches
    uploaded_file_hash = hashlib.sha3_256(image_bytes).hexdigest()
    if uploaded_file_hash != file_hash:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "File hash does not match.",
            },
        )

    if len(image_bytes) > C.MAX_IMAGE_PDF_SIZE:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": f"File too large, maximum size is {C.MAX_IMAGE_PDF_SIZE} bytes.",
            },
        )

    filename = sec.clean_filename(file.filename)
    extension = filename.split(".")[-1]
    blob_name = f"profile-pics/{user_id}/{user_id}.{extension}"
    compressed_blob_name = None
    bucket = C.PUBLIC_BUCKET

    if not file.content_type.startswith("image"):
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Invalid image file.",
            },
        )
    if file.content_type not in C.ACCEPTED_IMAGE_MIMETYPES:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": f"Only {', '.join(file_type.split(sep='/', maxsplit=1)[1] for file_type in C.ACCEPTED_IMAGE_MIMETYPES)} are allowed!",
            },
        )

    cloud_storage: CloudStorage = request.app.state.obj_map[CloudStorage]
    # since images with large resolutions can
    # lag the client's browser, we need to check the resolution using PIL
    try:
        pil_image_obj = Image.open(file.file)
    except (PIL.UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Image resolution is too large.",
            },
        )
    else:
        is_animated_image = hasattr(pil_image_obj, "is_animated") and pil_image_obj.is_animated
        try:
            tasks = await asyncio.gather(*[
                file_uploads.compress_and_save_image(
                    request=request,
                    image=pil_image_obj,
                    bucket=bucket,
                    blob_name=blob_name,
                    max_height=128,
                    max_width=128,
                    fixed_size=True,
                    is_animated=is_animated_image,
                    cache_controls=C.PROFILE_IMAGES_CACHE_CONTROLS,
                ),
                cloud_storage.upload_blob_from_memory(
                    bucket=bucket,
                    destination_blob_name=blob_name,
                    data=image_bytes,
                    mimetype=file.content_type,
                ),
            ])
        except:
            return ORJSONResponse(
                status_code=500,
                content={
                    "message": "An error occurred while processing the image.",
                },
            )

    has_error = False
    compressed_blob_name: str = tasks[0]
    try:
        analysis_results = await file_uploads.main_analysis_process(
            request=request,
            db=db,
            chunk_hash=uploaded_file_hash,
            chunk_bytes=image_bytes,
            is_pdf=False,
            mimetype=file.content_type,
            bucket_name=bucket,
            blob_name=blob_name,
            is_image=True,
            is_animated_image=is_animated_image,
        )
    except:
        has_error = True

    await cloud_storage.delete_blob(
        bucket=bucket,
        blob_name=blob_name,
    )
    if has_error:
        return ORJSONResponse(
            status_code=500,
            content={
                "message": "An error occurred while processing the image.",
            },
        )

    if isinstance(analysis_results, ORJSONResponse):
        return analysis_results

    safe_search_annotation, treat_image_as_file = analysis_results
    if treat_image_as_file:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Image is invalid.",
            },
        )
    if not file_uploads.analyse_safe_search_annotations(safe_search_annotation):
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Image contains inappropriate content.",
            },
        )

    image_url = cloud_storage.generate_public_bucket_url(
        compressed_blob_name,
    )
    await col.update_one(
        {"_id": user_id},
        {"$set": {
            "profile.image": {
                "url": image_url,
                "blob_name": compressed_blob_name,
                "bucket": bucket,
            },
        }}
    )

    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Update Successful",
            "image_url": image_url,
        },
    )

@user_api.post(
    path="/reset/profile-picture",
    description="Reset User profile picture.",
    response_model=schemas.APIResponse,
)
async def reset_profile_picture(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user = rbac_res.user_doc
    user_id = user["_id"]

    profile_image_info = user["profile"]["image"]
    if "blob_name" not in profile_image_info or "bucket" not in profile_image_info:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Your profile picture is already the default one.",
            },
        )

    cloud_storage: CloudStorage = request.app.state.obj_map[CloudStorage]
    await cloud_storage.delete_blob(
        blob_name=profile_image_info["blob_name"],
        bucket=profile_image_info["bucket"],
    )

    default_img_url = f"https://api.dicebear.com/5.x/initials/svg?seed={user['username']}"
    await col.update_one(
        {"_id": user_id},
        {"$set": {
            "profile.image": {
                "url": default_img_url,
            },
        }}
    )

    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Update Successful",
            "image_url": default_img_url,
        },
    )

@user_api.post(
    path="/edit/banner-picture",
    description="Edit User profile banner picture.",
)
async def edit_banner_picture(
    request: Request,
    file: UploadFile,
    file_hash: str = Form(
        min_length=64,
        max_length=64,
    ),
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user = rbac_res.user_doc
    if not rbac_res.user_doc["mirai_plus"]:
        return ORJSONResponse(
            status_code=403,
            content={
                "message": "You need to be a Mirai Plus member to use this feature.",
            },
        )

    user_id = user["_id"]
    image_bytes = await file.read()

    # Check if file hash matches
    uploaded_file_hash = hashlib.sha3_256(image_bytes).hexdigest()
    if uploaded_file_hash != file_hash:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "File hash does not match.",
            },
        )

    if len(image_bytes) > C.MAX_IMAGE_PDF_SIZE:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": f"File too large, maximum size is {C.MAX_IMAGE_PDF_SIZE} bytes.",
            },
        )

    filename = sec.clean_filename(file.filename)
    extension = filename.split(".")[-1]
    blob_name = f"banner-pics/{user_id}/{user_id}.{extension}"
    compressed_blob_name = None
    bucket = C.PUBLIC_BUCKET
    if not file.content_type.startswith("image"):
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Invalid image file.",
            },
        )
    if file.content_type not in C.ACCEPTED_IMAGE_MIMETYPES:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": f"Only {', '.join(file_type.split(sep='/', maxsplit=1)[1] for file_type in C.ACCEPTED_IMAGE_MIMETYPES)} are allowed!",
            },
        )

    cloud_storage: CloudStorage = request.app.state.obj_map[CloudStorage]
    # since images with large resolutions can
    # lag the client's browser, we need to check the resolution using PIL
    try:
        pil_image_obj = Image.open(file.file)
    except (PIL.UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Image resolution is too large.",
            },
        )
    else:
        is_animated_image = hasattr(pil_image_obj, "is_animated") and pil_image_obj.is_animated
        try:
            tasks = await asyncio.gather(*[
                file_uploads.compress_and_save_image(
                    request=request,
                    image=pil_image_obj,
                    bucket=bucket,
                    blob_name=blob_name,
                    max_width=1500,
                    max_height=500,
                    fixed_size=True,
                    is_animated=is_animated_image,
                    cache_controls=C.PROFILE_IMAGES_CACHE_CONTROLS,
                ),
                cloud_storage.upload_blob_from_memory(
                    bucket=bucket,
                    destination_blob_name=blob_name,
                    data=image_bytes,
                    mimetype=file.content_type,
                ),
            ])
        except:
            return ORJSONResponse(
                status_code=500,
                content={
                    "message": "An error occurred while processing the image.",
                },
            )

    has_error = False
    compressed_blob_name: str = tasks[0]
    try:
        analysis_results = await file_uploads.main_analysis_process(
            request=request,
            db=db,
            chunk_hash=uploaded_file_hash,
            chunk_bytes=image_bytes,
            is_pdf=False,
            mimetype=file.content_type,
            bucket_name=bucket,
            blob_name=blob_name,
            is_image=True,
            is_animated_image=is_animated_image,
        )
    except:
        has_error = True

    await cloud_storage.delete_blob(
        bucket=bucket,
        blob_name=blob_name,
    )
    if has_error:
        return ORJSONResponse(
            status_code=500,
            content={
                "message": "An error occurred while processing the image.",
            },
        )

    if isinstance(analysis_results, ORJSONResponse):
        return analysis_results

    safe_search_annotation, treat_image_as_file = analysis_results
    if treat_image_as_file:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Image is invalid.",
            },
        )
    if not file_uploads.analyse_safe_search_annotations(safe_search_annotation):
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Image contains inappropriate content.",
            },
        )

    image_url = cloud_storage.generate_public_bucket_url(
        compressed_blob_name,
    )
    await col.update_one(
        {"_id": user_id},
        {"$set": {
            "profile.banner": {
                "url": image_url,
                "blob_name": compressed_blob_name,
                "bucket": bucket,
            },
        }}
    )

    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Update Successful",
            "image_url": image_url,
        },
    )

@user_api.post(
    path="/reset/banner-picture",
    description="Reset User profile banner picture.",
)
async def reset_banner_picture(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user = rbac_res.user_doc
    user_id = user["_id"]

    profile_banner_info = user["profile"]["banner"]
    if "blob_name" not in profile_banner_info or "bucket" not in profile_banner_info:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Your profile banner is already the default one.",
            },
        )

    cloud_storage: CloudStorage = request.app.state.obj_map[CloudStorage]
    await cloud_storage.delete_blob(
        bucket=profile_banner_info["bucket"],
        blob_name=profile_banner_info["blob_name"],
    )
    await col.update_one(
        {"_id": user_id},
        {"$set": {
            "profile.banner": {
                "url": C.DEFAULT_BANNER,
            },
        }}
    )
    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Update Successful",
            "image_url": C.DEFAULT_BANNER,
        },
    )

@user_api.post(
    path="/post/comments",
    description="Upload a comment to our server.",
    response_model=schemas.APIResponse,
)
async def upload_post_comment(
    request: Request,
    data: schemas.PostText,
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user = rbac_res.user_doc
    max_char = C.MAX_POST_LENGTH[user["mirai_plus"]]
    if len(data.text) > max_char:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": f"Comment must be less than {max_char} characters",
            },
        )

    integrity_check_response = file_uploads.check_text_integrity(
        data=data.text,
        client_cr32c=data.crc32c_checksum,
        client_md5=data.md5_checksum,
    )
    if integrity_check_response is not None:
        return integrity_check_response

    author_id = user["_id"]
    db = rbac_res.database
    post_id = bson.ObjectId(data.post_id)
    post_col = db[C.POST_COLLECTION]
    if await post_col.find_one({"_id": post_id}) is None:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Post does not exist.",
            },
        )

    chat_col = db[C.COMMENTS_COLLECTION]
    info = await mask_sensitive_info(request, data.text)
    await chat_col.insert_one({
        "post_id": post_id,
        "description": info,
        "user_id": author_id,
        "timestamp": datetime.utcnow(),
    })

    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Post uploaded successfully.",
        },
    )

@user_api.post(
    path="/post",
    description="Upload a text only post to our server.",
    response_model=schemas.APIResponse,
)
async def upload_post_text(
    request: Request,
    data: schemas.PostText,
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user = rbac_res.user_doc
    max_char = C.MAX_POST_LENGTH[user["mirai_plus"]]
    if len(data.text) > max_char:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": f"Post text content must be less than {max_char} characters",
            },
        )

    integrity_check_response = file_uploads.check_text_integrity(
        data=data.text,
        client_cr32c=data.crc32c_checksum,
        client_md5=data.md5_checksum,
    )
    if integrity_check_response is not None:
        return integrity_check_response

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    author_id = user["_id"]

    col = db[C.POST_COLLECTION]
    info = await mask_sensitive_info(request, data.text)

    await col.insert_one({
        "description": info,
        "user_id": author_id,
        "timestamp": datetime.utcnow(),
    })

    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Post uploaded successfully.",
        },
    )

@user_api.post(
    path="/delete/post",
    description="Delete a post from our server.",
    response_model=schemas.APIResponse,
)
async def delete_post(
    request: Request,
    data: schemas.PostLikes,
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.POST_COLLECTION]
    post = await col.find_one({"_id": bson.ObjectId(data.post_id)})
    if post is None:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Post does not exist.",
            },
        )
    
    if post["user_id"] != rbac_res.user_doc["_id"]:
        return ORJSONResponse(
            status_code=403,
            content={
                "message": "You are not allowed to delete this post.",
            },
        )

    await col.delete_one({"_id": bson.ObjectId(data.post_id)})
    await db[C.COMMENTS_COLLECTION].delete_many({"post_id": bson.ObjectId(data.post_id)})

    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Post deleted successfully.",
        },
    )

@user_api.post(
    path="/delete/comment",
    description="Delete a comment from our server.",
    response_model=schemas.APIResponse,
)
async def delete_comment(
    request: Request,
    data: schemas.PostLikes,
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.COMMENTS_COLLECTION]
    post = await col.find_one({"_id": bson.ObjectId(data.post_id)})
    if post is None:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Comments does not exist.",
            },
        )
    
    if post["user_id"] != rbac_res.user_doc["_id"]:
        return ORJSONResponse(
            status_code=403,
            content={
                "message": "You are not allowed to delete this Comments.",
            },
        )

    await col.delete_one({"_id": bson.ObjectId(data.post_id)})

    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Comments deleted successfully.",
        },
    )


@user_api.post(
    path="/upload/post",
    description="Upload a post to our server.",
    response_model=schemas.APIResponse,
)
async def upload_post(
    request: Request,
    chunk: UploadFile,
    filename: str = Form(
        min_length=3,
    ),
    mimetype: str | None = Form(
        min_length=1,
        default="application/octet-stream",
    ),
    chunk_index: int = Form(),
    upload_token: str = Form(
        min_length=1,
    ),
    author: str = Form(
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
    ),
    chunk_hash: str = Form(
        min_length=64,
        max_length=64,
    ),
    file_md5_checksum: str = Form(
        min_length=24,
        max_length=24,
        description="Base64 encoded MD5 checksum of the whole file.",
    ),
    file_crc32c_checksum: str = Form(
        min_length=8,
        max_length=8,
        description="Base64 encoded CRC32C checksum of the whole file.",
    ),
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    content_range = file_uploads.validate_content_range(request)
    if isinstance(content_range, ORJSONResponse):
        return content_range

    filename = sec.clean_filename(filename)
    blob_name = f"post/{author}/{bson.ObjectId()}/{filename}"
    db = rbac_res.database
    cloud_storage: CloudStorage = request.app.state.obj_map[CloudStorage]
    upload_doc, upload_id, whole_upload_doc = await cloud_storage.append_file_to_document(
        request=request,
        db=db,
        user_id=bson.ObjectId(author),
        filename=filename,
        destination_blob_name=blob_name,
        mimetype=mimetype,
        upload_token=upload_token,
        file_md5_checksum=file_md5_checksum,
        file_crc32c_checksum=file_crc32c_checksum,
    )
    if isinstance(upload_doc, ORJSONResponse):
        return upload_doc

    blob_name = upload_doc["blob_name"] # get the blob name from the upload document
                                        # because it might have more than one chunk,
                                        # hence, the need to overwrite the old blob_name value
    author_doc = rbac_res.user_doc
    author_id = author_doc["_id"]
    if str(author_id) != author:
        return ORJSONResponse(
            status_code=403,
            content={
                "message": "You do not have permission to upload this.",
            },
        )

    if author_doc is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "User not found.",
            },
        )

    is_image = mimetype.startswith("image/")
    is_video = mimetype.startswith("video/")
    if not is_image and not is_video:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Only images and videos are allowed.",
            },
        )

    if is_image and mimetype not in C.ACCEPTED_IMAGE_MIMETYPES:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": f"Only {', '.join(file_type.split(sep='/', maxsplit=1)[1] for file_type in C.ACCEPTED_IMAGE_MIMETYPES)} are allowed!",
            },
        )

    file_size = file_uploads.validate_file_size(
        content_range=content_range,
        user_doc=author_doc,
        is_image_or_pdf=is_image,
        is_video=is_video,
    )
    if isinstance(file_size, ORJSONResponse):
        return file_size

    chunk_bytes = await chunk.read()
    if len(chunk_bytes) > C.MAX_CHUNK_SIZE:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": f"File chunk too large, maximum size is {C.MAX_CHUNK_SIZE} bytes.",
            },
        )

    data_integrity_response = file_uploads.check_data_integrity(
        data=chunk_bytes,
        client_hash=chunk_hash,
    )
    if data_integrity_response is not None:
        return data_integrity_response

    # if the file is an image, it must
    # be uploaded in one chunk, so we can check the resolution
    cloud_storage: CloudStorage = request.app.state.obj_map[CloudStorage]
    bucket_name = whole_upload_doc["bucket_name"]
    is_animated_image = False
    compressed_blob_name = None
    if is_image:
        # since images with large resolutions can
        # lag the client's browser, we need to check the resolution using PIL
        try:
            pil_image_obj = Image.open(chunk.file)
        except (PIL.UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning):
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": "Image resolution is too large",
                },
            )
        else:
            is_animated_image = hasattr(pil_image_obj, "is_animated") and pil_image_obj.is_animated
            try:
                compressed_blob_name = await file_uploads.compress_and_save_image(
                    request=request,
                    image=pil_image_obj,
                    bucket=bucket_name,
                    blob_name=blob_name,
                    is_animated=is_animated_image,
                )
            except Exception:
                return ORJSONResponse(
                    status_code=422,
                    content={
                        "message": "Something went wrong while processing the image.",
                    },
                )

    upload_url = upload_doc["upload_url"]
    response = await cloud_storage.resumable_upload_blob_from_memory(
        data=chunk_bytes,
        upload_url=upload_url,
        content_range=content_range,
    )
    if response != 200:
        return {
            "message": f"File chunk #{chunk_index} for {filename} has been uploaded successfully.",
        }

    finalise_response = await file_uploads.finalise_file_upload(
        request=request,
        db=db,
        upload_id=upload_id,
        chunk_hash=chunk_hash,
        chunk_bytes=chunk_bytes,
        mimetype=mimetype,
        filename=filename,
        file_size=file_size,
        blob_name=blob_name,
        bucket_name=bucket_name,
        compressed_blob_name=compressed_blob_name,
        is_image=is_image,
        is_animated_image=is_animated_image,
        treat_image_as_file=False,
        is_pdf=False,
        only_one_video=True,
    )
    if isinstance(finalise_response, ORJSONResponse):
        return finalise_response

    latest_upload_doc = finalise_response
    col = db[C.POST_COLLECTION]
    existing_id = await col.find_one({
        "_id": bson.ObjectId(upload_id),
    })
    if existing_id is not None:
        return {
            "message": "Post has been successfully published.",
        }

    data = {
        "_id": bson.ObjectId(upload_id),
        "description": latest_upload_doc["message"],
        "user_id": author_id,
        "timestamp": datetime.utcnow(),
    }
    if is_image:
        data["images"] = latest_upload_doc["uploaded_files"]
    else:
        data["video"] = latest_upload_doc["uploaded_files"]

    await col.insert_one(data)
    return {
        "message": "Post uploaded successfully.",
    }

@user_api.post(
    path="/posts/likes/add",
    description="Add a like to a post.",
)
async def add_post_like(
    request: Request,
    data : schemas.PostLikes,
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    current_user = rbac_res.user_doc
    if current_user is None:
        return ORJSONResponse(
        status_code=404,
        content={
            "message": "This user is not logged in",
            },
        )
    db = rbac_res.database

    post_id = bson.ObjectId(data.post_id)
    post_col = db[C.POST_COLLECTION]
    post_doc = await post_col.find_one({
        "_id": post_id,
    })
    if post_doc is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "Post does not exist.",
            },
        )

    if post_doc.get("likes") is None:
        tasks = [
            post_col.update_one(
                {"_id": post_id},
                {"$set": {
                    "likes": [current_user["_id"]],
                }},
            ),
        ]
    else:
        tasks = [
            post_col.update_one(
                {"_id": post_id},
                {"$addToSet": {
                    "likes": current_user["_id"],
                }},
            ),
        ]

    tasks.append(
        mongo.write_notification(
            db=db,
            user_id=post_doc["user_id"],
            notif_type=C.LIKE_POST_TYPE,
            partial_msg=C.LIKE_POST_MSG,
            other_user=current_user["_id"],
            post_id=post_id,
        ),
    )
    await asyncio.gather(*tasks)
    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Like successfully added.",
        },
    )

@user_api.post(
    path="/posts/likes/remove",
    description="Remove a like to a post.",
)
async def remove_post_like(
    request: Request,
    data : schemas.PostLikes,
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    if rbac_res.user_doc is None:
        return ORJSONResponse(
        status_code=404,
        content={
            "message": "This user is not logged in",
            },
        )

    current_user = User(rbac_res.user_doc)
    db = rbac_res.database

    post_id = bson.ObjectId(data.post_id)
    post_col = db[C.POST_COLLECTION]
    post_doc = await post_col.find_one({
        "_id": post_id,
    })
    if post_doc is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "Post does not exist.",
            },
        )

    if post_doc.get("likes") is None:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "This post has no likes.",
            },
        )

    await post_col.update_one(
        {"_id": post_id},
        {
        "$pull": {
            "likes": current_user.id,
            }
        })

    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Like successfully removed.",
        },
    )

@user_api.post(
    path="/comments/likes/add",
    description="Add a like to a post.",
)
async def add_comments_like(
    request: Request,
    data : schemas.PostLikes,
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    current_user = rbac_res.user_doc
    if current_user is None:
        return ORJSONResponse(
        status_code=404,
        content={
            "message": "This user is not logged in",
            },
        )
    db = rbac_res.database

    post_id = bson.ObjectId(data.post_id)
    post_col = db[C.COMMENTS_COLLECTION]
    post_doc = await post_col.find_one({
        "_id": post_id,
    })
    if post_doc is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "Comment does not exist.",
            },
        )

    if post_doc.get("likes") is None:
        tasks = [
            post_col.update_one(
                {"_id": post_id},
                {"$set": {
                    "likes": [current_user["_id"]],
                }},
            ),
        ]
    else:
        tasks = [
            post_col.update_one(
                {"_id": post_id},
                {"$addToSet": {
                    "likes": current_user["_id"],
                }},
            ),
        ]

    # tasks.append(
    #     mongo.write_notification(
    #         db=db,
    #         user_id=post_doc["user_id"],
    #         notif_type=C.LIKE_COMMENT_TYPE,
    #         partial_msg=C.LIKE_COMMENT_MSG,
    #         other_user=current_user["_id"],
    #         post_id=post_id,
    #     ),
    # )
    await asyncio.gather(*tasks)
    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Like successfully added.",
        },
    )

@user_api.post(
    path="/comments/likes/remove",
    description="Remove a like to a post.",
)
async def remove_comment_like(
    request: Request,
    data : schemas.PostLikes,
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    if rbac_res.user_doc is None:
        return ORJSONResponse(
        status_code=401,
        content={
            "message": "This user is not logged in",
            },
        )

    current_user = User(rbac_res.user_doc)
    db = rbac_res.database

    post_id = bson.ObjectId(data.post_id)
    post_col = db[C.COMMENTS_COLLECTION]
    post_doc = await post_col.find_one({
        "_id": post_id,
    })
    if post_doc is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "Comment does not exist.",
            },
        )

    if post_doc.get("likes") is None:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "This comment has no likes.",
            },
        )

    await post_col.update_one(
        {"_id": post_id},
        {
        "$pull": {
            "likes": current_user.id,
            }
        })

    return ORJSONResponse(
        status_code=200,
        content={
            "message": "Like successfully removed.",
        },
    )

@user_api.patch(
    path="/settings/update/content-moderation",
    description="Change the user's content moderation settings.",
)
async def update_content_moderation_settings(request: Request, data: schemas.ContentModeration, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user = rbac_res.user_doc
    author_id = user["_id"]
    await col.update_one(
        {"_id": author_id},
        {"$set": {
            "content_moderation.sexual_images": data.sexual_images,
            "content_moderation.violent_images": data.violent_images,
            "content_moderation.meme_images": data.meme_images,
        }},
    )
    return {
        "message":
            f"""Content moderation settings updated successfully.
Sexual content: {'Blurred' if data.sexual_images else 'Allowed'}
Violent images: {'Blurred' if data.violent_images else 'Allowed'}
Meme images: {'Blurred' if data.meme_images else 'Allowed'}""",
    }

@user_api.post(
    path="/file/upload/get/upload-id",
    description="Get an upload ID for uploading files to Google Cloud Storage.",
    response_model=schemas.UploadIdResponse,
)
async def get_upload_id(request: Request, data: schemas.GetUploadId, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc
    author_id = user_doc["_id"]
    if str(author_id) != data.author:
        return ORJSONResponse(
            content={
                "message": "You are not the sender of this message.",
            },
            status_code=403,
        )

    max_char = 0
    extra_data = None
    encrypt_msg = False
    bucket_name = C.PUBLIC_BUCKET
    if data.purpose == schemas.UploadPurpose.CHAT:
        encrypt_msg = True
        bucket_name = C.PRIVATE_BUCKET
        max_char = C.MAX_CHAT_MSG_LENGTH[user_doc["mirai_plus"]]
        if data.number_of_files > 3:
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": "You can only send up to 3 files at a time for chat file messages.",
                },
            )

        receiver_id = data.receiver
        if receiver_id is None:
            return ORJSONResponse(
                content={
                    "message": f"Receiver ID is required for {data.purpose.value}.",
                },
                status_code=422,
            )

        receiver_id = bson.ObjectId(receiver_id)
        extra_data = {
            "receiver": receiver_id,
        }
        receiver_doc = await col.find_one({"_id": receiver_id})
        if receiver_doc is None:
            return ORJSONResponse(
                content={
                    "message": "Receiver does not exist.",
                },
                status_code=404,
            )

        # check if sender is authorised to chat with receiver
        allowed_permissions = useful.evaluate_permissions(
            target_id=receiver_id,
            target_privacy=receiver_doc["privacy"],
            user_following=user_doc["social"]["following"]
        )
        if not allowed_permissions.send_direct_messages:
            return ORJSONResponse(
                content={
                    "message": "Message unintended for receiver.",
                },
                status_code=403,
            )

        blocked = await col.find_one({
            "$or": [
                {"_id": author_id, "blocked_users": receiver_id},
                {"_id": receiver_id, "blocked_users": author_id},
            ],
        })
        if blocked is not None:
            return ORJSONResponse(
                content={
                    "message": f"You are blocked by {receiver_doc['display_name']}." \
                                if blocked["_id"] == author_id \
                                else f"You have blocked {receiver_doc['display_name']}.",
                },
                status_code=403,
            )

    elif data.purpose == schemas.UploadPurpose.POST:
        bucket_name = C.PRIVATE_BUCKET
        if data.number_of_files > 4:
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": "You can only upload up to 4 images at a time for posts.",
                },
            )
        max_char = C.MAX_POST_LENGTH[user_doc["mirai_plus"]]

    if data.text and len(data.text) > max_char:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": f"Text content must be less than {max_char} characters",
            },
        )

    integrity_check_response = file_uploads.check_text_integrity(
        data=data.text,
        client_cr32c=data.crc32c_checksum,
        client_md5=data.md5_checksum,
    )
    if integrity_check_response is not None:
        return integrity_check_response

    text = None
    if data.text is not None:
        stripped_text = data.text.strip()
        if stripped_text:
            # scan the message for any confidential information and mask it if found
            text = await mask_sensitive_info(request, stripped_text)

    cloud_storage: CloudStorage = request.app.state.obj_map[CloudStorage]
    public_upload_id = await cloud_storage.generate_upload_token(
        request=request,
        db=db,
        user_id=author_id,
        bucket_name=bucket_name,
        number_of_files=data.number_of_files,
        purpose=data.purpose.value,
        text_msg=text,
        encrypt_msg=encrypt_msg,
        extra_data=extra_data,
    )
    if isinstance(public_upload_id, ORJSONResponse):
        return public_upload_id

    return {
        "upload_token": public_upload_id,
        "message": "Upload ID generated successfully.",
    }

@user_api.post(
    path="/chat/upload/file",
    description="Upload any types of files like .mp3, .png, etc. to a chat session.",
    response_model=schemas.APIResponse,
)
async def upload_chat_file(
    request: Request,
    chunk: UploadFile,
    filename: str = Form(
        min_length=3,
    ),
    mimetype: str | None = Form(
        min_length=1,
        default="application/octet-stream",
    ),
    chunk_index: int = Form(),
    upload_token: str = Form(
        min_length=1,
    ),
    sender: str = Form(
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
    ),
    receiver: str = Form(
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
    ),
    chunk_hash: str = Form(
        min_length=64,
        max_length=64,
    ),
    file_md5_checksum: str = Form(
        min_length=24,
        max_length=24,
        description="Base64 encoded MD5 checksum of the whole file.",
    ),
    file_crc32c_checksum: str = Form(
        min_length=8,
        max_length=8,
        description="Base64 encoded CRC32C checksum of the whole file.",
    ),
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    content_range = file_uploads.validate_content_range(request)
    if isinstance(content_range, ORJSONResponse):
        return content_range

    receiver = bson.ObjectId(receiver)
    filename = sec.clean_filename(filename)
    blob_name = f"chat/{sender}/{bson.ObjectId()}/{filename}"
    db = rbac_res.database
    cloud_storage: CloudStorage = request.app.state.obj_map[CloudStorage]
    upload_doc, upload_id, whole_upload_doc = await cloud_storage.append_file_to_document(
        request=request,
        db=db,
        user_id=bson.ObjectId(sender),
        filename=filename,
        destination_blob_name=blob_name,
        mimetype=mimetype,
        upload_token=upload_token,
        file_md5_checksum=file_md5_checksum,
        file_crc32c_checksum=file_crc32c_checksum,
    )
    if isinstance(upload_doc, ORJSONResponse):
        return upload_doc

    blob_name = upload_doc["blob_name"] # get the blob name from the upload document
                                        # because it might have more than one chunk,
                                        # hence, the need to overwrite the old blob_name value
    user_col = db[C.USER_COLLECTION]
    sender_doc = rbac_res.user_doc
    sender_id = sender_doc["_id"]
    if str(sender_id) != sender:
        return ORJSONResponse(
            status_code=403,
            content={
                "message": "You do not have permission to upload to this chat.",
            },
        )
    receiver_doc = await user_col.find_one(
        {"_id": receiver},
    )
    if sender_doc is None or receiver_doc is None:
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "User not found.",
            },
        )

    is_pdf = (mimetype == "application/pdf")
    is_image = mimetype.startswith("image/")
    is_video = mimetype.startswith("video/")
    file_size = file_uploads.validate_file_size(
        content_range=content_range,
        user_doc=sender_doc,
        is_image_or_pdf=(is_image or is_pdf),
        is_video=is_video,
    )
    if isinstance(file_size, ORJSONResponse):
        return file_size

    # Read the chunk and check if it's too large
    chunk_bytes = await chunk.read()
    if len(chunk_bytes) > C.MAX_CHUNK_SIZE:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": f"File chunk too large, maximum size is {C.MAX_CHUNK_SIZE} bytes.",
            },
        )

    # Check if file hash matches
    data_integrity_response = file_uploads.check_data_integrity(
        data=chunk_bytes,
        client_hash=chunk_hash,
    )
    if data_integrity_response is not None:
        return data_integrity_response

    # if the image is a PDF, it must
    # be uploaded in one chunk, so we can check if it's encrypted and < 150 pages
    if is_pdf:
        # since PDFs with large page counts can
        # lag the client's browser, we need to check the page count using PyPDF2
        try:
            pdf = pypdf.PdfReader(chunk.file)
            if pdf.is_encrypted:
                raise PdfWrongPasswordError()

            if len(pdf.pages) > 50:
                return ORJSONResponse(
                    status_code=422,
                    content={
                        "message": "PDF has too many pages. You can only upload a PDF with a maximum number of 50 pages.",
                    },
                )
        except (PdfWrongPasswordError):
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": "PDF is encrypted which is not allowed.",
                },
            )
        except (PdfReadError):
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": "Could not read PDF due to some unknown issues.",
                },
            )

    # if the file is an image, it must
    # be uploaded in one chunk, so we can check the resolution
    is_animated_image = False
    compressed_blob_name = None
    bucket_name = whole_upload_doc["bucket_name"]
    treat_image_as_file = (mimetype not in C.ACCEPTED_IMAGE_MIMETYPES)
    if is_image and not treat_image_as_file:
        # since images with large resolutions can
        # lag the client's browser, we need to check the resolution using PIL
        try:
            pil_image_obj = Image.open(chunk.file)
        except (PIL.UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning):
            treat_image_as_file = True
        else:
            is_animated_image = hasattr(pil_image_obj, "is_animated") and pil_image_obj.is_animated
            try:
                compressed_blob_name = await file_uploads.compress_and_save_image(
                    request=request,
                    image=pil_image_obj,
                    bucket=bucket_name,
                    blob_name=blob_name,
                    is_animated=is_animated_image,
                    cache_controls=C.CHAT_CACHE_CONTROLS,
                )
            except Exception:
                return ORJSONResponse(
                    status_code=400,
                    content={
                        "message": "Something went wrong while processing the image.",
                    },
                )

    upload_url = upload_doc["upload_url"]
    response = await cloud_storage.resumable_upload_blob_from_memory(
        data=chunk_bytes,
        upload_url=upload_url,
        content_range=content_range,
    )
    if response != 200:
        return {
            "message": f"File chunk #{chunk_index} for {filename} has been uploaded successfully.",
        }

    finalise_response = await file_uploads.finalise_file_upload(
        request=request,
        db=db,
        upload_id=upload_id,
        chunk_hash=chunk_hash,
        chunk_bytes=chunk_bytes,
        mimetype=mimetype,
        filename=filename,
        file_size=file_size,
        blob_name=blob_name,
        bucket_name=bucket_name,
        compressed_blob_name=compressed_blob_name,
        is_image=is_image,
        is_animated_image=is_animated_image,
        treat_image_as_file=treat_image_as_file,
        is_pdf=is_pdf,
    )
    if isinstance(finalise_response, ORJSONResponse):
        return finalise_response

    latest_upload_doc = finalise_response
    current_time = time.time()
    chat_col = db[C.CHAT_COLLECTION]
    min_expiry_time = sec.get_min_message_timer(
        sender_user_doc=sender_doc,
        receiver_user_doc=receiver_doc,
    )
    msg_data = {
        "sender": sender_id,
        "type": "file",
        "receiver": receiver,
        "timestamp": current_time,
        "message": latest_upload_doc["message"],
        "expiry": None if min_expiry_time == 0 else current_time + min_expiry_time,
        "read": False,
        "files": latest_upload_doc["uploaded_files"],
    }
    await chat_col.insert_one(msg_data)
    return {
        "message": "All files uploaded successfully.",
    }

@user_api.get(
    path="/chat/forgot-password/token/{token}",
    description="Verify a chat password reset token which would disable the user's chat password.",
    response_class=RedirectResponse,
)
async def forgot_chat_password_token(request: Request, token: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    err_msg = "Invalid or expired chat password reset token."
    err_category = "Failed to reset chat password."

    token = await sec.decrypt_token(request, token)
    signer = get_hmac_signer(C.FORGOT_CHAT_PASS_EXPIRY)
    token = signer.get(token)
    if token is None or token.get("_id") is None or token.get("user_id") is None or \
        not bson.ObjectId.is_valid(token["_id"]) or not bson.ObjectId.is_valid(token["user_id"]):
            useful.flash(
                request=request,
                message=err_msg,
                category=err_category,
            )
            return RedirectResponse(url="/")

    db = rbac_res.database
    user_col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc
    if str(user_doc["_id"]) != token["user_id"]:
        useful.flash(
            request=request,
            message=err_msg,
            category=err_category,
        )
        return RedirectResponse(url="/")

    token_col = db[C.ONE_TIME_TOKEN_COLLECTION]
    token_id = bson.ObjectId(token["_id"])
    matched_token = await token_col.find_one(
        filter={
            "_id": token_id,
        },
        projection={
            "_id": 1,
            "purpose": 1,
        },
    )
    if matched_token is None or matched_token["purpose"] != "forgot_chat_password":
        useful.flash(
            request=request,
            message=err_msg,
            category=err_category,
        )
        return RedirectResponse(url="/")

    if user_doc["chat"]["password_protection"] is None:
        useful.flash(
            request=request,
            message="You do not have a chat password to reset or have already reset it.",
            category=err_category,
        )
        return RedirectResponse(url="/")

    await asyncio.gather(*[
        token_col.delete_one({
            "_id": token_id,
        }),
        user_col.update_one({
            "_id": user_doc["_id"],
        }, {
            "$set": {
                "chat.password_protection": None,
            },
        }),
    ])
    useful.flash(
        request=request,
        message="Your chat password has been reset successfully, you can now access your chats.",
        category="Chat password reset successfully.",
    )
    return RedirectResponse(url="/")

@user_api.post(
    path="/chat/forgot-password",
    description="Send a chat password reset email to the user.",
)
async def forgot_chat_password(request: Request, data: schemas.RecaptchaToken, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="forgot_chat_password",
        min_threshold=0.75,
    )
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    db = rbac_res.database
    user_doc = rbac_res.user_doc

    signer = get_hmac_signer(C.FORGOT_CHAT_PASS_EXPIRY)
    token_id = bson.ObjectId()
    signed_token = signer.sign({
        "_id": str(token_id),
        "user_id": str(user_doc["_id"]),
    })
    encrypted_token, _ = await asyncio.gather(*[
        sec.encrypt_token(request, signed_token),
        db[C.ONE_TIME_TOKEN_COLLECTION].insert_one({
            "_id": token_id,
            "created_at": datetime.utcnow(),
            "purpose": "forgot_chat_password",
        }),
    ])
    msg = f"""
You are receiving this email due to a request to reset your chat password on your Mirai account.<br>
If you did not make this request, please change your password immediately and revoke all sessions!<br><br>
Otherwise, you can reset your chat password by clicking the button below.<br>
<a href='{useful.url_for(request, 'forgot_chat_password_token', token=encrypted_token, external=True)}' style='{C.EMAIL_BUTTON_STYLE}' target='_blank'>
    Click here to reset your chat password
</a>
    """

    from gcp import EmailCloudFunction # to avoid circular import
    email_cloud_function: EmailCloudFunction = request.app.state.obj_map[EmailCloudFunction]
    await email_cloud_function.send_email(
        to=user_doc["email"],
        subject="Mirai Chat Password Reset",
        body=msg,
        name=user_doc["display_name"],
    )
    return {
        "message": "Please check your email for a link to reset your chat password.",
    }

@user_api.patch(
    path="/chat/update/settings",
    description="Update the each of the chat settings like self-destructing messages one at a time!",
)
async def chat_update_settings(request: Request, data: schemas.ChatPrivacy, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    message_timer = data.message_timer
    hide_online_status = data.hide_online_status
    if message_timer is None and hide_online_status is None:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "No chat settings were provided to update.",
            }
        )

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc
    user_id = user_doc["_id"]

    if message_timer is not None and message_timer != user_doc["chat"]["message_timer"]:
        await col.update_one(
            {"_id": user_id},
            {
                "$set": {
                    "chat.message_timer": C.MESSAGE_TIMER_INT[message_timer],
                },
            }
        )
        return {
            "message": C.MESSAGE_TIMER_STR[message_timer],
        }

    if hide_online_status is not None and hide_online_status != user_doc["chat"]["hide_online_status"]:
        await col.update_one(
            {"_id": user_id},
            {
                "$set": {
                    "chat.hide_online_status": hide_online_status,
                },
            }
        )
        return {
            "message": "Your online status will now be hidden from other users." \
                                if hide_online_status else "Your online status will now be visible to other users.",
        }

    return ORJSONResponse(
        status_code=400,
        content={
            "message": "No chat settings were updated.",
        },
    )

@user_api.patch(
    path="/chat/update/password",
    description="Update the password of the chat (different from their logon password).",
)
async def chat_update_password(request: Request, data: schemas.ChatPassword, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="configure_chat_settings",
        min_threshold=0.75,
    )
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc
    user_id = user_doc["_id"]

    password = data.password
    if len(password) < 6 or len(password) > 64:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Chat password must be between 6 and 64 characters.",
            },
        )

    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    # check if the chat password is the same as the user's password
    if user_doc.get("password") is not None:
        user_password = await aes_gcm.symmetric_decrypt(
            ciphertext=user_doc["password"],
            key_id=C.DATABASE_KEY,
        )
        try:
            C.HASHER.verify(user_password, password)
        except (argon2_e.VerifyMismatchError):
            pass
        else:
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": "Chat password cannot be the same as your account password.",
                },
            )

    if user_doc["chat"].get("password_protection") is not None:
        # In this case, the user is trying to remove chat password protection
        user_chat_password = await aes_gcm.symmetric_decrypt(
            ciphertext=user_doc["chat"]["password_protection"],
            key_id=C.DATABASE_KEY,
        )
        try:
            C.HASHER.verify(user_chat_password, password)
        except (argon2_e.VerifyMismatchError):
            return ORJSONResponse(
                status_code=401,
                content={
                    "message": "Incorrect password.",
                },
            )
        except:
            return ORJSONResponse(
                status_code=500,
                content={
                    "message": C.ERROR_MSG,
                },
            )

        await col.update_many(
            {"_id": user_id},
            {
                "$set": {
                    # set remember_chat to False for all sessions
                    "sessions.$[].remember_chat": False,
                    # remove the chat password
                    "chat.password_protection": None,
                }
            },
        )
        return {
            "message": "Chat password protection has been removed."
        }

    # In this case, the user is trying to add chat password protection
    encrypted_password = await aes_gcm.symmetric_encrypt(
        plaintext=C.HASHER.hash(password),
        key_id=C.DATABASE_KEY,
    )
    # set remember_chat to False for all sessions
    await col.update_many(
        {"_id": user_id},
        {
            "$set": {
                "sessions.$[].remember_chat": False
            }
        }
    )
    await col.update_one(
        {"_id": user_id},
        {
            "$set": {
                "chat.password_protection": encrypted_password,
            },
        }
    )
    return {
        "message": "Chat password protection has been added."
    }

@user_api.websocket("/ws/{receiver_uid}")
async def chat_ws(websocket: WebSocket, receiver_uid: str):
    await websocket.accept()
    db = mongo.get_db_client()
    user_col = db[C.USER_COLLECTION]
    if not bson.ObjectId.is_valid(receiver_uid):
        return await websocket.close(reason="Invalid user ID.")
    receiver_uid = bson.ObjectId(receiver_uid)

    # Note: you can't use RBAC function on websocket
    # hence, the code below...
    invalid_session_msg = "Not authenticated."
    verify_res = await rbac.verify_access(websocket, [C.USER], user_col)
    if isinstance(verify_res, RedirectResponse):
        return await websocket.close(reason=invalid_session_msg)

    sender_user_doc = verify_res
    if sender_user_doc is None:
        return await websocket.close(reason=invalid_session_msg)
    sender_uid = sender_user_doc["_id"]
    if sender_uid == receiver_uid:
        return await websocket.close(reason="Sorry! You can't chat with yourself even if you're that lonely.")

    # check if the receiver exists
    receiver_uid = bson.ObjectId(receiver_uid)
    receiver_user_doc: dict | None = await user_col.find_one({
        "_id": receiver_uid,
    })
    if receiver_user_doc is None:
        return await websocket.close(reason="No such user exists.")

    aes_gcm: GcpAesGcm = websocket.app.state.obj_map[GcpAesGcm]
    # check if the sender has set a password for the chat sessions
    # and if the user is fetching the initial messages
    try:
        fetch_initial_messages = await websocket.receive_json()
        sender_chat_password = sender_user_doc["chat"]["password_protection"]
        if sender_chat_password is not None:
            # mainly for convenience which would only remember for the current session
            do_not_ask_again_flag = False
            sender_session_id = websocket.session[C.SESSION_COOKIE]
            for session in sender_user_doc["sessions"]:
                if (session["session_id"] == sender_session_id) and session.get("remember_chat", False):
                    do_not_ask_again_flag = True

            if not do_not_ask_again_flag:
                sender_chat_password = await aes_gcm.symmetric_decrypt(
                    ciphertext=sender_chat_password,
                    key_id=C.DATABASE_KEY,
                )
                await websocket.send_json({
                    "require_password": True,
                })

                recaptcha_enterprise: RecaptchaEnterprise = websocket.app.state.obj_map[RecaptchaEnterprise]
                while True:
                    user_payload = await websocket.receive_json()
                    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
                        site_key=C.MIRAI_SITE_KEY,
                        token=user_payload.get("recaptcha_token"),
                        action="enter_chat_password",
                        min_threshold=0.75,
                    )
                    if not recaptcha_assessment:
                        await websocket.send_json({
                            "password_result": "Invalid reCAPTCHA token.",
                        })
                        continue

                    password_json = user_payload.get("password")
                    try:
                        if password_json is None:
                            raise argon2_e.VerifyMismatchError
                        C.HASHER.verify(sender_chat_password, password_json)
                    except (argon2_e.VerifyMismatchError):
                        await websocket.send_json({
                            "password_result": "Invalid password.",
                        })
                    except:
                        await websocket.send_json({
                            "password_result": C.ERROR_MSG,
                        })
                    else:
                        # add/set "chat_remember" to True to the current session object
                        if user_payload.get("do_not_ask_again", False):
                            await user_col.update_one(
                                {"sessions.session_id": websocket.session[C.SESSION_COOKIE]},
                            {
                                "$set": {
                                    "sessions.$.remember_chat": True
                                }
                            })
                        await websocket.send_json({
                            "password_result": "Correct password.",
                        })
                        break
    except (WebSocketDisconnect, WebSocketException):
        logging.info(f"Client #{sender_uid} disconnected before entering password.")
        return

    # get chat lists
    chat_col = db[C.CHAT_COLLECTION]
    await chat.send_chat_list(
        ws=websocket,
        user_doc=sender_user_doc,
        user_col=user_col,
        chat_col=chat_col,
    )

    # receive all message from database
    current_time = int(time.time())
    latest_msg = {
        "timestamp": current_time,
    }
    cursor = chat_col.find({
        "$or": [
            {"sender": sender_uid, "receiver": receiver_uid},
            {"sender": receiver_uid, "receiver": sender_uid},
        ],
        "$and": [
            {"$or": [
                {"expiry": {"$eq": None}},
                {"expiry": {"$gt": current_time}},
            ]},
        ],
    })

    if fetch_initial_messages.get("fetch_initial_messages"):
        # if the user is opening the chat for the first time on their browser.
        # Doesn't necessarily mean that the user is opening a new chat session.
        encrypted_messages = [doc async for doc in cursor.sort("timestamp", pymongo.DESCENDING).limit(C.CHAT_MSG_LIMIT)]
        if not encrypted_messages:
            await websocket.send_json({"new_chat_session": True})
        else:
            decrypted_chat_messages = await chat.decrypt_messages(
                request=websocket,
                encrypted_messages=encrypted_messages,
            )
            latest_msg = decrypted_chat_messages[0]
            for message_doc in decrypted_chat_messages:
                message_doc["prepend"] = True
                await websocket.send_json(useful.format_json_response(message_doc, escape=False))
    else:
        # if the user is reconnecting.
        encrypted_msg = [doc async for doc in cursor.sort("timestamp", pymongo.DESCENDING).limit(1)]
        if encrypted_msg:
            latest_msg = encrypted_msg[0]

    cloud_storage: CloudStorage = websocket.app.state.obj_map[CloudStorage]
    deleted_chat_col = db[C.DELETED_CHAT_COLLECTION]
    try:
        await chat.add_user_to_connected_list(
            websocket=websocket,
            user_id=sender_user_doc["_id"],
        )
        while True:
            # verify session
            try:
                verify_res = await rbac.verify_access(websocket, [C.USER], user_col)
            except UserBannedException as e:
                verify_res = e
            if isinstance(verify_res, RedirectResponse | UserBannedException):
                return await websocket.close(reason=invalid_session_msg)

            # update the current user (sender) status to online
            sender_user_doc: dict | None = verify_res
            if sender_user_doc is None:
                return await websocket.close(reason=invalid_session_msg)
            if not sender_user_doc["chat"]["hide_online_status"] and not sender_user_doc["chat"]["online"]:
                await user_col.update_one(
                    {"_id": sender_uid,},
                    {
                        "$set": {
                            "chat.online": True,
                        }
                    }
                )
            elif sender_user_doc["chat"]["hide_online_status"] and sender_user_doc["chat"]["online"]:
                await user_col.update_one(
                    {"_id": sender_uid,},
                    {
                        "$set": {
                            "chat.online": False,
                        }
                    }
                )

            # check for any deleted messages
            deleted_msg_cursor = deleted_chat_col.find({
                "sender": receiver_uid,
            })
            expired_msg_cursor = chat_col.find({
                "$or": [
                    {"sender": sender_uid, "receiver": receiver_uid},
                    {"sender": receiver_uid, "receiver": sender_uid},
                ],
                "expiry": {
                    "$ne": None,
                    "$lt": int(time.time()),
                    "$gt": current_time,
                },
            })
            deleted_messages_id = [document["_id"] async for document in deleted_msg_cursor]
            expired_msg = [document async for document in expired_msg_cursor]
            if deleted_messages_id:
                for message_id in deleted_messages_id:
                    await websocket.send_json({
                        "message_id": str(message_id),
                        "deleted": True,
                    })
                await deleted_chat_col.delete_many({
                    "_id": {"$in": deleted_messages_id},
                })
            if expired_msg:
                # since the message will be automatically deleted by the cloud function from the database.
                await asyncio.gather(*[
                    # delete the file from the
                    # Google Cloud Storage private bucket
                    cloud_storage.delete_blob(
                        bucket=C.PRIVATE_BUCKET,
                        blob_name=chat_doc["message"],
                    ) for chat_doc in expired_msg if chat_doc["type"] != "text"
                ])
                for chat_doc in expired_msg:
                    chat_doc_id = str(chat_doc["_id"])
                    await websocket.send_json({
                        "message_id": chat_doc_id,
                        "expired": True,
                    })

            # retrieve new messages from the database
            new_msg_cursor = chat_col.find({
                "$or": [
                    {"sender": sender_uid, "receiver": receiver_uid},
                    {"sender": receiver_uid, "receiver": sender_uid},
                ],
                "$and": [
                    {"$or": [
                        {"expiry": {"$eq": None}},
                        {"expiry": {"$gt": time.time()}},
                    ]},
                ],
                "timestamp": {"$gt": latest_msg["timestamp"]},
            })
            new_encrypted_messages = [document async for document in new_msg_cursor.sort("timestamp", pymongo.ASCENDING)]

            # Decrypt the new messages
            new_messages = await chat.decrypt_messages(
                request=websocket,
                encrypted_messages=new_encrypted_messages,
            )
            if new_messages:
                latest_msg = new_messages[-1]

            # send the new decrypted messages to the client
            for message_doc in new_messages:
                await websocket.send_json(useful.format_json_response(message_doc, escape=False))

            # update the read status for the messages
            await chat_col.update_many({
                "sender": receiver_uid,
                "receiver": sender_uid,
                "read": False,
            }, {
                "$set": {
                    "read": True,
                }
            })

            # send latest chat list
            await chat.send_chat_list(
                ws=websocket,
                user_doc=sender_user_doc,
                user_col=user_col,
                chat_col=chat_col,
            )

            allowed_to_chat = False

            # check if the user is blocked
            blocked = await user_col.find_one({
                "$or": [
                    {"_id": sender_uid, "blocked_users": receiver_uid},
                    {"_id": receiver_uid, "blocked_users": sender_uid},
                ],
            })
            if blocked is not None:
                blocked_by = "sender" if blocked["_id"] == sender_uid else "receiver"
                await websocket.send_json({
                    "blocked": True,
                    "blocked_by": blocked_by,
                })
            else:
                # check if sender is authorised to chat with receiver
                receiver_permitted = useful.evaluate_permissions(
                    target_id=receiver_uid,
                    target_privacy=receiver_user_doc["privacy"],
                    user_following=sender_user_doc["social"]["following"]
                ).send_direct_messages

                # check if sender should be chatting with receiver (given own permissions)
                sender_permitted = useful.evaluate_permissions(
                    target_id=sender_uid,
                    target_privacy=sender_user_doc["privacy"],
                    user_following=receiver_user_doc["social"]["following"]
                ).send_direct_messages

                if not receiver_permitted:
                    await websocket.send_json({
                        "insufficient_permissions": True,
                        "restricted_by": "receiver",
                        "permission_level": receiver_user_doc["privacy"]["send_direct_messages"],
                    })
                elif not sender_permitted:
                    await websocket.send_json({
                        "insufficient_permissions": True,
                        "restricted_by": "sender",
                        "permission_level": sender_user_doc["privacy"]["send_direct_messages"],
                    })
                else:
                    await websocket.send_json({
                        "permissions_checked": True,
                    })
                    allowed_to_chat = True

            try:
                # wait for new messages from the client
                receive_user_msg_task = asyncio.create_task(
                    websocket.receive_json(),
                )
                _, pending = await asyncio.wait(
                    [receive_user_msg_task],
                    timeout=1.5,
                )
            except: # on unix system, an exception is raised
                raise WebSocketDisconnect(1001, "Connection closed by client.")

            # Cancel the pending task if
            # there was no new message from the client.
            # This is so that the user would receive any new messages
            # from the opposite user in the database via polling.
            for task in pending:
                task.cancel()
            if pending:
                continue

            data = receive_user_msg_task.result()
            fetch_messages = data.get("fetch_messages", False)
            if fetch_messages and data.get("oldest_msg_id") is not None:
                # if user is requesting to fetch messages...
                oldest_msg_id = bson.ObjectId(data["oldest_msg_id"])
                oldest_msg_cursor = chat_col.find({
                    "$or": [
                        {"sender": sender_uid, "receiver": receiver_uid},
                        {"sender": receiver_uid, "receiver": sender_uid},
                    ],
                    "_id": {"$lt": oldest_msg_id},
                })
                oldest_encrypted_messages = [
                    document async for document in oldest_msg_cursor.sort("_id", pymongo.DESCENDING).limit(C.CHAT_MSG_LIMIT)
                ]
                oldest_messages = await chat.decrypt_messages(
                    request=websocket,
                    encrypted_messages=oldest_encrypted_messages,
                )
                if oldest_messages:
                    for message_doc in oldest_messages:
                        message_doc["prepend"] = True
                        if message_doc == oldest_messages[-1]:
                            message_doc["fetch_completed"] = True
                        else:
                            message_doc["fetching"] = True
                        await websocket.send_json(useful.format_json_response(message_doc, escape=False))
                else:
                    await websocket.send_json({
                        "fetch_completed": True,
                        "no_messages": True,
                    })
                continue

            delete_msg = data.get("delete", False)
            if delete_msg:
                # if user is requesting to delete a message...
                delete_msg_id = bson.ObjectId(delete_msg)
                chat_doc = await chat_col.find_one({
                    "_id": delete_msg_id,
                    "sender": sender_uid,
                })
                if chat_doc is None:
                    continue

                message_type: str = chat_doc["type"]
                if message_type != "text":
                    # delete the file from the
                    # Google Cloud Storage private bucket
                    deletion_tasks = []
                    for file in chat_doc["files"]:
                        deletion_tasks.append(
                            cloud_storage.delete_blob(
                                bucket=C.PRIVATE_BUCKET,
                                blob_name=file["blob_name"]
                            )
                        )
                        if file.get("compressed_blob_name") is not None:
                            deletion_tasks.append(
                                cloud_storage.delete_blob(
                                    bucket=C.PRIVATE_BUCKET,
                                    blob_name=file["compressed_blob_name"]
                                )
                            )
                    await asyncio.gather(*deletion_tasks)
                await chat_col.delete_one({
                    "_id": delete_msg_id,
                })
                await deleted_chat_col.insert_one({
                    "_id": delete_msg_id,
                    "sender": sender_uid,
                    "deleted_at": datetime.utcnow(),
                })
                continue

            if not allowed_to_chat:
                continue

            # check if the message is valid
            msg = data.get("message")
            if msg is None:
                continue
            if not isinstance(msg, str):
                await websocket.send_json({
                    "error": "Your message must be a string.",
                })
                continue
            msg = msg.strip()
            if len(msg) < 1:
                continue

            max_msg_length = C.MAX_CHAT_MSG_LENGTH[sender_user_doc["mirai_plus"]]
            if sender_user_doc["mirai_plus"] and len(msg) > max_msg_length:
                await websocket.send_json({
                    "error": f"Your message is too long. Please shorten it to less than {max_msg_length} characters.",
                })
                continue

            receiver_user_doc: dict | None = await user_col.find_one({
                "_id": receiver_uid,
            })
            if receiver_user_doc is None:
                return await websocket.close(reason="No such user exists.")

            # check the crc32c checksum of the message
            # to make sure that the message is not corrupted
            msg_crc32c_checksum = data.get("crc32c_checksum")
            msg_md5_checksum = data.get("md5_checksum")
            if msg_crc32c_checksum is None or msg_md5_checksum is None:
                await websocket.send_json({
                    "error": "Missing crc32c or md5 checksums for message, please try again.",
                })
                continue
            if (msg_crc32c_checksum != crc32c(msg)) or (msg_md5_checksum != hashlib.md5(msg.encode("utf-8")).hexdigest()):
                await websocket.send_json({
                    "error": "Message checksums do not match, please try again.",
                })
                continue

            # scan the message for any confidential information and mask it if found
            msg = await mask_sensitive_info(websocket, msg)

            min_expiry_time = sec.get_min_message_timer(
                sender_user_doc=sender_user_doc,
                receiver_user_doc=receiver_user_doc,
            )

            # insert the message into the database
            msg_dict = {
                "_id": bson.ObjectId(),
                "message": msg,
                "sender": sender_uid,
                "receiver": receiver_uid,
                "timestamp": time.time(),
                "type": "text",
                "read": False,
                "expiry": None if min_expiry_time == 0 else time.time() + min_expiry_time,
            }
            latest_msg = msg_dict
            await websocket.send_json(useful.format_json_response(msg_dict, escape=False))

            # encrypt the message before inserting into the database
            encrypted_message = await aes_gcm.symmetric_encrypt(
                plaintext=msg,
                key_id=C.DATABASE_KEY,
            )
            msg_dict["message"] = bson.Binary(encrypted_message)
            await chat_col.insert_one(msg_dict)
    except (WebSocketDisconnect, WebSocketException):
        cleanup_tasks = [
            user_col.update_one(
                {"_id": sender_uid},
                {
                    "$set": {
                        "chat.online": False,
                    }
                }
            ),
            chat.remove_user_from_connected_list(
                user_id=sender_uid,
                websocket=websocket,
            ),
        ]
        await asyncio.gather(*cleanup_tasks)
        logging.debug("Client disconnected")

@user_api.post(
    path="/user/export/data",
    description="Export all the data associated with the user's account.",
)
async def export_data(request: Request, data: schemas.RecaptchaToken, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="export_data",
        min_threshold=0.75,
    )
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=422,
            content={
                "error": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    db = rbac_res.database
    user_doc = rbac_res.user_doc
    security_info = user_doc["security"]
    if "exported_data" in security_info:
        exported_data = security_info["exported_data"]
        if "expiry_date" in exported_data:
            if time.time() < exported_data["expiry_date"]:
                return ORJSONResponse(
                    status_code=400,
                    content={
                        "error": f"You can only request a new data export again after 3 days. Please try again later in {int(exported_data['expiry_date'] - time.time())} seconds.",
                    }
                )
        elif "requested_at" in exported_data:
            if (time.time() - exported_data["requested_at"]) < (24 * 60 * 60):
                return ORJSONResponse(
                    status_code=400,
                    content={
                        "error": "You have already requested an export of your data within the 24 hour. Please try again later.",
                    }
                )

    cloud_tasks: CloudTasks = request.app.state.obj_map[CloudTasks]
    response = await cloud_tasks.create_http_task(
        url=C.EXPORT_DATA_URL_FUNCTION,
        method="POST",
        queue_name=C.EXPORT_DATA_QUEUE,
        payload={
            "user_id": str(user_doc["_id"]),
        },
    )
    await db[C.USER_COLLECTION].update_one(
        {"_id": user_doc["_id"]},
        {
            "$set": {
                "security.exported_data": {
                    "requested_at": time.time(),
                    "task_name": response["name"],
                },
            },
        },
    )

    return {
        "message": "Your data export request has been submitted.\nYou will receive an email when the export is ready within the next 1 hour.",
    }

@user_api.post(
    path="/security/2fa/setup/sms",
    description="Setup SMS 2FA for the user and send the code to the user's phone number for verification. This route is rate limited to 1 SMS per 5 minutes.",
)
async def setup_phone_sms(request: Request, data: schemas.SetupSMS, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="setup_sms_2fa",
        min_threshold=0.75,
    )
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=422,
            content={
                "error": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    db = rbac_res.database
    user_col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc

    if user_doc["security"].get("sms_2fa", False):
        return ORJSONResponse(
            status_code=400,
            content={
                "error": "You have already setup SMS 2FA for your account.",
            }
        )

    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    # check if the user has already sent a SMS verification code within the last 15 minutes (900 seconds)
    sms_code_dict = user_doc["security"].get("sms_code")
    user_phone_num = user_doc.get("phone_num")
    if user_phone_num is not None:
        user_phone_num = await aes_gcm.symmetric_decrypt(
            ciphertext=user_phone_num,
            key_id=C.DATABASE_KEY,
        )
    if (user_phone_num == data.phone_num) and sms_code_dict and ((sms_code_dict["created_at"] + C.SMS_TWO_FA_RATE_LIMIT) > time.time()):
        return ORJSONResponse(
            status_code=422,
            content={
                "error":
                    "We have already sent a code to {}. Please either submit the sent code or wait for {} minutes before requesting a new code.".format(
                        data.phone_num,
                        int((sms_code_dict["created_at"] + C.SMS_TWO_FA_RATE_LIMIT - time.time()) / 60),
                    ),
            }
        )

    sms_code = sec.generate_secret_code()
    twilio_api: TwilioAPI = request.app.state.obj_map[TwilioAPI]
    await twilio_api.send_sms(
        to=data.phone_num,
        body=f"Use {sms_code} for your two-factor authentication confirmation code on Mirai",
    )
    encrypted_phone_num = await aes_gcm.symmetric_encrypt(
        plaintext=data.phone_num,
        key_id=C.DATABASE_KEY,
    )
    await user_col.update_one(
        {"_id": user_doc["_id"]},
        {
            "$set": {
                "phone_num": bson.Binary(encrypted_phone_num),
                "security.sms_code": {
                    "code": sms_code,
                    "created_at": time.time(),
                    "expiry": time.time() + C.SMS_TWO_FA_EXPIRY,
                }
            }
        }
    )
    return {
        "message": "Successfully sent the confirmation code to your phone number.",
    }

@user_api.post(
    path="/security/2fa/verfiy/sms",
    description="Verify the SMS 2FA code sent to the user's phone number and enable SMS 2FA for the user.",
)
async def verify_sms_setup(request: Request, data: schemas.VerifySmsSetup, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc

    matched = await sec.verify_sms_code(
        code=data.code,
        user_doc=user_doc,
        col=user_col,
    )
    if isinstance(matched, ORJSONResponse):
        return matched

    data_to_update = {
        "security.sms_2fa": True,
    }
    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    backup_code = user_doc["security"].get("backup_code")
    # generate a random backup code for the user if the user does not have one
    if backup_code is None:
        backup_code = await sec.generate_backup_code(request)
        encrypted_backup_code = await aes_gcm.symmetric_encrypt(
            plaintext=backup_code,
            key_id=C.DATABASE_KEY,
        )
        data_to_update["security.backup_code"] = bson.Binary(encrypted_backup_code)
    else:
        backup_code = await aes_gcm.symmetric_decrypt(
            ciphertext=backup_code,
            key_id=C.DATABASE_KEY,
        )

    # update the user document
    await user_col.update_one(
        {"_id": user_doc["_id"]},
        {
            "$set": data_to_update,
            "$unset": {
                "security.sms_code": "",
            },
        }
    )

    return {
        "message": "2FA SMS method set and enabled successfully.",
        "backup_code": backup_code,
        "escaped_backup_code": html.escape(backup_code), # needed for base85 encoding
    }

@user_api.delete(
    path="/security/2fa/remove/sms",
    description="Removes the SMS 2FA method from the user's account.",
)
async def remove_sms_two_fa(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc

    # check if the user has already enabled 2FA
    if not user_doc["security"].get("sms_2fa", False):
        return ORJSONResponse(
            status_code=400,
            content={
                "error": "2FA (SMS Method) is already disabled for this account.",
            }
        )

    await user_col.update_one(
        {"_id": user_doc["_id"]},
        {
            "$set": {
                "security.sms_2fa": False,
            },
            "$unset": {
                "security.sms_code": "",
                "phone_num": "",
            },
        }
    )
    return {
        "message": "2FA (SMS Method) has been removed for this account.",
    }

@user_api.patch(
    path="/security/2fa/generate/backup-code",
    description="Generate a new backup code for the user.",
)
async def generate_backup_code(request: Request, data: schemas.RecaptchaToken, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="generate_new_backup_code",
        min_threshold=0.75,
    )
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "error": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc

    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    backup_code = await sec.generate_backup_code(request)
    encrypted_backup_code = await aes_gcm.symmetric_encrypt(
        plaintext=backup_code,
        key_id=C.DATABASE_KEY,
    )
    await col.update_one(
        {"_id": user_doc["_id"]},
        {"$set": {
            "security.backup_code": bson.Binary(encrypted_backup_code),
        }},
    )
    return {
        "backup_code": backup_code,
    }

@user_api.get(
    path="/security/2fa/get/2fa-token",
    description="Generate a shared secret for 2FA authenticator token generation for the user to scan with their authenticator app.",
)
async def generate_two_fa_token(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc

    # check if the user has already enabled 2FA
    if user_doc["security"].get("secret_totp_token") is not None:
        return ORJSONResponse(
            status_code=400,
            content={
                "error": "2FA is already enabled for this account.",
            }
        )

    secret_token, qrcode_data = await sec.generate_totp_secret(
        username=user_doc["username"],
    )
    return {
        "secret_token": secret_token,
        "qrcode_data": qrcode_data,
    }

@user_api.delete(
    path="/security/2fa/remove/2fa-token",
    description="Removes the 2FA authenticator token for the user.",
)
async def remove_two_fa_token(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc

    # check if the user has enabled 2FA
    if user_doc["security"].get("secret_totp_token") is None:
        return ORJSONResponse(
            status_code=400,
            content={
                "error": "2FA (Authenticatior Method) has not been enabled for this account.",
            }
        )

    await user_col.update_one(
        {"_id": user_doc["_id"]},
        {
            "$unset": {
                "security.secret_totp_token": "",
            }
        }
    )
    return {
        "message": "2FA (Authenticatior Method) has been removed for this account.",
    }

@user_api.post(
    path="/security/2fa/set/2fa-token",
    description="Set the 2FA authenticator token for the user.",
)
async def set_two_fa_token(request: Request, data: schemas.SetTwoFAToken, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_col = db[C.USER_COLLECTION]
    user_doc = rbac_res.user_doc

    # check if the user has already enabled 2FA
    if user_doc["security"].get("secret_totp_token") is not None:
        return ORJSONResponse(
            status_code=400,
            content={
                "error": "2FA (Authenticatior Method) is already enabled for this account.",
            }
        )

    # check if the token is valid
    if not pyotp.TOTP(data.two_fa_token).verify(data.two_fa_code):
        return ORJSONResponse(
            status_code=400,
            content={
                "error": "Invalid confirmation code.",
            }
        )

    # encrypt the token before inserting into the database
    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    encrypted_token = await aes_gcm.symmetric_encrypt(
        plaintext=data.two_fa_token,
        key_id=C.DATABASE_KEY,
    )

    data_to_update = {
        "security.secret_totp_token": bson.Binary(encrypted_token),
    }
    backup_code = user_doc["security"].get("backup_code")
    # generate a random backup code for the user if the user does not have one
    if backup_code is None:
        backup_code = await sec.generate_backup_code(request)
        encrypted_backup_code = await aes_gcm.symmetric_encrypt(
            plaintext=backup_code,
            key_id=C.DATABASE_KEY,
        )
        data_to_update["security.backup_code"] = bson.Binary(encrypted_backup_code)
    else:
        backup_code = await aes_gcm.symmetric_decrypt(
            ciphertext=backup_code,
            key_id=C.DATABASE_KEY,
        )

    # update the user document
    await user_col.update_one(
        {"_id": user_doc["_id"]},
        {"$set": data_to_update},
    )

    return {
        "message": "2FA Authenticatior method set and enabled successfully.",
        "backup_code": backup_code,
        "escaped_backup_code": html.escape(backup_code), # needed for base85 encoding
    }

@user_api.put(
    path="/settings/google/unlink",
    description="Unlink the user's Google account from their account.",
    response_model=schemas.APIResponse,
)
async def unlink_google_account(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    authenticated = useful.get_authenticated_status(request, rbac_res.user_doc)

    if not authenticated:
        return ORJSONResponse(
            status_code=400,
            content={
                "error": "You are not authenticated.",
            }
        )

    return await oauth2.unlink_oauth_account(
        db=rbac_res.database,
        user_doc=rbac_res.user_doc,
        provider="google",
    )

@user_api.put(
    path="/settings/facebook/unlink",
    description="Unlink the user's Facebook account from their account.",
    response_model=schemas.APIResponse,
)
async def unlink_facebook_account(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    authenticated = useful.get_authenticated_status(request, rbac_res.user_doc)

    if not authenticated:
        return ORJSONResponse(
            status_code=400,
            content={
                "error": "You are not authenticated.",
            }
        )

    return await oauth2.unlink_oauth_account(
        db=rbac_res.database,
        user_doc=rbac_res.user_doc,
        provider="facebook",
    )

@user_api.put(path="/edit-privacy")
async def set_privacy(request: Request, permissions: schemas.Permission | None = None, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_col = db[C.USER_COLLECTION]
    public_requests = False
    coroutines = []
    print(permissions)

    if permissions is not None:
        update_values = {"$set": {
            f"privacy.{field}": level.value
            for field, level in permissions.dict(exclude_none=True).items()
            if rbac_res.user_doc["privacy"][field] != level.value
        }}
        print(update_values)
        # for field, level in permissions.dict(exclude_none=True).items():
        #     print((rbac_res.user_doc["privacy"][field],  level))
        if not update_values["$set"]:
            return ORJSONResponse(
                status_code=400,
                content={"message": "Error: Permissions Unedited"}
            )

        update_values["$set"].update({"privacy.last_updated": datetime.utcnow()})
        update_values.update({"$unset": {"setup_incomplete": ""}})
        public_requests = (update_values["$set"].get("privacy.be_follower") == C.FRIENDSHIP_TYPE.PUBLIC)
    else:
        update_values = {"$unset": {"setup_incomplete": ""}}
    if public_requests:
        coroutines.append(user_col.update_many(
            filter={"_id": {
                "$in": rbac_res.user_doc["social"][C.FOLLOWER_TYPE.PENDING]
            }},
            update={"$pull": {
                f"social.{C.FOLLOWER_TYPE.REQUESTS}": rbac_res.user_doc["_id"]
            }},
        ))
        update_values["$set"].update({f"social.{C.FOLLOWER_TYPE.PENDING}": []})

    coroutines.append(user_col.update_one(
        filter={"username": rbac_res.user_doc["username"]},
        update=update_values,
    ))

    response = await asyncio.gather(*coroutines)

    if response[-1].modified_count:
        return ORJSONResponse(
            status_code=200,
            content={"message": "Permissions Successfully Edited"},
        )

    return ORJSONResponse(
        status_code=400,
        content={"message": "Error: Permissions Unedited"}
    )

@user_api.get(
    path="/followers",
    response_model=schemas.Followers,
    response_model_exclude_unset=True,
)
async def get_followers(request: Request, follower_type: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_col = db[C.USER_COLLECTION]

    if follower_type not in C.FOLLOWER_TYPE:
        return ORJSONResponse(
            status_code=400,
            content={"message": "Specify correct follower_type"}
        )

    follower_info = rbac_res.user_doc["social"][follower_type]
    if C.DEBUG_MODE:
        print(follower_info)

    # Find user info of all followers/following/pending/requests users
    cursor = user_col.find(filter={"_id": {"$in": follower_info}})
    users = await cursor.to_list(length=len(follower_info))

    if users is None:
        return ORJSONResponse(
            status_code=500,
            content={"message": "Internal Server Error"}
        )

    return {
        follower_type: [{
            "username":
                user["username"],
            "display_name":
                user["display_name"],
            "user_image_url":
                user["profile"]["image"]["url"],
            "following_status":
                useful.get_following_status(
                    user["_id"],
                    rbac_res.user_doc["social"][C.FOLLOWER_TYPE.FOLLOWING],
                    rbac_res.user_doc["social"][C.FOLLOWER_TYPE.PENDING],
                    rbac_res.user_doc["social"][C.FOLLOWER_TYPE.REQUESTS],
                ),
            "bio":
                user["profile"]["bio"],
        } for user in users]
    }

@user_api.put("/follow-user/{target_username}")
async def follow_user(request: Request, target_username: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    """
    #### Trigger: "Follow" Button
    ------
    #### User Added | To User's | List
    ##### If target permission is "request_needed":
     - Current      | Target    | pending_list
     - Target       | Current   | requests_list
    ##### If target permission is "public":
     - Current      | Target    | followers_list
     - Target       | Current   | following_list
    """
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_collection = db[C.USER_COLLECTION]
    user = rbac_res.user_doc

    target = await user_collection.find_one(
        filter={"username": target_username},
        projection={"privacy.be_follower": True, f"social.{C.FOLLOWER_TYPE.REQUESTS}": True}
    )

    if target is None:
        return ORJSONResponse(
            status_code=404,
            content={"message": "User not found."}
        )

    user_id = user["_id"]
    target_id = bson.ObjectId(target["_id"])
    blocked = await user_collection.find_one({
        "$or": [
            {"_id": target_id, "blocked_users": user_id},
            {"_id": user_id, "blocked_users": target_id},
        ],
    })

    if blocked:
        return ORJSONResponse(
            status_code=403,
            content={"message": "Blocked by user."}
        )

    if user_id == target_id:
        return ORJSONResponse(
            status_code=403,
            content={"message": "Cannot follow own self"}
        )

    if target["privacy"]["be_follower"] == C.FRIENDSHIP_TYPE.PUBLIC or user_id in target["social"][C.FOLLOWER_TYPE.REQUESTS]:
        success_message = "followed"
        results: list[UpdateResult] = await asyncio.gather(
            user_collection.update_one(
                filter={"_id": user_id},
                update={"$addToSet": {f"social.{C.FOLLOWER_TYPE.FOLLOWING}": target_id}}
            ),
            user_collection.update_one(
                filter={"_id": target_id},
                update={"$addToSet": {f"social.{C.FOLLOWER_TYPE.FOLLOWERS}": user_id}}
            ),
            mongo.write_notification(
                db=db,
                user_id=target_id,
                notif_type=C.FOLLOW_TYPE,
                partial_msg=C.FOLLOW_MSG,
                other_user=user_id,
            ),
        )
    elif target["privacy"]["be_follower"] == C.FRIENDSHIP_TYPE.REQUEST_NEEDED:
        success_message = "requested"
        results: list[UpdateResult] = await asyncio.gather(
            user_collection.update_one(
                filter={"_id": user_id},
                update={"$addToSet": {f"social.{C.FOLLOWER_TYPE.REQUESTS}": target_id}}
            ),
            user_collection.update_one(
                filter={"_id": target_id},
                update={"$addToSet": {f"social.{C.FOLLOWER_TYPE.PENDING}": user_id}}
            ),
            mongo.write_notification(
                db=db,
                user_id=target_id,
                notif_type=C.FOLLOW_TYPE,
                partial_msg=C.FOLLOW_REQUEST_MSG,
                other_user=user_id,
            ),
        )
    else:
        return ORJSONResponse(
            status_code=500,
            content={"message": "Internal Server Error"}
        )

    if all(result.raw_result["updatedExisting"] for result in results[:2]):
        return ORJSONResponse(
            status_code=200,
            content={"message": success_message}
        )
    else:
        return ORJSONResponse(
            status_code=400,
            content={"message": "User already followed/requested."}
        )

@user_api.put("/unfollow-user/{target_username}")
async def unfollow_user(request: Request, target_username: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    """
    #### Trigger: "Unfollow", "Ignore" Button
    ---
    #### User Removed | From User's | List
     - Target         | Current     | following_list
     - Current        | Target      | followers_list
    ##### OR
     - Target         | Current     | pending_list
     - Current        | Target      | requests_list
    """
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_collection = db[C.USER_COLLECTION]
    user = rbac_res.user_doc

    target = await user_collection.find_one(
        filter={"username": target_username},
        projection={"_id": 1},
    )

    user_id = user["_id"]
    target_id = bson.ObjectId(target["_id"])

    if target is None:
        return ORJSONResponse(
            status_code=404,
            content={"message": "User not found."}
        )

    if user_id == target_id:
        return ORJSONResponse(
            status_code=403,
            content={"message": "Cannot follow own self"}
        )

    results: list[UpdateResult] = await asyncio.gather(
        user_collection.update_one(
            filter={"_id": user_id},
            update={"$pull": {
                f"social.{C.FOLLOWER_TYPE.FOLLOWING}": target_id,
                f"social.{C.FOLLOWER_TYPE.PENDING}": target_id,
            }}
        ),
        user_collection.update_one(
            filter={"_id": target_id},
            update={"$pull": {
                f"social.{C.FOLLOWER_TYPE.FOLLOWERS}": user_id,
                f"social.{C.FOLLOWER_TYPE.REQUESTS}": user_id
            }}
        ),
    )

    if any(result.raw_result["updatedExisting"] for result in results):
        return ORJSONResponse(
            status_code=200,
            content={"message": "Successfully removed"}
        )
    else:
        return ORJSONResponse(
            status_code=400,
            content={"message": "Removal unsuccessful"}
        )

@user_api.put("/confirm-following/{target_username}")
async def confirm_following(request: Request, target_username: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    """
    #### Trigger: "Accept" Button
    ---
    #### User Added | To User's | List
     - Target       | Current   | followers_list
     - Current      | Target    | following_list
    ---
    #### User Removed | From User's | List
     - Target         | Current     | pending_list
     - Current        | Target      | requests_list
    """
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_collection = db[C.USER_COLLECTION]
    user = rbac_res.user_doc

    target = await user_collection.find_one(
        filter={"username": target_username},
        projection={f"social.{C.FOLLOWER_TYPE.REQUESTS}": True}
    )
    user_id = user["_id"]

    if target is None:
        return ORJSONResponse(
            status_code=404,
            content={"message": "User not found"}
        )
    elif user_id not in target["social"][C.FOLLOWER_TYPE.REQUESTS]: # Also checks if you are trying to add yourself
        return ORJSONResponse(
            status_code=403,
            content={"message": "User has not requested to follow you"}
        )

    target_id = bson.ObjectId(target["_id"])
    blocked = await user_collection.find_one({
        "$or": [
            {"_id": target_id, "blocked_users": user_id},
            {"_id": user_id, "blocked_users": target_id},
        ],
    })

    if blocked:
        return ORJSONResponse(
            status_code=403,
            content={"message": "Blocked by user."}
        )

    results: list[UpdateResult] = await asyncio.gather(
        user_collection.update_one(
            filter={"_id": user_id},
            update={
                "$addToSet": {f"social.{C.FOLLOWER_TYPE.FOLLOWERS}": target_id},
                "$pull": {f"social.{C.FOLLOWER_TYPE.PENDING}": target_id},
            }
        ),
        user_collection.update_one(
            filter={"_id": target_id},
            update={
                "$addToSet": {f"social.{C.FOLLOWER_TYPE.FOLLOWING}": user_id},
                "$pull": {f"social.{C.FOLLOWER_TYPE.REQUESTS}": user_id},
            }
        ),
        mongo.write_notification(
            db=db,
            user_id=user_id,
            notif_type=C.FOLLOW_TYPE,
            partial_msg=C.USER_ACCEPTED_FOLLOW_REQUEST_MSG,
            other_user=target_id,
        ),
        mongo.write_notification(
            db=db,
            user_id=target_id,
            notif_type=C.FOLLOW_TYPE,
            partial_msg=C.ACCEPTED_FOLLOW_REQUEST_MSG,
            other_user=user_id,
        ),
    )

    if all(result.raw_result["updatedExisting"] for result in results[:2]):
        return ORJSONResponse(
            status_code=200,
            content={"message": "User followed"}
        )
    else:
        return ORJSONResponse(
            status_code=400,
            content={"message": "User already followed."}
        )

@user_api.put("/remove-request/{target_username}")
async def remove_request(request: Request, target_username: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    """
    #### Trigger: "Remove" Button
    ---
    #### User Removed | From User's | List
     - Current        | Target      | pending_list
     - Target         | Current     | requests_list
    """
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_collection = db[C.USER_COLLECTION]
    user = rbac_res.user_doc

    target = await user_collection.find_one(
        filter={"username": target_username},
        projection={"privacy.be_follower": True, f"social.{C.FOLLOWER_TYPE.REQUESTS}": True}
    )

    if user is None or target is None:
        return ORJSONResponse(
            status_code=404,
            content={"message": "User not found."}
        )

    user_id = user["_id"]
    target_id = target["_id"]

    results: list[UpdateResult] = await asyncio.gather(
        user_collection.update_one(
            filter={"_id": target_id},
            update={"$pull": {f"social.{C.FOLLOWER_TYPE.PENDING}": bson.ObjectId(user_id)}}
        ),
        user_collection.update_one(
            filter={"_id": user_id},
            update={"$pull": {f"social.{C.FOLLOWER_TYPE.REQUESTS}": bson.ObjectId(target_id)}}
        ),
    )

    if all(result.raw_result["updatedExisting"] for result in results):
        return ORJSONResponse(
            status_code=200,
            content={"message": "User request removed"}
        )
    else:
        return ORJSONResponse(
            status_code=400,
            content={"message": "Request has not been sent"}
        )

@user_api.put("/block-user/{target_username}")
async def block_user(request: Request, target_username: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_collection = db[C.USER_COLLECTION]

    target = await user_collection.find_one(
        filter={"username": target_username},
        projection={"_id": True},
    )

    if target is None:
        return ORJSONResponse(
            status_code=404,
            content={"message": "User not found."}
        )

    if target["_id"] == rbac_res.user_doc["_id"]:
        return ORJSONResponse(
            status_code=403,
            content={"message": "Not allowed to block yourself."}
        )

    response: list[UpdateResult] = await asyncio.gather(
        user_collection.update_one(
            filter={"_id": rbac_res.user_doc["_id"]},
            update={
                "$addToSet": {"blocked_users": target["_id"]},
            },
            upsert=True,
        ),
        user_collection.update_one( # User unfollows target
            filter={"_id": rbac_res.user_doc["_id"]},
            update={"$pull": {
                f"social.followers": target["_id"],
                f"social.pending": target["_id"],
            }},
        ),
        user_collection.update_one( # Target unfollows user
            filter={"username": target_username},
            update={"$pull": {
                f"social.following": rbac_res.user_doc["_id"],
                f"social.requests": rbac_res.user_doc["_id"],
            }},
        ),
    )

    if response[0].modified_count:
        return ORJSONResponse(
            status_code=200,
            content={"message": "User blocked."}
        )

    return ORJSONResponse(
        status_code=400,
        content={"message": "User already blocked."}
    )

@user_api.put("/unblock-user/{target_username}")
async def unblock_user(request: Request, target_username: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_collection = db[C.USER_COLLECTION]

    target = await user_collection.find_one(
        filter={"username": target_username},
        projection={"_id": True},
    )

    if target is None:
        return ORJSONResponse(
            status_code=404,
            content={"message": "User not found."}
        )

    response: UpdateResult = await user_collection.update_one(
        filter={"_id": rbac_res.user_doc["_id"]},
        update={"$pull": {"blocked_users": target["_id"]}}
    )

    if response.modified_count:
        await user_collection.update_one(
            filter={
                "_id": rbac_res.user_doc["_id"],
                "blocked_users": [],
            },
            update={"$unset": {"blocked_users": ""}}
        )
        return ORJSONResponse(
            status_code=200,
            content={"message": "User unblocked."},
        )

    return ORJSONResponse(
        status_code=400,
        content={"message": "User not blocked."}
    )

@user_api.get("/blocked-users")
async def get_blocked_users(request: Request, offset: int | None = None, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_collection = db[C.USER_COLLECTION]

    if not offset:
        offset = 0

    blocked_users = await user_collection.find_one(
        filter={"_id": rbac_res.user_doc["_id"]},
        projection={
            "blocked_users": {"$slice": [offset, offset + 10]}
        }
    )
    if not blocked_users:
        return []

    user_info = await user_collection.find(
        filter={
            "_id": {"$in": blocked_users["blocked_users"]},
        },
        projection={
            "username": True,
            "display_name": True,
            "profile.bio": True,
            "profile.image.url": True,
            "_id": False
        }
    ).to_list(length=10)

    return user_info

@user_api.get("/mirai-plus")
async def get_mirai_plus_stripe_link(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user = User(rbac_res.user_doc)
    payment_col = rbac_res.database[C.PAYMENT_COLLECTION]
    subscription: StripeSubscription = request.app.state.obj_map[StripeSubscription]

    existing_session = await payment_col.find_one_and_delete(
        filter={
            "user_id": user.id,
            "subscription": None,
        },
        projection={"checkout_session": True},
    )

    if not existing_session:
        existing_session = {"checkout_session": None}
    session = await subscription.create_new_session(
        request=request, 
        user_id=user.id, 
        email=user.email, 
        old_session_id=existing_session["checkout_session"],
    )

    if not session:
        return ORJSONResponse(
            status_code=500,
            content={"message": "Error, please refresh and try again."}
        )

    await payment_col.insert_one({
        "user_id": user.id,
        "checkout_session": session["id"],
        "subscription": None,
        "start_date": None,
        "end_date": None,
    })
    return {
        "url": session["url"],
    }

@user_api.get("/mirai-plus/payment")
async def payment_complete(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user = rbac_res.user_doc
    payment_col = db[C.PAYMENT_COLLECTION]
    user_col = db[C.USER_COLLECTION]

    payment = await payment_col.find_one(
        filter={
            "user_id": user["_id"],
            "subscription": None,
        },
        projection={"checkout_session": True},
    )

    subscription: StripeSubscription = request.app.state.obj_map[StripeSubscription]
    subscription_id = await subscription.get_subscription(
        user_id=user["_id"], 
        checkout_session_id=payment["checkout_session"],
    )

    if subscription_id is not None:
        await asyncio.gather(
            user_col.update_one(
                filter={"username": user["username"]},
                update={"$set": {"mirai_plus": True}},
            ),
            payment_col.update_one(
                filter={
                    "user_id": user["_id"],
                    "subscription": None,
                },
                update={"$set": {
                    "subscription": subscription_id,
                    "start_date": datetime.utcnow(),
                }},
            ),
            subscription.update_subscription_metadata(
                subscription_id=subscription_id,
                user_id=user["_id"]
            )
        )
    return RedirectResponse(useful.url_for(request, "mirai_plus"))

@user_api.delete("/mirai-plus/cancel")
async def cancel_mirai_plus(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user = rbac_res.user_doc
    payment_col = rbac_res.database[C.PAYMENT_COLLECTION]

    _filter = {"user_id": user["_id"], "end_date": None}
    subscription_id = await payment_col.find_one(
        filter=_filter,
        projection={"subscription": True},
    )
    if not subscription_id:
        return ORJSONResponse(
            status_code=400,
            content={"message": "No pre-existing subscription found."}
        )
    subscription_id = subscription_id["subscription"]

    subscription: StripeSubscription = request.app.state.obj_map[StripeSubscription]
    current_period_end = await subscription.cancel_subscription(subscription_id)
    if current_period_end:
        await payment_col.update_one(
            filter=_filter,
            update={"$set": {"end_date": current_period_end}},
        )
        return {
            "message": f"Mirai+ valid until {current_period_end.strftime('%F')}.",
        }

    return ORJSONResponse(
        status_code=400,
        content={"message": "No pre-existing subscription found."}
    )

@user_api.put("/mirai-plus/resume")
async def resume_mirai_plus(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user = rbac_res.user_doc
    payment_col = rbac_res.database[C.PAYMENT_COLLECTION]
    if not user["mirai_plus"]:
        return ORJSONResponse(
            status_code=400,
            content={"message": "No existing payment to resume."}
        )

    _filter = {"user_id": user["_id"], "end_date": {"$gte": datetime.utcnow()}}
    payment = await payment_col.find_one(
        filter=_filter,
        projection={"subscription": True},
    )

    if not payment:
        return ORJSONResponse(
            status_code=400,
            content={"message": "No existing payment to resume."}
        )

    subscription: StripeSubscription = request.app.state.obj_map[StripeSubscription]
    if await subscription.resume_subscription(payment["subscription"]):
        await payment_col.update_one(
            filter=_filter,
            update={"$set": {"end_date": None}},
        )
        return {
            "message": "Auto collection has been re-enabled.",
        }

    return ORJSONResponse(
        status_code=400,
        content={"message": "No existing payment to resume."}
    )

@user_api.post("/report/{reported_username}")
async def report_user(request: Request, reported_username: str, report:schemas.Report, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    if reported_username == rbac_res.user_doc["username"]:
        return ORJSONResponse(
            status_code=403,
            content={"message": "Cannot report yourself."}
        )

    admin_db = rbac_res.admin_database
    user_col = rbac_res.database[C.USER_COLLECTION]
    report_col = admin_db[C.REPORT_COLLECTION]

    reported_user = await user_col.find_one({"username": reported_username})
    if not reported_user:
        return ORJSONResponse(
            status_code=404,
            content={"message": "User not found."},
        )

    await report_col.insert_one({
        "title": report.reason.value,
        "affected": report.affected.value,
        "reasons": report.method,
        "created_at": datetime.utcnow(),
        "status": "open",
        "reported_user_id": reported_user["_id"],
        "reported_username": reported_username,
        "reported_by": rbac_res.user_doc["username"],
        "report_by_id": rbac_res.user_doc["_id"],
    })
    return {
        "message": "Reported created. Thank you.",
    }