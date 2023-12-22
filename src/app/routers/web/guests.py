# import third-party libraries
import bson
from fastapi import (
    APIRouter, 
    Request, 
    Depends,
)
from fastapi.responses import (
    RedirectResponse, 
    ORJSONResponse,
)

# import local Python libraries
from utils import constants as C
from utils.functions import (
    rbac,
    security as sec,
    useful as useful,
)
from utils.classes import (
    hmac,
    User,
)
from .web_utils import render_template
from middleware import csp

# import Python's standard libraries
# import time

guest_router = APIRouter(
    include_in_schema=False,
    prefix="",
    dependencies=sec.get_rate_limiter_dependency(C.GUEST_ROUTER),
    tags=["guests"],
)
RBAC_DEPENDENCY = Depends(rbac.GUEST_RBAC, use_cache=False)

@guest_router.get("/login")
async def login(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    return await render_template(
        name="guest/login.html",
        context={
            "request": request,
            "csp_nonce": csp.get_nonce(request),
        }
    )

@guest_router.get("/register")
async def register(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    return await render_template(
        name="guest/register.html",
        context={
            "request": request,
            "csp_nonce": csp.get_nonce(request),
        }
    )

@guest_router.get(
    path="/forgot-password/token/{token}",
    description="Verify the password reset token and allow the user to type in their new password.",
)
async def forgot_password_token(request: Request, token: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    category = "Failed to reset password."
    err_msg = "The password reset link is invalid or has expired."
    decrypted_token = await sec.decrypt_token(request, token)
    signer = hmac.get_hmac_signer(C.FORGOT_PASS_EXPIRY)
    unsigned_token = signer.get(decrypted_token)
    if unsigned_token is None or unsigned_token.get("email") is None or unsigned_token.get("_id") is None or not bson.ObjectId.is_valid(unsigned_token["_id"]):
        useful.flash(
            request=request,
            message=err_msg,
            category=category,
        )
        return RedirectResponse(url="/")

    db = rbac_res.database
    matched_token = await db[C.ONE_TIME_TOKEN_COLLECTION].find_one(
        filter={
            "_id": bson.ObjectId(unsigned_token["_id"]),
        },
        projection={
            "_id": 1,
            "purpose": 1,
        },
    )
    if matched_token is None or matched_token.get("purpose") != "forgot_password":
        useful.flash(
            request=request,
            message=err_msg,
            category=category,
        )
        return RedirectResponse(url="/")

    email = unsigned_token["email"].lower().strip()
    col = db[C.USER_COLLECTION]
    user_doc: dict | None = await col.find_one({
        "email": email,
    })
    if user_doc is None:
        useful.flash(
            request=request,
            message=err_msg,
            category=category,
        )
        return RedirectResponse(url="/")

    # check if user has 2FA enabled
    redirect_response = sec.validate_2fa_reset_password(
        request=request,
        user_doc=user_doc,
        token=token,
    )
    if isinstance(redirect_response, ORJSONResponse):
        return RedirectResponse(url=useful.url_for(request, "two_fa"))

    return await render_template(
        name="guest/reset_password.html",
        context={
            "request": request,
            "email": email,
            "csp_nonce": csp.get_nonce(request),
        }
    )

@guest_router.get(
    path="/login/2fa",
    description="Show the 2FA page for the user to enter their 2FA code via their preferred methods.",
)
async def two_fa(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user_info = sec.validate_2fa_request(
        request=request,
    )
    if isinstance(user_info, ORJSONResponse):
        return RedirectResponse(url=useful.url_for(request, "login"))

    user_id = user_info["user_id"]
    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = await col.find_one({
        "_id": bson.ObjectId(user_id),
    })
    if user_doc is None:
        return RedirectResponse(url=useful.url_for(request, "login"))

    return await render_template(
        name="guest/2fa.html",
        context={
            "request": request,
            "user": await User.init(user_doc, rbac_res.database),
            "csp_nonce": csp.get_nonce(request),
        }
    )

@guest_router.get("/admin/login")
async def admin_login(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    return await render_template(
        name="guest/admin_login.html",
        context={
            "request": request,
            "csp_nonce": csp.get_nonce(request),
        }
    )