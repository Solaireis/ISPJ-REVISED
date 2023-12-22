# import third-party libraries
import bson
import pymongo.errors as mongo_e
from pymongo.collation import (
    Collation, 
    CollationStrength,
)
from fastapi import (
    APIRouter, 
    Request, 
    Depends,
)
from fastapi.responses import (
    ORJSONResponse,
    RedirectResponse,
)
import argon2.exceptions as argon2_e

# import local Python libraries
from utils import constants as C
from utils.functions import (
    database as mongo,
    rbac,
    security as sec,
    useful,
)
from gcp import (
    RecaptchaEnterprise, 
    GcpAesGcm,
)
from utils.classes import (
    TwilioAPI,
)
from utils.classes.hmac import get_hmac_signer
import schemas

# import Python's standard libraries
import time
import asyncio
import logging
from datetime import datetime

guest_api = APIRouter(
    include_in_schema=True,
    prefix=C.API_PREFIX,
    dependencies=sec.get_rate_limiter_dependency(C.GUEST_ROUTER),
    tags=["guests"],
)
RBAC_DEPENDENCY = Depends(rbac.GUEST_RBAC, use_cache=False)

@guest_api.post(
    path="/2fa/send-sms",
    description="Send a SMS to the user's phone number with a code to verify their identity.",
)
async def two_fa_sms(request: Request, data: schemas.RecaptchaToken, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user_info = sec.validate_2fa_request(
        request=request,
    )
    if isinstance(user_info, ORJSONResponse):
        return user_info

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="send_2fa_sms",
        min_threshold=0.75,
    ) 
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    user_id = bson.ObjectId(user_info["user_id"])
    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = await col.find_one(
        {"_id": user_id},
    )
    user_phone_number = user_doc.get("phone_num")
    if user_phone_number is None:
        return ORJSONResponse(
            status_code=403,
            content={
                "message": "You have not set your phone number yet.",
            }
        )

    # check if the user has already sent a SMS in the last 15 minutes
    sms_code_info = user_doc["security"].get("sms_code")
    if sms_code_info is not None and sms_code_info and (sms_code_info["created_at"] + C.SMS_TWO_FA_RATE_LIMIT) > time.time():
        return ORJSONResponse(
            status_code=400,
            content={
                "message": 
                    "We have already sent you a SMS in the last 15 minutes. Please either wait for the SMS to arrive or try again later after {} minutes.".format(
                        int((sms_code_info["created_at"] + C.SMS_TWO_FA_RATE_LIMIT - time.time()) / 60),
                    ),
            }
        )

    # Send SMS
    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    user_phone_number = await aes_gcm.symmetric_decrypt(
        ciphertext=user_phone_number,
        key_id=C.DATABASE_KEY,
    )
    sms_code = sec.generate_secret_code()
    twilio_api: TwilioAPI = request.app.state.obj_map[TwilioAPI]
    await twilio_api.send_sms(
        to=user_phone_number,
        body=f"Use {sms_code} for your two-factor authentication code on Mirai",
    )
    await col.update_one(
        {"_id": user_id},
        {"$set": {
            "security.sms_code": {
                "code": sms_code,
                "created_at": time.time(),
                "expiry": time.time() + C.SMS_TWO_FA_EXPIRY,
            }
        }},
    )

    return {
        "message": f"Sent a SMS to {user_doc['display_name']}'s phone number with a code to verify your identity.",
    }

@guest_api.post(
    path="/2fa/submit-token",
    description="Submit the token sent to the user's email or from the authenticator app to verify their identity.",
)
async def two_fa_submit_token(request: Request, data: schemas.TwoFAToken, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user_info = sec.validate_2fa_request(
        request=request,
        error_msg="Missing 2FA initialisation data. Please either log in again or restart your 2FA flow from pages like the reset password page.",
    )
    if isinstance(user_info, ORJSONResponse):
        return user_info

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="submit_2fa_token",
        min_threshold=0.75,
    ) 
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    user_id = bson.ObjectId(user_info["user_id"])
    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = await col.find_one(
        {"_id": user_id},
    )
    if user_doc is None:
        return ORJSONResponse(
            status_code=403,
            content={"message": "Please login first."},
        )

    response = None
    if data.purpose == schemas.TwoFaMethods.SMS and user_doc["security"].get("sms_2fa"):
        response = await sec.verify_sms_code(
            code=data.two_fa_token,
            user_doc=user_doc,
            col=col,
        )
    elif data.purpose == schemas.TwoFaMethods.AUTHENTICATOR and user_doc["security"].get("secret_totp_token"):
        response = await sec.verify_totp_token(
            request=request,
            token=data.two_fa_token,
            user_doc=user_doc,
        )
    else:
        return ORJSONResponse(
            status_code=403,
            content={
                "message": 
                    "The user no longer have 2FA enabled.",
            },
        )

    if response is not None:
        return response

    if user_info["add_session_after_2fa"] and user_info["purpose"] == "login":
        if user_info["stay_signed_in"]:
            session_expiry = C.SESSION_EXPIRY
        else:
            session_expiry = C.DO_NOT_REMEMBER_EXPIRY

        await sec.add_session(
            request=request,
            user_doc=user_doc,
            session_expiry=session_expiry,
            user_col=col,
        )

    if user_info["purpose"] == "reset_password":
        request.session["2fa_password_flow"] = "completed"

    redirect_url = request.session["2fa"]["redirect_url"]
    request.session.pop("2fa", None)
    return {
        "message": "Successfully authenticated.",
        "redirect_url": redirect_url,
    }

@guest_api.post(
    path="/2fa/disable",
    description="Disable 2FA for the user when the user inputs their backup code.",
)
async def disable_two_fa(request: Request, data: schemas.BackupCode, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    user_info = sec.validate_2fa_request(
        request=request,
    )
    if isinstance(user_info, ORJSONResponse):
        return user_info

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="submit_2fa_backup_code",
        min_threshold=0.75,
    ) 
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    user_id = bson.ObjectId(user_info["user_id"])
    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = await col.find_one(
        {"_id": user_id},
    )
    if user_doc is None:
        return ORJSONResponse(
            status_code=403,
            content={"message": "Please login first."},
        )

    user_backup_code = user_doc["security"].get("backup_code")
    if user_backup_code is None:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "You do not have a backup code. Please contact customer support.",
            },
        )

    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    user_backup_code = await aes_gcm.symmetric_decrypt(
        ciphertext=user_backup_code,
        key_id=C.DATABASE_KEY,
    )
    if user_backup_code != data.backup_code:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "The backup code is incorrect.",
            },
        )

    new_backup_code = await sec.generate_backup_code(request)
    new_backup_code = await aes_gcm.symmetric_encrypt(
        plaintext=new_backup_code,
        key_id=C.DATABASE_KEY,
    )
    await col.update_one(
        {"_id": user_id},
        {
            "$set": {
                "security.backup_code": bson.Binary(new_backup_code),
            },
            "$unset": {
                "phone_num": "",
                "security.sms_2fa": "",
                "security.sms_code": "",
                "security.secret_totp_token": "",
            },
        },
    )
    request.session.pop("2fa", None)
    return {
        "message": "Successfully disabled 2FA and a new backup code has been generated. Please login again to continue.",
    }

@guest_api.post(
    path="/login",
    description="Login to get authentication token cookie to access other API endpoints.",
    summary="Login to the API.",
    response_model=schemas.APIResponse,
)
async def api_login(request: Request, data: schemas.Login, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    recaptcha_enterprise = await RecaptchaEnterprise.init()
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="login",
        min_threshold=0.75,
    ) 
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    if C.ALLOWED_PASS_CHAR.fullmatch(data.password) is None:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Password should not contain any illegal characters.",
            }
        )

    # retrieve from database
    user_identifier = data.user_identifier
    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc: dict | None = await col.find_one(
        filter={
            "$or": [
                {"username": user_identifier},
                {"email": user_identifier},
            ]
        },
        collation=Collation(locale="en", strength=CollationStrength.PRIMARY),
    )
    err_msg = "The username, email, or password is incorrect."
    if user_doc is None or user_doc.get("password") is None:
        await sec.random_sleep()
        return ORJSONResponse(
            status_code=401,
            content={
                "message": err_msg,
            }
        )

    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    password_hash = await aes_gcm.symmetric_decrypt(
        ciphertext=user_doc["password"],
        key_id=C.DATABASE_KEY,
    )
    try:
        C.HASHER.verify(password_hash, data.password)
    except (argon2_e.VerifyMismatchError):
        await sec.random_sleep()
        return ORJSONResponse(
            status_code=401,
            content={
                "message": err_msg,
            }
        )
    except:
        return ORJSONResponse(
            status_code=500,
            content={
                "message": C.ERROR_MSG,
            }
        )

    # check if user's email has been verified
    if not user_doc["verified"]:
        await sec.send_verify_email(
            request=request,
            user_doc=user_doc,
        )
        return ORJSONResponse(
            status_code=403,
            content={
                "message": "Your email has not been verified. Please check your email for the verification link.",
            }
        )

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    # check if the user's credentials has been compromised using Google Cloud's API
    try:
        if await recaptcha_enterprise.check_credentials(user_doc["email"], data.password):
            for flash_msg in request.session.get(C.FLASH_MESSAGES, []):
                if flash_msg["message"] == "password_compromised":
                    break
            else:
                useful.flash(
                    request=request,
                    message="password_compromised",
                )
    except:
        logging.warning("Failed to check if user's credentials has been compromised.", exc_info=True)

    # check if user has 2FA enabled
    redirect_response = sec.redirect_to_2fa(
        request=request,
        user_doc=user_doc,
        purpose="login",
        redirect_url=useful.url_for(request, "index"),
        stay_signed_in=data.stay_signed_in,
        add_session_after_2fa=True,
    )
    if isinstance(redirect_response, ORJSONResponse):
        return redirect_response

    # check if user is logging in from a different location
    # if it exists check if the datetime is wihtin 14 days
    location = await useful.get_location_str(request)
    matched_location = await col.find_one(
        {
            "_id": user_doc["_id"],
            "security.last_accessed.location": location,
            "security.last_accessed.datetime": {
                "$gte": time.time() - C.LOCATION_TTL,
            },
        },
        projection={"_id": 1},
    )
    email_token = data.email_token
    if matched_location is None:
        if email_token is None or email_token.strip() == "":
            await sec.send_email_token(
                request=request,
                user_doc=user_doc,
                location=location,
                user_col=col,
            )
            return ORJSONResponse(
                status_code=403,
                content={
                    "message": "email",
                },
            )
        else:
            response = await sec.verify_email_token(
                request=request,
                email_token=email_token,
                user_doc=user_doc,
                user_col=col,
            )
            if response is not None:
                return response

    if data.stay_signed_in:
        session_expiry = C.SESSION_EXPIRY
    else:
        session_expiry = C.DO_NOT_REMEMBER_EXPIRY

    await sec.add_session(
        request=request,
        user_doc=user_doc,
        location=location,
        session_expiry=session_expiry,
        user_col=col,
    )

    return {
        "message": "Login successful.",
    }

@guest_api.post(
    path="/register",
    description="Create a user account and login to get authentication token cookie to access other API endpoints.",
    summary="Create an account to login to the API.",
    response_model=schemas.APIResponse,
)
async def api_register(request: Request, data: schemas.Register, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    if C.USERNAME_CHAR_WHITELIST_REGEX.fullmatch(data.username) is None:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Username can only contain alphanumeric characters, underscores, and dashes.",
            }
        )

    email = data.email.lower()
    username = data.username
    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    matched_doc: dict | None = await col.find_one(
        filter={
            "$or": [
                {"username": username},
                {"email": email},
            ]
        },
        collation=Collation(locale="en", strength=CollationStrength.PRIMARY),
    )
    if matched_doc is not None:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "The username or email is already in use.",
            }
        )

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="register",
        min_threshold=0.75,
    )
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    password_validation_response = await sec.main_password_validations(
        request=request,
        email=email,
        password=data.password,
    )
    if password_validation_response is not None:
        return password_validation_response

    encrypted_password_hash = await sec.secure_password(data.password)
    if isinstance(encrypted_password_hash, ORJSONResponse):
        return encrypted_password_hash

    location = await useful.get_location_str(request)
    user_doc = mongo.get_default_user_doc(
        email=email,
        username=username,
        password_hash=encrypted_password_hash,
        session_info=None,
        is_registering=True,
        location=location,
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

    await sec.send_verify_email(
        request=request,
        user_doc=user_doc,
    )
    useful.flash(
        request,
        "You have successfully registered an account. Please check your email for the verification link.",
        "success"
    )
    return {
        "message": "Successfully registered a new account on Mirai.",
    }

@guest_api.get(
    path="/verify-email/{token}",
    description="Verify the user's email address using the token sent to the user's email generated when trying logging in or after account registration.",
    summary="Verify the user's email address.",
    response_class=RedirectResponse,
)
async def verify_email(request: Request, token: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    token = await sec.decrypt_token(request, token)
    hmac_signer = get_hmac_signer(
        max_age=C.EMAIL_VERIFICATION_EXPIRY,
    )
    payload = hmac_signer.get(token)
    if payload is None:
        useful.flash(
            request,
            "Token is invalid or has expired. Please try logging in again to generate a new token.",
            "error",
        )
        return RedirectResponse(url=useful.url_for(request, "login"))

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = await col.find_one({
        "email": payload["email"]
    })
    if user_doc is None:
        useful.flash(
            request,
            # didn't show the "User not found" message to prevent enumeration attacks (though unlikely)
            "Token is invalid or has expired. Please try logging in again to generate a new token.",
            "error",
        )
        return RedirectResponse(url=useful.url_for(request, "login"))

    category = "error"
    msg = "Sorry, your email address is already verified!"
    if not user_doc["verified"]:
        await col.update_one(
            {"_id": user_doc["_id"]},
            {"$set": {
                "verified": True,
            }}
        )
        msg = "Successfully verified your email address. You can now log in."
        category = "success"

    useful.flash(
        request,
        msg,
        category,
    )
    return RedirectResponse(url=useful.url_for(request, "login"))

@guest_api.post(
    path="/forgot-password",
    description="Send a password reset link to the user's email.",
    response_model=schemas.APIResponse,
)
async def forgot_password(request: Request, data: schemas.ForgotPassword, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="forgot_password",
        min_threshold=0.75,
    )
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    email = data.email.lower().strip()
    db = rbac_res.database
    col = db[C.USER_COLLECTION]

    success_msg = {
        # to prevent enumeration attacks
        "message": "You should receive an email with a password reset link from us soon if your email is in our database.",
    }
    user_doc: dict | None = await col.find_one({
        "email": email,
    })
    if user_doc is None:
        return success_msg

    signer = get_hmac_signer(C.FORGOT_PASS_EXPIRY)
    token_id = bson.ObjectId()
    signed_token = signer.sign({
        "_id": str(token_id),
        "email": email,
    })
    encrypted_token, _ = await asyncio.gather(*[
        sec.encrypt_token(request, signed_token),
        db[C.ONE_TIME_TOKEN_COLLECTION].insert_one({
            "_id": token_id,
            "created_at": datetime.utcnow(),
            "purpose": "forgot_password",
        }),
    ])
    msg = f"""
You are receiving this email due to a request to reset your password on your Mirai account.<br>
If you did not make this request, please ignore this email.<br><br>
You can change the password on your account by clicking the button below.<br>
<a href='{useful.url_for(request, 'forgot_password_token', token=encrypted_token, external=True)}' style='{C.EMAIL_BUTTON_STYLE}' target='_blank'>
    Click here to reset your password
</a>
"""

    from gcp import EmailCloudFunction # to avoid circular import
    email_cloud_function: EmailCloudFunction = request.app.state.obj_map[EmailCloudFunction]
    await email_cloud_function.send_email(
        to=email,
        subject="Reset Password",
        body=msg,
        name=user_doc["display_name"],
    )
    return success_msg

@guest_api.post(
    path="/forgot-password/process",
    description="Send a password reset link to the user's email.",
    response_model=schemas.APIResponse,
)
async def forgot_password_process(request: Request, data: schemas.ForgotPasswordProcess, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="forgot_password_process",
        min_threshold=0.75,
    )
    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    err_msg = "The password reset link is invalid or has expired."
    token = await sec.decrypt_token(request, data.token)
    signer = get_hmac_signer(C.FORGOT_PASS_EXPIRY)
    token = signer.get(token)
    if token is None or token.get("email") is None or token.get("_id") is None or not bson.ObjectId.is_valid(token["_id"]):
        return ORJSONResponse(
            status_code=400,
            content={
                "message": err_msg,
            }
        )

    email = token["email"].lower().strip()
    db = rbac_res.database
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
    if matched_token is None or matched_token.get("purpose") != "forgot_password":
        return ORJSONResponse(
            status_code=400,
            content={
                "message": err_msg,
            }
        )

    col = db[C.USER_COLLECTION]
    user_doc: dict | None = await col.find_one({
        "email": email,
    })
    if user_doc is None:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": err_msg,
            }
        )

    # check if user has 2FA enabled
    reset_pass_2fa_response = sec.validate_2fa_reset_password(
        user_doc=user_doc,
        request=request,
        token=data.token,
    )
    if isinstance(reset_pass_2fa_response, ORJSONResponse):
        return reset_pass_2fa_response

    # password validations
    password_validation_response = await sec.main_password_validations(
        request=request,
        email=email,
        password=data.password,
    )
    if password_validation_response is not None:
        return password_validation_response

    encrypted_password_hash = await sec.secure_password(data.password)
    if isinstance(encrypted_password_hash, ORJSONResponse):
        return encrypted_password_hash

    await asyncio.gather(*[
        token_col.delete_one({
            "_id": token_id,
        }),
        col.update_one({
            "email": email,
        }, {
            "$set": {
                "password": bson.Binary(encrypted_password_hash),
            },
        })
    ])

    request.session.clear()
    useful.flash(
        request,
        "You have successfully reset your password. Please login with your new password.",
        "success",
    )
    return {
        "message": "Successfully reset your password.",
    }

@guest_api.post(
    path="/admin",
    description="Honeypot page",
    summary="Login to the API.",
    response_model=schemas.APIResponse,
)
async def api_admin_login(request: Request, data: schemas.Login, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    logging.warning(f"Login attempt to admin pages from {useful.get_user_ip(request)} with user identifier {data.user_identifier} and password {data.password}")
    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    recaptcha_assessment = await recaptcha_enterprise.verify_assessment(
        site_key=C.MIRAI_SITE_KEY,
        token=data.recaptcha_token,
        action="admin_login",
        min_threshold=0.75,
    ) 

    if not recaptcha_assessment:
        return ORJSONResponse(
            status_code=401,
            content={
                "message": "Failed to verify that the user is not a bot. Please try submitting the form again.",
            }
        )

    if C.ALLOWED_PASS_CHAR.fullmatch(data.password) is None:
        return ORJSONResponse(
            status_code=401,
            content={
                "message": "Password should not contain any illegal characters.",
            }
        )


    await sec.random_sleep()
    return ORJSONResponse(
        status_code=401,
        content={
            "message": "The username, email, or password is incorrect.",
        },
    )