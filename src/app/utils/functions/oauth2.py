# import third-party libraries
import orjson
import bson
from pymongo.database import Database
import pymongo.errors as mongo_e
from oauthlib.oauth2 import rfc6749
from fastapi import Request, Response
from fastapi.responses import ORJSONResponse, RedirectResponse
from fastapi_sso.sso.google import GoogleSSO
from fastapi_sso.sso.facebook import FacebookSSO

# import local Python libraries
from utils import constants as C
from . import database as mongo
from .useful import url_for, flash
from . import security as sec
from gcp import SecretManager

# import Python's standard libraries
import os
import html
import logging

# NOTE: This is a workaround for the internal network of 
# the deployment server as cloud run does not support self-signed certificates.
# However, it is noted that the redirect_uri MUST be https.
ALLOW_INSECURE_HTTP = not C.DEBUG_MODE
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" if ALLOW_INSECURE_HTTP else "0"

__secret_manager = SecretManager()
__FACEBOOK_CREDENTIALS = __secret_manager.get_secret_payload(
    secret_id="facebook-client-secret",
)
def get_facebook_sso(request: Request) -> FacebookSSO:
    """Returns the FacebookSSO object."""
    client_secret = __FACEBOOK_CREDENTIALS
    return FacebookSSO(
        client_id=C.FACEBOOK_CLIENT_ID,
        client_secret=client_secret,
        redirect_uri=url_for(request, "login_facebook_callback", external=True),
        scope=["email"],
        allow_insecure_http=ALLOW_INSECURE_HTTP,
    )

__GOOGLE_CREDENTIALS = orjson.loads(
    __secret_manager.get_secret_payload(
        secret_id="web-oauth2-client",
    ),
)
def get_google_sso(request: Request) -> GoogleSSO:
    """Returns the GoogleSSO object."""
    client_secret_json = __GOOGLE_CREDENTIALS["web"]
    return GoogleSSO(
        client_id=client_secret_json["client_id"],
        client_secret=client_secret_json["client_secret"],
        redirect_uri=url_for(request, "login_google_callback", external=True),
        scope=[
            # for retrieving the user's public personal information
            "https://www.googleapis.com/auth/userinfo.profile",
            # for getting the user's email
            "https://www.googleapis.com/auth/userinfo.email",
            # for associating the user with their personal info on Google
            "openid",
            # for Google to send security alerts to the user's email
            "https://www.googleapis.com/auth/gmail.send",
            # for Google to read the user's emails as required for some OAuth2 logins
            "https://www.googleapis.com/auth/gmail.readonly",
        ],
        allow_insecure_http=ALLOW_INSECURE_HTTP,
    )

async def process_oauth_callback(sso_obj: GoogleSSO | FacebookSSO, request: Request, oauth_type: str, user_doc: dict | None) -> Response:
    """Processes the OAuth2 callback from the various identity providers.

    Args:
        sso_obj (GoogleSSO | FacebookSSO):
            The SSO object.
        request (Request): 
            The request object.
        oauth_type (str):
            The type of OAuth2 login.
        user_doc (dict | None):
            The user document if the user is linking an OAuth2 account to their Mirai account.

    Returns:
        Response: 
            Redirects to the home page if successful, otherwise returns an error message.
    """
    request.session.pop(C.FLASH_MESSAGES, None)
    is_linking_oauth2 = (C.SESSION_COOKIE in request.session and user_doc is not None)

    try:
        user_info = await sso_obj.verify_and_process(request)
    except (rfc6749.errors.CustomOAuth2Error, rfc6749.errors.OAuth2Error) as e:
        logging.error(f"OAuth2 error: {e}")
        if is_linking_oauth2:
            flash(
                request=request, 
                message=f"Failed to link your {oauth_type.title()} account. Please try again.", 
                category="oauth2_error",
            )
            return RedirectResponse(url=url_for(request, "account_info_settings"))

        flash(
            request=request, 
            message=f"{oauth_type.title()} login failed. Please try again.", 
            category="error",
        )
        return RedirectResponse(url=url_for(request, "login"))

    # retrieve from user database
    email = user_info.email.lower()
    db = mongo.get_db_client()
    col = db[C.USER_COLLECTION]

    if is_linking_oauth2:
        user = await col.find_one_and_update(
            filter={
                "_id": user_doc["_id"],
                "email": email,
                "oauth2": {
                    "$not": {
                        "$elemMatch": {
                            "$eq": oauth_type,
                        },
                    },
                },
            },
            update={"$addToSet": {"oauth2": oauth_type}},
            projection={"_id": 1},
        )
        if user is None:
            flash(
                request=request, 
                message=f"Failed to link your {oauth_type.title()} account as you have either already linked it to your Mirai account or the email was not the same as your Mirai account.", 
                category="oauth2_error",
            )
        else:
            flash(
                request=request,
                message=f"Successfully linked your {oauth_type.title()} account to your Mirai account.",
                category="oauth2_success",
            )
        return RedirectResponse(url=url_for(request, "account_info_settings"))

    user_doc: dict | None = await col.find_one(
        {"email": email},
    )
    # retrieve from admin database
    if user_doc is None: # If the user is not found, check the admin database server
        admin_db = mongo.get_db_client(get_admin_db=True)
        admin_col = admin_db[C.ADMIN_COLLECTION]
        admin_doc: dict | None = await admin_col.find_one(
            {"email": email},
        )
        if admin_doc is not None:
            # if the user is found in the admin database server
            user_doc = admin_doc # then set the user_doc to the admin_doc
            col = admin_col      # and set the collection to the admin collection
            logging.info("Admin or Root has logged in.")

    # check if the user has an account with Mirai
    # but has not linked with the identity provider
    if user_doc is not None and oauth_type not in user_doc.get("oauth2", []):
        flash(
            request=request, 
            message=f"You already have an account with Mirai. Please login to your Mirai account and link it with your {oauth_type.title()} account first.", 
            category="error",
        )
        return RedirectResponse(url=url_for(request, "login"))

    # create new user if not found
    registered_new_acc = False
    if user_doc is None:
        registered_new_acc = True
        # create new user in the user database server
        if user_info.first_name is not None:
            user_info.first_name = html.escape(user_info.first_name)
        if user_info.last_name is not None:
            user_info.last_name = html.escape(user_info.last_name)
        if user_info.display_name is not None:
            user_info.display_name = html.escape(user_info.display_name, quote=False)

        user_id = bson.ObjectId()
        username = "_".join([user_info.first_name or "", user_info.last_name or ""])
        for char in username:
            if char not in C.USERNAME_CHAR_WHITELIST:
                username = username.replace(char, "_")

        if username == "" or all(char == "_" for char in username):
            username = f"user_{user_id}"

        username_exists = await col.find_one({
            "username": username,
        })
        if username_exists is not None:
            username = f"{user_info.first_name or 'user'}_{user_id}"

        user_doc = mongo.get_default_user_doc(
            _id=user_id,
            email=email,
            username=username,
            password_hash=None,
            session_info=None,
            oauth2=[oauth_type],
            display_name=user_info.display_name or username,
            verified=True,
        )

        # add profile picture
        user_profile = user_info.picture
        if user_profile is not None:
            if oauth_type == "google":
                # rsplit to remove Google's default profile picture size
                user_profile = user_profile.rsplit(sep="=", maxsplit=1)[0]
            user_doc["profile"]["image"]["url"] = user_profile

        try:
            await col.insert_one(user_doc)
        except (mongo_e.DuplicateKeyError):
            return ORJSONResponse(
                status_code=400,
                content={
                    "message": "The email address is already in use.",
                }
            )

    if not registered_new_acc:
        redirect_response = sec.redirect_to_2fa(
            request=request,
            user_doc=user_doc,
            purpose="login",
            redirect_url=url_for(request, "index"),
            stay_signed_in=False,
            add_session_after_2fa=True,
        )
        if isinstance(redirect_response, ORJSONResponse):
            return RedirectResponse(
                url=url_for(request, "two_fa")
            )

    # update session info
    await sec.add_session(
        request=request,
        user_doc=user_doc,
        session_expiry=C.DO_NOT_REMEMBER_EXPIRY,
        user_col=col,
    )
    return RedirectResponse(url="/")

async def unlink_oauth_account(db: Database, user_doc: dict, provider: str) -> dict | ORJSONResponse:
    """Unlinks the user's account from the given OAuth2 provider.

    Args:
        db (Database):
            The MongoDB database object.
        user_doc (dict):
            The user document.
        provider (str):
            The OAuth2 provider to unlink. Must be one of "google" or "facebook".

    Returns:
        dict | ORJSONResponse:
            The response object.
    """
    provider = provider.lower()
    if provider not in ("google", "facebook"):
        raise ValueError("Invalid OAuth2 provider.")

    if len(user_doc.get("oauth2", [])) == 0:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "You have not linked your Mirai account with any Google or Facebook accounts.",
            },
        )

    # check if the user has a password
    # to prevent locking themselves out
    if user_doc.get("password") is None and len(user_doc["oauth2"]) == 1:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": f"You must set a password before unlinking your Mirai account from your {provider.title()} account to avoid locking yourself out.",
            },
        )

    user_col = db[C.USER_COLLECTION]
    # remove "google" from the "oauth2" array
    user = await user_col.find_one_and_update(
        filter={
            "_id": user_doc["_id"],
            "oauth2": {
                "$elemMatch": {
                    "$eq": provider,
                },
            },
        },
        update={"$pull": {"oauth2": provider}},
        projection={"_id": 1},
    )
    if user is None:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": f"Failed to unlink your {provider.title()} account as you have not linked it to your Mirai account.",
            }
        )

    return {
        "message": f"Successfully unlinked your {provider.title()} account from your Mirai account.",
    }