# import third-party libraries
import pyotp
import qrcode
import user_agents
from fastapi import Request
from fastapi.params import Depends
import argon2.exceptions as argon2_e
from pymongo.collection import Collection
from fastapi.responses import ORJSONResponse
from fastapi.exceptions import HTTPException

# import local Python libraries
from utils import constants as C
from utils.functions.useful import (
    url_for,
    get_user_ip,
    download_url,
)
from gcp import (
    GcpAesGcm,
    GcpKms,
    RecaptchaEnterprise,
)
from .useful import (
    get_location_str, 
    datetime_to_unix_time,
)
from utils.classes.hmac import get_hmac_signer

# import Python's standard libraries
import io
import time
import random
import base64
import hashlib
import secrets
import asyncio
import warnings
from datetime import (
    datetime, 
    timedelta,
)
from binascii import Error as BinasciiError

async def random_sleep(min_t: int | None = 2, max_t: int | None = 4) -> None:
    """Sleeps for a random amount of time to 
    make enumeration attacks harder via security through obscurity.

    Args:
        min_t (int, optional):
            The minimum time to sleep for. Defaults to 2.
        max_t (int, optional):
            The maximum time to sleep for. Defaults to 4.

    Returns:
        None
    """
    await asyncio.sleep(random.uniform(min_t, max_t))

async def encrypt_token(request: Request, token: str, key_id: str | None = C.TOKEN_KEY) -> str:
    """Encrypts a token using AESGCM.

    Args:
        request (Request):
            The request object.
        token (str):
            The token to encrypt.
        key_id (str, optional):
            The key ID to use. Defaults to C.TOKEN_KEY.

    Returns:
        str: 
            The encrypted token.
    """
    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    encrypted_token = await aes_gcm.symmetric_encrypt(
        plaintext=token,
        key_id=key_id,
    )
    return base64.urlsafe_b64encode(encrypted_token).decode("utf-8")

async def decrypt_token(request: Request, token: str, key_id: str | None = C.TOKEN_KEY) -> str | None:
    """Decrypts a token using AESGCM.

    Args:
        request (Request):
            The request object.
        token (str):
            The token to decrypt.
        key_id (str, optional):
            The key ID to use. Defaults to C.TOKEN_KEY.

    Returns:
        str | None: 
            The decrypted token or None if the token is invalid.
    """
    if token is None:
        return None

    try:
        token = base64.urlsafe_b64decode(token)
        aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
        decrypted_token = await aes_gcm.symmetric_decrypt(
            ciphertext=token,
            key_id=key_id,
        )
    except (HTTPException, BinasciiError, ValueError, TypeError):
        return None

    return decrypted_token

async def send_email_token(request: Request, user_doc: dict, location: str, user_col: Collection) -> None:
    """Sends an email token to the user for verification.

    Args:
        request (Request):
            The request object.
        user_doc (dict):
            The user document.
        location (str):
            The location string.
        user_col (Collection):
            The user collection.

    Returns:
        None:
    """
    ip_addr = get_user_ip(request)
    token_per_ip_count = 0
    existing_tokens: list[dict] = user_doc["security"].get("email_tokens", [])
    for existing_token in existing_tokens:
        if ip_addr == existing_token["ip_address"]:
            token_per_ip_count += 1
            if time.time() < existing_token["expiry"] and token_per_ip_count >= C.MAX_EMAIL_TOKENS_PER_IP:
                return

    current_datetime = datetime.utcnow().strftime("%d %B %Y, %H:%M:%S %z")
    token = generate_secret_code()
    msg = f"""
Your Mirai account, {user_doc['email']}, was logged in to from a new IP address.<br><br>

Time: {current_datetime} (UTC)<br>Location*: {location}<br>
Login IP Address: {ip_addr}<br>
*Location is approximate based on the login's IP address.<br><br>

Please enter the generated code below to authenticate yourself.<br>
Generated Code (will expire in {C.TWO_FA_TOKEN_EXPIRY // 60} minutes!):<br>
<strong>{token}</strong><br><br>

If this was not you, we recommend that you <strong>change your password immediately</strong> by clicking the link below.<br>
Change password:<br>
{url_for(request, "settings", external=True)}"""

    if len(existing_tokens) >= C.MAX_EMAIL_TOKENS:
        # sort by expiry from oldest to newest
        existing_tokens.sort(key=lambda x: x["expiry"])
        await user_col.update_one(
            {"_id": user_doc["_id"]},
            {"$set": {
                "security.email_tokens": existing_tokens[-C.MAX_EMAIL_TOKENS + 1:],
            }},
        )

    await user_col.update_one(
        {"_id": user_doc["_id"]},
        {"$push": {
            "security.email_tokens": {
                "token": token,
                "expiry": time.time() + C.TWO_FA_TOKEN_EXPIRY,
                "ip_address": ip_addr,
            },
        }},
    )

    from gcp import EmailCloudFunction # to avoid circular import
    email_cloud_function: EmailCloudFunction = request.app.state.obj_map[EmailCloudFunction]
    await email_cloud_function.send_email(
        to=user_doc["email"],
        subject="Login from a different location",
        body=msg,
        name=user_doc["display_name"],
    )

async def verify_email_token(request: Request, email_token: str, user_doc: dict, user_col: Collection) -> None | ORJSONResponse:
    """Verifies the email token sent to the user.

    Args:
        request (Request):
            The request object.
        email_token (str):
            The email token to verify.
        user_doc (dict):
            The user document.
        user_col (Collection):
            The user collection.

    Returns:
        None | ORJSONResponse:
            None if the token is valid, otherwise an error response.
    """
    ip_addr = get_user_ip(request)
    email_token = email_token.strip()
    current_time = time.time()
    for token_doc in user_doc["security"].get("email_tokens", []):
        if token_doc["token"] == email_token and token_doc["expiry"] > current_time and token_doc["ip_address"] == ip_addr:
            await user_col.update_one(
                {"_id": user_doc["_id"]},
                {"$pull": {
                    "security.email_tokens": {
                        "token": email_token,
                    },
                }},
            )
            return
    else:
        return ORJSONResponse(
            status_code=401,
            content={
                "message": "Invalid or expired verification token.",
            }
        )

async def generate_backup_code(request: Request) -> bytes:
    """Generates a backup code.

    Args:
        request (Request):
            The request object.

    Returns:
        bytes: 
            The backup code.
    """
    gcp_kms: GcpKms = request.app.state.obj_map[GcpKms]
    random_bytes = await gcp_kms.get_random_bytes(
        n_bytes=C.BACKUP_CODE_BYTES,
        generate_from_hsm=not C.DEBUG_MODE,
    )
    return base64.b85encode(random_bytes).decode("utf-8")

def generate_secret_code(n_digits: int | None = 6) -> str:
    """Generates a secret code securely using the secrets module to ensure high entropy.

    Args:
        n_digits (int | None):
            The number of digits to generate.
            Defaults to 6.

    Returns:
        str: 
            The generated secret code.
    """
    return "".join([str(secrets.randbelow(10)) for _ in range(n_digits)])

async def verify_sms_code(code: str, user_doc: dict, col: Collection) -> None | ORJSONResponse:
    """Verifies the token retrieved via an sms message.

    Args:
        code (str):
            The sms code to verify.
        user_doc (dict):
            The user document.
        col (Collection):
            The user collection.

    Returns:
        None | ORJSONResponse:
            None if the code is valid, otherwise an error response.
    """
    sms_code_dict = user_doc["security"].get("sms_code")
    if not sms_code_dict:
        return ORJSONResponse(
            status_code=400,
            content={
                "error": "No sms code found.",
            }
        )

    if sms_code_dict["code"] != code:
        return ORJSONResponse(
            status_code=401,
            content={
                "error": "Invalid sms code.",
            }
        )

    if sms_code_dict["expiry"] < time.time():
        return ORJSONResponse(
            status_code=401,
            content={
                "error": "Expired sms code. Please request a new one.",
            }
        )

    await col.update_one(
        {"_id": user_doc["_id"]},
        {"$unset": {
            "security.sms_code": "",
        }},
    )

async def verify_totp_token(request: Request, token: str, user_doc: dict) -> None | ORJSONResponse:
    """Verifies the token retrieved via an authenticator app.

    Args:
        request (Request):
            The request object.
        token (str):
            The totp token to verify against the totp secret.
        user_doc (dict):
            The user document.

    Returns:
        None | ORJSONResponse:
            None if the token is valid, otherwise an error response.
    """
    encrypted_totp_secret = user_doc["security"]["secret_totp_token"]
    aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
    totp_secret = await aes_gcm.symmetric_decrypt(
        ciphertext=encrypted_totp_secret,
        key_id=C.DATABASE_KEY,
    )
    if not pyotp.TOTP(totp_secret).verify(token):
        return ORJSONResponse(
            status_code=401,
            content={
                "message": "Invalid TOTP token.",
            }
        )

async def generate_totp_secret(username: str) -> tuple[str, str]:
    """Generates a totp secret to be generated from GCP KMS Cloud HSM and MUST be kept secret

    Args:
        username (str):
            The username of the user.

    Returns:
        tuple[str, str]:
            The generated totp secret, and the QR code for the totp secret.
    """
    gcp_kms = await GcpKms.init()
    random_bytes = await gcp_kms.get_random_bytes(
        n_bytes=20,
        generate_from_hsm=not C.DEBUG_MODE,
    )
    secret_token = base64.b32encode(random_bytes)

    # generate totp uri to be 
    # used in the qrcode generation for convenience
    totp = pyotp.totp.TOTP(
        s=secret_token, 
        digits=6,
        digest=hashlib.sha1, # to be compatible with most authenticator apps
    )
    totp_uri = totp.provisioning_uri(
        name=f"@{username}", 
        issuer_name="Mirai",
    )

    # generate QR code for convenience
    stream = io.BytesIO()

    # create a qrcode object
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=15,
        border=5,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    qrcode_image = qr.make_image(
        fill_color=(234, 167, 199), 
        back_color="white",
    )

    # save the qrcode image in the memory buffer
    qrcode_image.save(stream)

    # get the image from the memory buffer and encode it into base64
    encoded_qrcode_data = base64.b64encode(stream.getvalue()).decode("utf-8")
    return (
        secret_token.decode("utf-8"), 
        f"data:image/png;base64, {encoded_qrcode_data}",
    )

async def add_session(request: Request, user_doc: dict, session_expiry: int, user_col: Collection, location: str | None = None) -> None:
    """Adds a session to the user document.

    Args:
        request (Request):
            The request object.
        user_doc (dict):
            The user document.
        session_expiry (int):
            The session expiry in seconds.
        user_col (Collection):
            The user collection.
        location (str | None, optional):
            The location of the user. Defaults to None and will be automatically determined via the request object.

    Returns:
        None
    """
    if location is None:
        location = await get_location_str(request)

    gcp_kms: GcpKms = request.app.state.obj_map[GcpKms]
    session_id = await gcp_kms.get_random_bytes(
        n_bytes=C.SESSION_BYTES,
        generate_from_hsm=not C.DEBUG_MODE,
    )
    session_id = base64.b85encode(session_id).decode("utf-8")
    request.session[C.SESSION_COOKIE] = session_id
    current_datetime = datetime.utcnow()
    current_time = datetime_to_unix_time(current_datetime)
    expiry_date = current_datetime + timedelta(seconds=session_expiry)

    ua = request.headers.get("User-Agent", "Unknown")
    parsed_ua = user_agents.parse(ua)
    os_name = parsed_ua.os.family + " " + parsed_ua.os.version_string
    session_data = {
        "session_id": session_id,
        "added_on": current_datetime,
        "expiry_date": expiry_date,
        "browser": parsed_ua.browser.family,
        "os": os_name.strip(),
        "location": location,
        "ip_address": get_user_ip(request),
        "user_agent": ua,
    }
    if session_expiry == C.DO_NOT_REMEMBER_EXPIRY:
        request.session[C.EXPIRY_ONCLOSE] = True

    update_kwargs = {
        "update": {
            "$push": {
                "sessions": session_data,
            },
            "$set": {
                "security.last_login": current_datetime,
            }
        },
    }

    matched_location = None
    for location_info in user_doc["security"].get("last_accessed", []):
        if location_info["location"] == location:
            matched_location = location_info
            break

    if matched_location is None:
        update_kwargs["update"]["$push"]["security.last_accessed"] = {
            "location": location,
            "datetime": current_time,
        }
    else:
        update_kwargs["update"]["$set"] = {
            "security.last_accessed.$[elem].datetime": current_time,
        }
        update_kwargs["array_filters"] = [{"elem.location": location}]

    await user_col.update_one(
        {"_id": user_doc["_id"]}, 
        **update_kwargs,
    )

def validate_2fa_request(request: Request, error_msg: str | None = "Please login first.") -> dict | ORJSONResponse:
    """Validates the 2fa request.

    Args:
        request (Request):
            The request object.
        error_msg (str | None, optional):
            The error message to return if the request is invalid. Defaults to "Please login first.".

    Returns:
        dict | ORJSONResponse:
            The user info if the request is valid, else an ORJSONResponse.
    """
    user_info = request.session.get("2fa")
    if user_info is None or user_info.get("ttl", 0) < time.time():
        request.session.pop("2fa", None)
        return ORJSONResponse(
            status_code=403,
            content={"message": error_msg},
        )
    return user_info

def validate_2fa_reset_password(request: Request, user_doc: dict, token: str) -> None | ORJSONResponse:
    """Validate 2FA for reset password flow.

    Args:
        request (Request):
            The request object.
        user_doc (dict):
            The user document.
        token (str):
            The reset password token.

    Returns:
        None | ORJSONResponse:
            None if the request is valid, else an ORJSONResponse 
            for the user to authenticate themselves for 2FA before resetting their password.
    """
    if request.session.get("2fa_password_flow", "") != "completed":
        redirect_response = redirect_to_2fa(
            request=request,
            user_doc=user_doc,
            purpose="reset_password",
            redirect_url=url_for(request, "forgot_password_token", token=token),
        )
        if isinstance(redirect_response, ORJSONResponse):
            return redirect_response

def check_if_user_has_2fa(user_doc: dict) -> bool:
    """Checks if the user has 2fa enabled.

    Args:
        user_doc (dict):
            The user doc

    Returns:
        bool:
            True if the user has 2fa enabled, else False.
    """
    return (user_doc["security"].get("sms_2fa", False) or user_doc["security"].get("secret_totp_token") is not None)

def redirect_to_2fa(request: Request, user_doc: dict, redirect_url: str, purpose: str,
                    stay_signed_in: bool | None = None, add_session_after_2fa: bool | None = False) -> None | ORJSONResponse:
    """Checks if the user has 2fa enabled and redirects the user to the 2fa page if they do.

    Args:
        request (Request):
            The request object.
        user_doc (dict):
            The user doc
        redirect_url (str):
            The redirect url to redirect the user after the 2FA flow.
        purpose (str):
            The purpose for the 2FA flow.
        stay_signed_in (bool | None, optional):
            Whether the user wants to stay signed in which will result in a login session that lasts longer. Defaults to None.
        add_session_after_2fa (bool | None, optional):
            Whether the user wants to add a session after 2fa. Defaults to False.

    Returns:
        None | ORJSONResponse:
            None if the user does not have 2fa enabled, else an ORJSONResponse.
    """
    if check_if_user_has_2fa(user_doc):
        request.session["2fa"] = {
            "user_id": str(user_doc["_id"]),
            "ttl": time.time() + C.TWO_FA_TIMEOUT,
            "redirect_url": redirect_url,
            "purpose": purpose,
            "add_session_after_2fa": add_session_after_2fa,
        }
        if stay_signed_in is not None:
            request.session["2fa"]["stay_signed_in"] = stay_signed_in

        return ORJSONResponse(
            status_code=403,
            content={
                "message": f"2fa required, please go to {url_for(request, 'two_fa')}",
            }
        )

async def send_verify_email(request: Request, user_doc: dict) -> None:
    """Sends the verification email to the user.

    Args:
        request (Request):
            The request object.
        user_doc (dict):
            The user document.

    Returns:
        None:
    """
    hmac_signer = get_hmac_signer(
        max_age=C.EMAIL_VERIFICATION_EXPIRY
    )
    signed_token = hmac_signer.sign({
        "email": user_doc["email"],
    })
    encrypted_token = await encrypt_token(request, signed_token)
    msg = f"""
Welcome to Mirai!<br>
Please click the link below to verify your email address:<br>
<a href='{url_for(request, "verify_email", external=True, token=encrypted_token)}' style='{C.EMAIL_BUTTON_STYLE}' target='_blank'>Verify Email</a><br>
"""

    from gcp import EmailCloudFunction # to avoid circular import
    email_cloud_function: EmailCloudFunction = request.app.state.obj_map[EmailCloudFunction]
    await email_cloud_function.send_email(
        to=user_doc["email"],
        subject="Email Verification",
        body=msg,
        name=user_doc["display_name"],
    )

PASSWORD_POLICIES_REGEX = (
    C.TWO_REPEAT_CHAR_REGEX,
    C.UPPERCASE_REGEX,
    C.LOWERCASE_REGEX,
    C.DIGIT_REGEX,
    C.SPECIAL_CHAR_REGEX,
)
def check_password_requirements(password: str) -> tuple[bool, str]:
    """Checks the password against the password requirements.

    Args:
        password (str):
            The password to check.

    Returns:
        tuple[bool, str]:
            Whether the password meets the requirements and the advisory message.
    """
    conditions_met = 0
    advisory_msg = "Password is too weak, "
    advisory_parts = []
    if C.UPPERCASE_REGEX.search(password) is None:
        advisory_parts.append("uppercase letter")
    else:
        conditions_met += 1

    if C.LOWERCASE_REGEX.search(password) is None:
        advisory_parts.append("lowercase letter")
    else:
        conditions_met += 1

    if C.DIGIT_REGEX.search(password) is None:
        advisory_parts.append("number")
    else:
        conditions_met += 1

    if C.SPECIAL_CHAR_REGEX.search(password) is None:
        advisory_parts.append("special character")
    else:
        conditions_met += 1

    if len(advisory_parts) > 0:
        advisory_msg += "please try adding " + ", ".join(advisory_parts)

    if C.TWO_REPEAT_CHAR_REGEX.search(password) is None:
        if len(advisory_parts) > 0:
            advisory_msg += ". Additionally, "
        advisory_msg += "there must not be two or more repeated characters"
    else:
        conditions_met += 1

    return (conditions_met >= (len(PASSWORD_POLICIES_REGEX) - 1), advisory_msg)

PASSWORD_TEXT_PATH = C.APP_ROOT_PATH.joinpath("utils", "misc", "common_passwords.txt")
PASSWORD_TEXT_PATH.parent.mkdir(parents=True, exist_ok=True)
if C.DEBUG_MODE and not PASSWORD_TEXT_PATH.exists() and not PASSWORD_TEXT_PATH.is_file():
    # Downloads the list of common passwords if it does not exist 
    # and ONLY in debug mode, when deployed, the container should have the file.
    downloaded_common_passwords = asyncio.run(
        download_url(
            url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
            method="GET",
            download_bytes=False,
        )
    )
    PASSWORD_TEXT_PATH.write_text(
        data="\n".join(downloaded_common_passwords.splitlines()), 
    )
COMMON_PASSWORD_ARR = set(PASSWORD_TEXT_PATH.read_text().splitlines())
async def check_common_passwords(password: str) -> bool:
    """Checks if the password is a common password against the list of 10,000 common passwords.

    Args:
        password (str):
            The password to check.

    Returns:
        bool:
            True if the password is a common password, False otherwise.
    """
    return (password in COMMON_PASSWORD_ARR)

async def main_password_validations(request: Request, email:str, password: str) -> ORJSONResponse | None:
    """Does the main password validations like checking for illegal characters, etc.

    Args:
        request (Request):
            The request object.
        email (str):
            The email of the user.
        password (str):
            The password to check.

    Returns:
        ORJSONResponse | None:
            A response if the password is invalid, None otherwise.
    """
    if C.ALLOWED_PASS_CHAR.fullmatch(password) is None:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Password should not contain any illegal characters.",
            }
        )

    met_pass_policy, advisory_msg = check_password_requirements(password)
    if not met_pass_policy:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": advisory_msg,
            }
        )

    # check against 10,000 most common passwords
    if await check_common_passwords(password):
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Password is too common. Please enter a more unique password.",
            }
        )

    # check if the user's credentials has been compromised using Google Cloud's API
    recaptcha_enterprise: RecaptchaEnterprise = request.app.state.obj_map[RecaptchaEnterprise]
    if await recaptcha_enterprise.check_credentials(email, password):
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Your credentials has been compromised. Please enter another password.",
            }
        )

async def secure_password(password: str) -> bytes | ORJSONResponse:
    """Hashes the password using Argon2id and encrypts it (pepper) using AES-256-GCM.

    Args:
        password (str):
            The password to hash and pepper it.

    Returns:
        bytes | ORJSONResponse:
            The encrypted password hash in bytes if successful, 
            ORJSONResponse otherwise if there was an error hashing the password.
    """
    try:
        password_hash = C.HASHER.hash(password)
    except (argon2_e.HashingError):
        return ORJSONResponse(
            status_code=500,
            content={
                "message": C.ERROR_MSG,
            }
        )

    aes_gcm = await GcpAesGcm.init()
    encrypted_password_hash = await aes_gcm.symmetric_encrypt(
        plaintext=password_hash,
        key_id=C.DATABASE_KEY,
    )
    return encrypted_password_hash

def get_min_message_timer(sender_user_doc: dict, receiver_user_doc: dict) -> int:
    """Returns the minimum message timer between the sender and receiver.

    Args:
        sender_user_doc (dict):
            The sender's user document.
        receiver_user_doc (dict):
            The receiver's user document.

    Returns:
        int:
            The minimum expiry interval. (0 if both users have message_timer set to 0 meaning no message timer)
    """
    sender_expiry_setting = sender_user_doc["chat"]["message_timer"]
    receiver_expiry_setting = receiver_user_doc["chat"]["message_timer"]

    if sender_expiry_setting == 0 or receiver_expiry_setting == 0:
        return max(sender_expiry_setting, receiver_expiry_setting)
    return min(sender_expiry_setting, receiver_expiry_setting)

def clean_filename(filename: str) -> str:
    """Cleans the filename.

    Args:
        filename (str):
            The filename to clean.

    Returns:
        str:
            The cleaned filename.
    """
    return C.FILENAME_BLACKLIST_REGEX.sub("-", filename).replace(" ", "_")

def get_rate_limiter_dependency(router_name: str) -> list[Depends] | None:
    """Gets the rate limiter dependency for the router.

    Args:
        router_name (str):
            The name of the router.

    Returns:
        list[Depends] | None:
            The rate limiter dependency for the router.
    """
    if C.DEBUG_MODE or not C.USE_REDIS:
        return None

    if router_name in C.RATE_LIMITER_TABLE:
        return [C.RATE_LIMITER_TABLE[router_name]]

    warnings.warn(
        message=f"Rate limiter not found for {router_name}, using default rate limiter instead.", 
        category=RuntimeWarning,
    )
    return [C.DEFAULT_RATE_LIMIT]