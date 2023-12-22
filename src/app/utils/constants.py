# import third-party libraries
from fastapi import Depends
from fastapi_limiter.depends import RateLimiter
from argon2 import (
    PasswordHasher, 
    Type as Argon2Type,
)

# import Python's standard libraries
import re
import pathlib
from collections import namedtuple

# Application constants
# TODO: Edit the following 3 flags when deploying to production
DEBUG_MODE = True
USE_REMOTE_DB = False 
if not DEBUG_MODE and not USE_REMOTE_DB:
    # just in case, you're like mumei and forgor
    USE_REMOTE_DB = True
USE_REDIS = False # Set to True in production if you want to use Redis 
                # for the rate limiter as it is expensive, only use it near the presentation date.
if USE_REDIS and DEBUG_MODE:
    USE_REDIS = False
MAINTENANCE_MODE = False
APP_ROOT_PATH = pathlib.Path(__file__).parent.parent.resolve()
FAVICON_PATH = APP_ROOT_PATH.joinpath("static", "favicon.ico")
ERROR_MSG = "An error has occurred, please try again later."
DOMAIN = "https://localhost:8080" if DEBUG_MODE else "https://miraisocial.live"
DOMAINS = (
    "http://localhost:8080",
    "https://localhost:8080",
    "https://miraisocial.live",
    "https://www.miraisocial.live",
    "https://mirai-gio6eqy5nq-as.a.run.app",
)
API_PREFIX = "/api"
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
FLASH_MESSAGES = "_messages"
EMAIL_ADDRESS = "notify.mirai@gmail.com"
NOREPLY_EMAIL_ADDRESS = "noreply@miraisocial.live"
LONG_RUNNING_TASK_TIMEOUT = 15 * 60 # 15 minutes
ERROR_TABLE = {
    400: {
        "title": "400 - Bad Request",
        "description": "The request was invalid"
    },
    401: {
        "title": "401 - Unauthorized",
        "description": "The requested resource is unauthorized"
    },
    403: {
        "title": "403 - Forbidden",
        "description": "The requested resource is forbidden"
    },
    404: {
        "title": "404 - Page Not Found",
        "description": "The requested resource was not found"
    },
    405: {
        "title": "405 - Method Not Allowed",
        "description": "The method is not allowed for the requested URL"
    },
    418: {
        "title": "I'm a teapot",
        "description": "I'm a teapot"
    },
    422: {
        "title": "422 - Unprocessable Entity",
        "description": "Unprocessable entity"
    },
    429: {
        "title": "429 - Too Many Requests",
        "description": "Too many requests, please slow down and try again later",
    },
    500: {
        "title": "500 - Internal Server Error",
        "description": "Internal server error"
    },
    503: {
        "title": "503 - Service Unavailable",
        "description": "Service unavailable"
    },
    504: {
        "title": "504 - Gateway Timeout",
        "description": "Gateway timeout"
    },
    505: {
        "title": "505 - HTTP Version Not Supported",
        "description": "HTTP version not supported"
    },
    511: {
        "title": "511 - Network Authentication Required",
        "description": "Network authentication required"
    },
}
BROWSER_TABLE = {
    "Chrome": "chrome_64x64.webp",
    "Edge": "edge_64x64.webp",
    "Firefox": "firefox_57-70_64x64.webp",
    "IE": "internet-explorer_9-11_64x64.webp",
    "Opera": "opera_64x64.webp",
    "Safari": "safari_64x64.webp",
    "Samsung Internet": "samsung-internet_64x64.webp",
}
BROWSER_TABLE["Chrome Mobile iOS"] = BROWSER_TABLE["Chrome"]

# Twilio
TWILIO_SID = "twilio-sid"
TWILIO_AUTH_TOKEN = "twilio-auth-token"

# For 2FA
SMS_TWO_FA_EXPIRY = 3600 # 1 hour
SMS_TWO_FA_RATE_LIMIT = 900 # 1 sms per 15 minutes
TWO_FA_TIMEOUT = 15 * 60 # 15 minutes
MAX_EMAIL_TOKENS_PER_IP = 3
MAX_EMAIL_TOKENS = MAX_EMAIL_TOKENS_PER_IP * 3
TWO_FA_TOKEN_EXPIRY = 8 * 60 # 8 minutes
LOCATION_TTL = 60 * 60 * 24 * 7 # 1 week
BACKUP_CODE_BYTES = 14
TWO_FA_TOKEN_BYTES = 12

# For HMAC signing
FORGOT_PASS_EXPIRY = 3600 # 1 hour
FORGOT_CHAT_PASS_EXPIRY = 30 * 60 # 30 minutes
UPLOAD_ID_EXPIRY = 3600 # 1 hour
EMAIL_VERIFICATION_EXPIRY = 86400 # 24 hours

# Email verification constants
EMAIL_BUTTON_STYLE = "background-color:#eaa7c7;width:min(250px,40%);border-radius:5px;color:white;padding:14px 25px;text-decoration:none;text-align:center;display:inline-block;"

# OAuth2 logins
FACEBOOK_CLIENT_ID = "669903787952531"

# Regex
HEX_REGEX_PATTERN = r"^[0-9a-f]+$"
BSON_OBJECTID_REGEX = HEX_REGEX_PATTERN
USERNAME_CHAR_WHITELIST_REGEX = re.compile(r"^[\w-]+$")
USERNAME_CHAR_WHITELIST = {chr(i) for i in range(48, 58)} | {chr(i) for i in range(65, 91)} | {chr(i) for i in range(97, 123)} | {"_", "-"}
RANGE_CONTENT_REGEX = re.compile(r"^bytes (\d+)-(\d+)/(\d+)$")
# from https://stackoverflow.com/questions/7406102/create-sane-safe-filename-from-any-unsafe-string/71199182#71199182
FILENAME_BLACKLIST_REGEX = re.compile(r"[/\\?%*:|\"<>\x7F\x00-\x1F]")
NRIC_REGEX = re.compile(r"[STFGM]\d{7}[A-Z]", flags=re.IGNORECASE)
CREDIT_CARD_REGEX = re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?(?:\d{4}[ -]?)?(?:\d{3})?\b")

# from https://stackoverflow.com/questions/72768/how-do-you-detect-credit-card-type-based-on-number

# added some regex here if want to use
DRIVERS_LICENSE_REGEX = re.compile(r"^[A-Z]{2}\d{7}$") #SG Drivers License
EMAIL_ADDRESS_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+.[a-zA-Z]{2,}$")
IPV4_ADDRESS_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

SG_STR_ADDR_REGEX = re.compile(r"\d{1,5} [\w\s]{1,30}(?: (?:Road|Street|Avenue|Lane|Drive|Close|Crescent|Way|Park|Link|View|Place|Heights|Green|Hill|Walk|Terrace|Block|Circle|Square|Rise|Grove|Valley|Gardens|Point|Boulevard|Esplanade)){1} #\d{1,4}-\d{1,2} [\w\s]{1,30} Singapore \d{6}", flags=re.IGNORECASE)
SSN_REGEX = re.compile(r"\d{3}-\d{2}-\d{4}") # social security number, United states

# Search constants
SEARCH_MAX_LENGTH = 100
SEARCH_RANDOM_QUERIES = (
    "amogus",
    "Mirai",
    "Nurture",
    "Touhou",
    "Hololive",
)

# Notification constants
FOLLOW_TYPE = "follow"
FOLLOW_MSG = "has followed you"
FOLLOW_REQUEST_MSG = "requested to follow you"
ACCEPTED_FOLLOW_REQUEST_MSG = "has accepted your follow request"
USER_ACCEPTED_FOLLOW_REQUEST_MSG = "is now following you"
LIKE_POST_TYPE = "like_post"
LIKE_POST_MSG = "has liked your post"
LIKE_COMMENT_TYPE = "like_comment"
LIKE_COMMENT_MSG = "has liked your comment"

# User profile constants
MAX_USERNAME_LENGTH = 25
MAX_BIO_LENGTH = 180
MAX_LOCATION_LENGTH = 25
MAX_WEBSITE_LENGTH = 1200

# Post constants
MAX_POST_LENGTH = (280, 400) # (free, mirai+)

# Chat constants
CHAT_MSG_LIMIT = 15 # for pagination
MAX_CHAT_MSG_LENGTH = (500, 1000) # (free, mirai+)
MESSAGE_TIMER_INT = {
    "disabled": 0,
    "1h": 3600,
    "24h": 86400,
    "7d": 604800,
    "1m": 2592000,
    "6m": 15768000,
    "1y": 31536000,
}
MESSAGE_TIMER_INT_TO_STR = {
    0: "disabled",
    3600: "1h",
    86400: "24h",
    604800: "7d",
    2592000: "1m",
    15768000: "6m",
    31536000: "1y",
}
MESSAGE_TIMER_STR = {
    "disabled": "Message Timer has been disabled.",
    "1h": "New messages will now be deleted after an hour.",
    "24h": "New messages will now be deleted after 24 hours.",
    "7d": "New messages will now be deleted after 7 days.",
    "1m": "New messages will now be deleted after 1 month.",
    "6m": "New messages will now be deleted after 6 months.",
    "1y": "New messages will now be deleted after 1 year.",
}

# Tailwind CSS components
__NODE_MODULES_PATH = APP_ROOT_PATH.parent.parent.joinpath("node_modules")
FLOWBITE_JS_PATH = __NODE_MODULES_PATH.joinpath("flowbite", "dist", "flowbite.js")
FLOWBITE_JS_MAP_PATH = __NODE_MODULES_PATH.joinpath("flowbite", "dist", "flowbite.js.map")
PRELINE_JS_PATH = __NODE_MODULES_PATH.joinpath("preline", "dist", "preline.js")
TW_ELEMENTS_JS_PATH = __NODE_MODULES_PATH.joinpath("tw-elements", "dist", "js", "index.min.js")
TW_ELEMENTS_JS_MAP_PATH = __NODE_MODULES_PATH.joinpath("tw-elements", "dist", "js", "index.min.js.map")

# Other npm packages
FILEPOND_JS_PATH = __NODE_MODULES_PATH.joinpath("filepond", "dist", "filepond.min.js")
FILEPOND_CSS_PATH = __NODE_MODULES_PATH.joinpath("filepond", "dist", "filepond.min.css")
FILEPOND_IMAGE_PREVIEW_JS_PATH = __NODE_MODULES_PATH.joinpath("filepond-plugin-image-preview", "dist", "filepond-plugin-image-preview.min.js")
FILEPOND_IMAGE_PREVIEW_CSS_PATH = __NODE_MODULES_PATH.joinpath("filepond-plugin-image-preview", "dist", "filepond-plugin-image-preview.min.css")
FILEPOND_EXIF_ORIENTATION_JS_PATH = __NODE_MODULES_PATH.joinpath("filepond-plugin-image-exif-orientation", "dist", "filepond-plugin-image-exif-orientation.min.js")
FILEPOND_VALIDATE_SIZE_JS_PATH = __NODE_MODULES_PATH.joinpath("filepond-plugin-file-validate-size", "dist", "filepond-plugin-file-validate-size.min.js")

# GCP Constants
GCP_PROJECT_NO = "638007043747"
GCP_PROJECT_ID = "ispj-mirai"
GCP_PROJECT_LOCATION = "asia-southeast1" if DEBUG_MODE else "global"

# GCP OAuth2 Client
WEB_OAUTH2_CLIENT = "web-oauth2-client"

# GCP Cloud functions URLs
EXPORT_DATA_URL_FUNCTION = "https://mirai-export-data-gio6eqy5nq-as.a.run.app"
CREATE_SIGNED_URL_FUNCTION = "https://create-signed-url-gio6eqy5nq-as.a.run.app"
PASSPORT_EYE_URL_FUNCTION = "https://passport-eye-gio6eqy5nq-as.a.run.app"
SEND_EMAIL_URL_FUNCTION = "https://send-email-gio6eqy5nq-as.a.run.app"

# GCP Cloud tasks
EXPORT_DATA_QUEUE = "export-user"

# reCAPTCHA Enterprise Site-keys
MIRAI_SITE_KEY = "6Lday1AjAAAAAAKK5UolpOjnukwC35uLDaFgL-7v"

# GCP Secrets Manager Secret IDs
LARGE_FILE_KEY = "large-files-key"

# KMS Key IDs
TOKEN_KEY = "token-key"
DATABASE_KEY = "database-key"

# Google Cloud Storage constants
ACCEPTED_IMAGE_MIMETYPES = (
    "image/jpeg",
    "image/png",
    "image/gif",
)
DEFAULT_BANNER = "https://storage.googleapis.com/mirai-public/banner-pics/default-banner.webp"
MAX_CHUNK_SIZE = 30 * 1024 * 1024 # 30 MB
MAX_IMAGE_PDF_SIZE = 10 * 1024 * 1024 # 10 MB
PREM_MAX_IMAGE_PDF_SIZE = 20 * 1024 * 1024 # 20 MB
MAX_FILE_SIZE = 50 * 1024 * 1024 # 50 MB
PREM_MAX_FILE_SIZE = 100 * 1024 * 1024 # 100 MB
MAX_VIDEO_SIZE = 500 * 1024 * 1024 # 500 MB
PREM_MAX_VIDEO_SIZE = 1000 * 1024 * 1024 # 1 GB
SIGNED_URL_EXPIRY = 15 * 60 # 15 minutes
POSTS_SIGNED_URL_EXPIRY = 60 * 60 # 1 hour
PUBLIC_BUCKET = "mirai-public"
PRIVATE_BUCKET = "mirai-confidential"
DEFAULT_CACHE_CONTROLS = "public, max-age=31536000, must-revalidate" # 1 year
CHAT_CACHE_CONTROLS = "private, no-store, no-cache"
PROFILE_IMAGES_CACHE_CONTROLS = "public, max-age=900" # 15 minutes

# Password Constants
ALLOWED_CHARS = r"A-Za-z\d!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^"
TWO_REPEAT_CHAR_REGEX = re.compile(
    fr"^(?!.*([{ALLOWED_CHARS}])\1{{2}}).+$"
)
LOWERCASE_REGEX = re.compile(r"[a-z]+")
UPPERCASE_REGEX = re.compile(r"[A-Z]+")
DIGIT_REGEX = re.compile(r"[\d]+")
SPECIAL_CHAR_REGEX = re.compile(r"[!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^]+")
ALLOWED_PASS_CHAR = re.compile(fr"^[{ALLOWED_CHARS}]{{1,}}$")
HASHER = PasswordHasher(
    encoding="utf-8",
    time_cost=4,         # 4 count of iterations
    salt_len=64,         # 64 bytes salt
    hash_len=64,         # 64 bytes hash
    parallelism=4,       # 4 threads
    memory_cost=64*1024, # 64MiB
    type=Argon2Type.ID   # using hybrids of Argon2i and Argon2d
)

# Roles
GUEST = "guest"
USER = "user"
GENERAL = (GUEST, USER)
ADMIN = "admin"
ROOT = "root"
MIRAI_PLUS = "mirai_plus"
ALLROLES= (GUEST, USER, ADMIN, ROOT, MIRAI_PLUS)

# Router names
GUEST_ROUTER = "guest_router"
USER_ROUTER = "user_router"
GENERAL_ROUTER = "general_router"
LENIENT_ROUTER = "lenient_router"
ADMIN_ROUTER = "admin_router"
ROOT_ROUTER = "root_router"
ERRORS_ROUTER = "errors_router"
MIRARI_PLUS_ROUTER = "mirai_plus_router"
ALLROLES_ROUTER = "allroles_router"

# Rate limits
# E.g. Limit to 10 requests every 15 seconds => RateLimiter(times=10, seconds=15)
DEFAULT_RATE_LIMIT = Depends(RateLimiter(times=10, seconds=15))
RATE_LIMITER_TABLE = {
    GENERAL_ROUTER: DEFAULT_RATE_LIMIT,
    GUEST_ROUTER: DEFAULT_RATE_LIMIT,
    USER_ROUTER: Depends(RateLimiter(times=20, seconds=10)),
    ADMIN_ROUTER: Depends(RateLimiter(times=25, seconds=10)),
    ROOT_ROUTER: Depends(RateLimiter(times=25, seconds=10)),
    ALLROLES_ROUTER: DEFAULT_RATE_LIMIT,
    LENIENT_ROUTER: Depends(RateLimiter(times=35, seconds=1)), # used for retrieving user's files
}

# MongoDB
DB_USERNAME_SECRET_ID = "mongodb-user"
DB_PASSWORD_SECRET_ID = "mongodb-pass"
ADMIN_DB_USERNAME_SECRET_ID = "mongodb-admin-user"
ADMIN_DB_PASSWORD_SECRET_ID = "mongodb-admin-pass"
DB_NAME = "Mirai"
ADMIN_DB_NAME = "Mirai_Admin"
USER_COLLECTION = "users"
ONE_TIME_TOKEN_COLLECTION = "one_time_tokens"
NOTIFICATION_COLLECTION = "notifications"
ADMIN_COLLECTION = "admins"
POST_COLLECTION = "posts"
COMMENTS_COLLECTION = "comments"
CHAT_COLLECTION = "chats"
DELETED_CHAT_COLLECTION = "deleted_chats"
FILE_ANALYSIS_COLLECTION = "file_analysis"
UPLOAD_IDS_COLLECTION = "upload_ids"
REPORT_COLLECTION = "reports"
BAN_COLLECTION = "ban_logs"
LOCK_COLLECTION = "lock_logs"
PAYMENT_COLLECTION = "payments"
MIRAI_SYSTEM_COLLECTION = "mirai_system"

# For seeding the admin accounts
ROOT_EMAIL = "notify.mirai@gmail.com"
ADMIN_EMAIL = "dummy99.mirai@gmail.com"

# Session
SESSION_COOKIE = "session"
SESSION_BYTES = 32
EXPIRY_ONCLOSE = "expire_onclose"
DO_NOT_REMEMBER_EXPIRY = 60 * 60 * 24 # 1 day
SESSION_EXPIRY = 60 * 60 * 24 * 7 # 7 days

# Followers
FOLLOWER_TYPE = namedtuple(
    typename="Follower_Type",
    field_names=("FOLLOWERS", "FOLLOWING", "PENDING", "REQUESTS"),
    defaults=("followers", "following", "pending", "requests"),
)()
FRIENDSHIP_TYPE = namedtuple(
    typename="Friendship_Type",
    field_names=("PUBLIC", "FOLLOWERS", "DISABLED", "CLOSE_FRIEND", "REQUEST_NEEDED", "UNDEFINED"),
    defaults=("public", "followers", "disabled", "close_friend", "request_needed", None),
)()

PERMISSIONS = namedtuple(
    typename="Permissions", 
    field_names=(
        "send_direct_messages",
        "be_follower",
        "see_posts",
        "search_indexed",
        "profile_location",
        "profile_url",
        "last_updated",
    )
)