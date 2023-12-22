# import third-party libraries
import orjson
import redis.asyncio as redis
from fastapi import FastAPI
from fastapi.responses import (
    FileResponse, 
    ORJSONResponse,
)
from fastapi.exceptions import HTTPException
from fastapi.staticfiles import StaticFiles
from starlette.routing import Mount
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from google.cloud import logging as gcp_logging
from fastapi_limiter import FastAPILimiter

# import local Python libraries
from utils import constants as C
from middleware import (
    SessionMiddleware, 
    CacheControlMiddleware,
    CacheControlURLRule,
    add_app_exception_handlers,
    CSRFMiddleware,
    ContentSecurityPolicy,
    StrictTransportSecurity,
    XSSProtection,
    ContentTypeOptions,
    XFrameOptions,
    ReferrerPolicy,
    ExpectCT,
)
from gcp import (
    CloudFunction,
    EmailCloudFunction,
    CloudTasks,
    GoogleComputerVision,
    GoogleNLP,
    GcpAesGcm,
    GcpKms,
    SecretManager,
    CloudStorage,
    WebRisk,
    RecaptchaEnterprise,
)
from utils.classes import (
    TwilioAPI,
    StripeSubscription,
    hmac,
)
from utils.functions import (
    ipinfo,
    database,
    useful,
)
import routers

# import Python's standard libraries
import re
import asyncio
import logging

app = FastAPI(
    title="Mirai",
    debug=C.DEBUG_MODE,
    version="1.0.0",
    routes=[
        Mount(
            path="/static", 
            app=StaticFiles(
                directory=str(C.APP_ROOT_PATH.joinpath("static"))
            ), 
            name="static"
        ),
    ],
    default_response_class=ORJSONResponse,
    docs_url="/docs" if C.DEBUG_MODE else None,
    redoc_url="/redoc" if C.DEBUG_MODE else None,
    openapi_url="/openapi.json" if C.DEBUG_MODE else None,
    openapi_tags=[
        {
            "name": "users",
            "description": "API Routes that logged in Mirai users can access.",
        },
        {
            "name": "guests",
            "description": "API Routes that guests can access.",
        },
        {
            "name": "general",
            "description": "API Routes that only guests or logged in users can access.",
        },
        {
            "name": "all_roles",
            "description": "API Routes that all roles can access including admins.",
        },
        {
            "name": "lenient",
            "description": "API Routes that all roles can access including admins, but they have a more lenient rate limit.",
        },
        {
            "name": "admins",
            "description": "API Routes that only admins can access.",
        },
        {
            "name": "root",
            "description": "API Routes that only the root can access.",
        },
    ],
    swagger_ui_oauth2_redirect_url=None,
)

@app.on_event("startup")
async def startup() -> None:
    secrets = ("gcp-logging", "redis-password", "virustotal-api-key")
    if C.DEBUG_MODE:
        secret_manager = await SecretManager.init()
        gcp_logging_info, redis_password, vt_api_key = await asyncio.gather(*[
            secret_manager.get_secret_payload_async(
                secret_id=secret_id,
            ) for secret_id in secrets
        ])
    else:
        secret_manager = SecretManager()
        gcp_logging_info, redis_password, vt_api_key = [
            secret_manager.get_secret_payload(
                secret_id=secret_id,
            ) for secret_id in secrets
        ]

    obj_init_tasks = [
        RecaptchaEnterprise.init(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
        CloudFunction.init(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
        EmailCloudFunction.init(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
        CloudTasks.init(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
        GoogleComputerVision.init(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
        GoogleNLP.init(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
        GcpAesGcm.init(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
        GcpKms.init(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
        CloudStorage.init(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
        WebRisk.init(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
        ipinfo.get_ipinfo_handler(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
        TwilioAPI.init(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
        StripeSubscription.init(
            secret_manager=secret_manager,
            async_mode=C.DEBUG_MODE,
        ),
    ]
    obj_arr = await asyncio.gather(*obj_init_tasks)
    obj_map = {_obj.__class__: _obj for _obj in obj_arr}
    obj_map[SecretManager] = secret_manager
    app.state.obj_map = obj_map

    if C.USE_REDIS:
        # Note that the Redis client does not encrypt data before transmitting it to the Redis server.
        redis_client = redis.Redis(
            host="redis-16894.c23537.asia-seast2-mz.gcp.cloud.rlrcp.com",
            password=redis_password,
            port=16894,
            encoding="utf-8", 
            decode_responses=True,
            socket_keepalive=False,
        )
        await FastAPILimiter.init(
            redis=redis_client,
            identifier=useful.redis_rate_limiter_identifier,
        )

    # Add a GCP logging client to the FastAPI app
    gcp_logging_client = gcp_logging.Client.from_service_account_info(
        info=orjson.loads(gcp_logging_info),
    )
    gcp_logging_client.setup_logging(
        log_level=logging.INFO,
    )

    # add a state to the FastAPI app for 
    # connected user ids array and VirusTotal client
    app.state.vt_api_key = vt_api_key
    app.state.chat_connected_users = set()

@app.on_event("shutdown")
async def shutdown() -> None:
    # Only works if reload is set to False
    db = database.get_db_client()
    try:
        user_col = db[C.USER_COLLECTION]
        await user_col.update_many(
            filter={
                "_id": {"$in": list(app.state.chat_connected_users)},
                "chat.status": "online",
            },
            update={"$set": {"status": "offline"}},
        )
    finally:
        db.client.close()

"""--------------------------- Start of App Routes ---------------------------"""

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(C.FAVICON_PATH)

@app.get("/js/tailwind/flowbite/flowbite.js", include_in_schema=False)
async def flowbite_js():
    return FileResponse(C.FLOWBITE_JS_PATH)

@app.get("/js/tailwind/flowbite/flowbite.js.map", include_in_schema=False)
async def flowbite_js_map():
    return FileResponse(C.FLOWBITE_JS_MAP_PATH)

@app.get("/js/tailwind/preline/preline.js", include_in_schema=False)
async def preline_js():
    return FileResponse(C.PRELINE_JS_PATH)

@app.get("/js/tailwind/tw-elements/index.min.js", include_in_schema=False)
async def tw_elements_js():
    return FileResponse(C.TW_ELEMENTS_JS_PATH)

@app.get("/js/tailwind/tw-elements/index.min.js.map", include_in_schema=False)
async def tw_elements_js_map():
    return FileResponse(C.TW_ELEMENTS_JS_MAP_PATH)

@app.get("/js/filepond/filepond.min.js", include_in_schema=False)
async def filepond_js():
    return FileResponse(C.FILEPOND_JS_PATH)

@app.get("/css/filepond/filepond.min.css", include_in_schema=False)
async def filepond_css():
    return FileResponse(C.FILEPOND_CSS_PATH)

@app.get("/js/filepond/filepond-plugin-image-preview.min.js", include_in_schema=False)
async def filepond_plugin_image_preview_js():
    return FileResponse(C.FILEPOND_IMAGE_PREVIEW_JS_PATH)

@app.get("/css/filepond/filepond-plugin-image-preview.min.css", include_in_schema=False)
async def filepond_plugin_image_preview_css():
    return FileResponse(C.FILEPOND_IMAGE_PREVIEW_CSS_PATH)

@app.get("/js/filepond/filepond-plugin-image-exif-orientation.min.js", include_in_schema=False)
async def filepond_plugin_image_exif_orientation_js():
    return FileResponse(C.FILEPOND_EXIF_ORIENTATION_JS_PATH)

@app.get("/js/filepond/filepond-plugin-file-validate-size.min.js", include_in_schema=False)
async def filepond_plugin_file_validate_size_js():
    return FileResponse(C.FILEPOND_VALIDATE_SIZE_JS_PATH)

@app.get("/teapot", include_in_schema=False)
async def teapot():
    raise HTTPException(status_code=418)

# API routers
app.include_router(routers.allroles_api)
app.include_router(routers.guest_api)
app.include_router(routers.user_api)
app.include_router(routers.general_api)
app.include_router(routers.lenient_api)
app.include_router(routers.root_api)
app.include_router(routers.admin_api)

# Web routers
app.include_router(routers.allroles_router)
app.include_router(routers.general_router)
app.include_router(routers.admin_router)
app.include_router(routers.maintenance_router)
app.include_router(routers.guest_router)
app.include_router(routers.user_router)
app.include_router(routers.guest_router)

"""--------------------------- End of App Routes ---------------------------"""

"""--------------------------- Start of App Middleware ---------------------------"""

add_app_exception_handlers(app)
app.add_middleware(
    GZipMiddleware,
    minimum_size=500,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        C.DOMAIN,
        "https://www.miraisocial.live",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    SessionMiddleware,
    signer=hmac.get_hmac_signer(
        max_age=C.SESSION_EXPIRY,
    ),
    session_cookie="session",
    https_only=True,
    max_age=C.SESSION_EXPIRY,
)
app.add_middleware(
    ContentSecurityPolicy,
    script_nonce=True,
    csp_options={
        "script-src": [
            "'self'",
            "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.13.0/js/all.min.js",
            "https://www.google.com/recaptcha/enterprise.js",
            "https://cdn.enzoic.com/js/enzoic.min.js",
            "https://cdnjs.cloudflare.com/ajax/libs/intl-tel-input/17.0.8/js/intlTelInput.min.js",
            "https://cdn.plyr.io/3.7.3/plyr.polyfilled.js",
            "https://cdn.jsdelivr.net/npm/@justinribeiro/lite-youtube@1.4.0/lite-youtube.js",
            "https://platform.twitter.com",
            "https://cdnjs.cloudflare.com/ajax/libs/intl-tel-input/17.0.9/js/utils.js",
        ],
        "style-src": [
            "'self'",
            "'unsafe-inline'",
            "https:",
            "https://cdn.plyr.io/3.7.3/plyr.css",
            "https://cdnjs.cloudflare.com/ajax/libs/intl-tel-input/17.0.9/css/intlTelInput.css",
            "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.1/css/all.min.css",
        ], 
        "worker-src":[
            "'self'",
            "blob:",
        ],
    },
    exempt_routes=[app.openapi_url, app.docs_url, app.redoc_url] if C.DEBUG_MODE else None,
)
app.add_middleware(
    XSSProtection,
)
app.add_middleware(
    ContentTypeOptions,
)
app.add_middleware(
    XFrameOptions,
)
app.add_middleware(
    ReferrerPolicy,
)
app.add_middleware(
    ExpectCT,
)
if not C.DEBUG_MODE:
    app.add_middleware(
        StrictTransportSecurity,
    )
    app.add_middleware(
        CSRFMiddleware,
        signer=hmac.get_hmac_signer(
            max_age=C.SESSION_EXPIRY,
        ),
        cookie_name=C.CSRF_COOKIE_NAME,
        max_age=C.SESSION_EXPIRY,
        samesite="Lax",
        secure=True,
        csrf_length=64,
    )
    app.add_middleware(
        CacheControlMiddleware,
        routes=[
            CacheControlURLRule(
                path=re.compile(r"^/static/.*$"),
                cache_control="public, max-age=31536000, must-revalidate",
            ),
            CacheControlURLRule(
                path=re.compile(r"^/js/tailwind/.*$"),
                cache_control="public, max-age=31536000, must-revalidate",
            ),
            CacheControlURLRule(
                path=re.compile(r"^/js/filepond/.*$|^/css/filepond/.*$"),
                cache_control="public, max-age=86400, must-revalidate",
            ),
            CacheControlURLRule(
                path="/favicon.ico",
                cache_control="public, max-age=31536000, must-revalidate",
            ),
        ],
    )
else:
    app.add_middleware(
        HTTPSRedirectMiddleware,
    )

"""--------------------------- End of App Middleware ---------------------------"""

if __name__ == "__main__":
    import uvicorn
    cert_path = C.APP_ROOT_PATH.joinpath("app-cert.pem")
    private_key_path = C.APP_ROOT_PATH.joinpath("app-private-key.pem")
    uvicorn.run(
        "main:app", 
        host="localhost", 
        port=8080,
        reload=True,
        log_level="debug",
        ssl_keyfile=str(private_key_path),
        ssl_certfile=str(cert_path),
    )