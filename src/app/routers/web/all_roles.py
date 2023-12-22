# import third-party libraries
from fastapi import (
    APIRouter,
    Request,
    Depends,
)
from fastapi.responses import (
    RedirectResponse,
)

# import local Python libraries
from utils.functions import (
    rbac,
    security as sec,
    useful,
)
from utils import constants as C
from .web_utils import render_template
from utils.classes import (
    User,
    VtAnalysis,
)
from middleware import csp
import logging
from gcp import (
    WebRisk,
)

# import Python's standard libraries
import asyncio
import urllib.parse as urlparse

allroles_router = APIRouter(
    include_in_schema=False,
    prefix="",
    dependencies=sec.get_rate_limiter_dependency(C.ALLROLES_ROUTER),
    tags=["all_roles"],
)
RBAC_DEPENDENCY = Depends(rbac.ALLROLES_RBAC, use_cache=False)

@allroles_router.get("/")
async def index(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    current_user = None
    if rbac_res.user_doc is not None:
        current_user = rbac_res.user_doc
        current_role: list[str] = current_user["security"]["role"]

        if "admin" in current_role:
            logging.info(
                f"Admin, #{current_user['_id']}, logged in sucessfully, redirecting...",
            )
            return RedirectResponse(
                url=useful.url_for(request, "admin_db"),
            )
        if "root" in current_role:
            logging.info(
                f"Maintenance, #{current_user['_id']}, logged in sucessfully, redirecting...",
            )
            return RedirectResponse(
                url=useful.url_for(request, "maintenance_db"),
            )
        if "user" in current_role:
            current_user = await User.init(current_user, rbac_res.database)

    return await render_template(
        name="general/home.html",
        context={
            "request": request,
            "user":current_user,
            "csp_nonce": csp.get_nonce(request),
        },
    )

@allroles_router.get("/logout")
async def web_logout(request: Request, _: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    return RedirectResponse(url=useful.url_for(request, "logout"))

DELIMITER = "url="
@allroles_router.get("/redirect")
async def redirect_confirmation(
    request: Request,
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    params = str(request.query_params)
    if not params.startswith(DELIMITER):
        return RedirectResponse(url=useful.url_for(request, "index"))

    if len(params) > C.MAX_WEBSITE_LENGTH:
        return RedirectResponse(url=useful.url_for(request, "index"))

    url = params[len(DELIMITER):]
    splitted_url = url.rsplit(sep="?", maxsplit=1)
    url = urlparse.unquote(splitted_url[0])
    if len(splitted_url) == 2: # there can only be up to two elements max due to maxsplit=1
        url += "?" + splitted_url[1]

    is_own_domain = url.startswith("/")
    for domain in C.DOMAINS:
        url_copy = url
        if url.startswith(domain):
            is_own_domain = True
            url_copy = url_copy.replace(domain, "", 1)

        url_copy = url_copy.rsplit(sep="?", maxsplit=1)[0].rsplit(sep="#", maxsplit=1)[0]
        if url_copy in ("/logout", "/api/logout", "/redirect"):
            # to prevent trolls
            return RedirectResponse(url=useful.url_for(request, "index"))

        if is_own_domain:
            break
    else:
        if not useful.check_if_str_is_url(url):
            return RedirectResponse(url=useful.url_for(request, "index"))

    if is_own_domain:
        return RedirectResponse(url=url)

    db = rbac_res.database
    malicious = False
    col = db[C.FILE_ANALYSIS_COLLECTION]
    url_to_check = url.rsplit(sep="#", maxsplit=1)[0]
    analysis_doc = await col.find_one(
        {"identifier": url_to_check},
    )

    # If a result is found : Check what the result states
    if analysis_doc is None:
        vt_api_key: str = request.app.state.vt_api_key
        async with VtAnalysis(vt_api_key) as vt_client:
            web_risk: WebRisk = request.app.state.obj_map[WebRisk]
            url_checks = await asyncio.gather(*[
                web_risk.search_uri(url_to_check),
                vt_client.check_link(url_to_check, col),
            ])
            malicious = any(url_checks)

    if analysis_doc is not None:
        malicious = analysis_doc["malicious"]

    user = None
    if rbac_res.user_doc is not None:
        user = await User.init(rbac_res.user_doc, db)

    return await render_template(
        name="general/redirect_confirmation.html",
        context={
            "request": request,
            "url": url,
            "malicious": malicious,
            "user": user,
            "csp_nonce": csp.get_nonce(request),
        },
    )