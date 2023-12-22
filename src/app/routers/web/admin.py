# import third-party libraries
from fastapi import (
    APIRouter, 
    Request,
    Depends,
)
from fastapi.responses import RedirectResponse
import pymongo

# import local Python libraries
from utils import constants as C
from utils.functions import (
    database as mongo,
    rbac,
    security as sec,
)
from utils.classes import (
    User, 
    Report, 
    Bans,
)
from .web_utils import render_template
from middleware import csp

# import Python's standard libraries
import logging

admin_router = APIRouter(
    include_in_schema=False,
    prefix="",
    dependencies=sec.get_rate_limiter_dependency(C.ADMIN_ROUTER),
    tags=["admins"],
)
RBAC_DEPENDENCY = Depends(rbac.ADMIN_RBAC, use_cache=False)

@admin_router.get("/admin")
async def admin_db(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    admin_db = rbac_res.admin_database
    num_of_current_users =  await mongo.get_account_count(db, "user")
    num_of_ban_logs = await mongo.get_ban_logs_counts(admin_db)
    num_of_report_logs = await mongo.get_report_logs_counts(admin_db)
    num_of_banned_users = await mongo.get_banned_users_counts(db)
    num_of_open_reports = await mongo.get_open_reports_counts(admin_db)
    current_user = rbac_res.user_doc
    current_user_username = current_user["username"]
    is_admin = True
    is_root = False

    logging.info(f" {current_user_username} has accessed the admin dashboard")
    return await render_template(
        name="admin/mod_dashboard.html",
        context={
            "request": request,
            "display_name": current_user["username"],
            "user_image_url": current_user["profile"]["image"]["url"],
            "current_users": num_of_current_users,
            "csp_nonce": csp.get_nonce(request),
            "is_admin": is_admin,
            "is_root": is_root,
            "num_of_ban_logs": num_of_ban_logs,
            "num_of_report_logs": num_of_report_logs,
            "num_of_banned_users": num_of_banned_users,
            "num_of_open_reports": num_of_open_reports,
        },
    )

# TODO: route for admin to take actions agaisnt the users
@admin_router.get("/admin/mirai/users")
async def admin_user_list(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    # import the suser class into the list
    db = rbac_res.database
    num_of_current_users =  await mongo.get_account_count(db, "user")
    user_dict = await mongo.get_all_users(db, "user")
    userlist = [await User.init(user_doc, rbac_res.database) for user_doc in user_dict]

    current_user = rbac_res.user_doc
    current_user_username = current_user["username"]
    is_admin = True
    is_root = False

    logging.info(f"{current_user_username} has accessed the admin user list")
    return await render_template(
        name="admin/user_list.html",
        context={
            "request": request,
            "display_name": current_user["username"],
            "user_image_url": current_user["profile"]["image"]["url"],
            "current_users": num_of_current_users,
            "userlist": userlist,
            "csp_nonce": csp.get_nonce(request),
            "is_admin": is_admin,
            "is_root": is_root,
        },
    )

@admin_router.get("/admin/mirai/reports")
async def admin_reports(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    # import the suser class into the list
    db = rbac_res.admin_database
    num_of_current_users =  await mongo.get_account_count(db, "user")
    cursor = db[C.REPORT_COLLECTION].find({
        "status": "open",
    })
    user_list = [Report(user_doc) async for user_doc in cursor]

    current_user = rbac_res.user_doc
    current_user_username = current_user["username"]
    is_admin = True
    is_root = False

    logging.info(f"{current_user_username} has accessed the admin reports")
    return await render_template(
        name="admin/reports.html",
        context={
            "request": request,
            "display_name": current_user["username"],
            "user_image_url": current_user["profile"]["image"]["url"],
            "current_users": num_of_current_users,
            "userlist": user_list,
            "csp_nonce": csp.get_nonce(request),
            "is_admin": is_admin,
            "is_root": is_root,
        },
    )

@admin_router.get("/admin/mirai/bans")
async def admin_ban(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    #import the suser class into the list
    db = rbac_res.admin_database

    num_of_current_users =  await mongo.get_account_count(db, "user")
    user_list = await mongo.get_all_bans(db)

    current_user = rbac_res.user_doc
    current_user_username = current_user["username"]

    # get the isadmin flag and is root flags
    is_admin = True
    is_root = False

    logging.info(f"{current_user_username} has accessed the admin ban list")
    return await render_template(
        name="admin/bans.html",
        context={
            "request": request,
            "display_name": current_user["username"],
            "user_image_url": current_user["profile"]["image"]["url"],
            "current_users": num_of_current_users,
            "userlist": user_list,
            "csp_nonce": csp.get_nonce(request),
            "is_admin": is_admin,
            "is_root": is_root,
        },
    )
