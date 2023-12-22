# import third-party libraries
from fastapi import (
    APIRouter,
    Request,
    Depends,
)
from fastapi.responses import RedirectResponse

# import local Python libraries
from utils import constants as C
from utils.functions import (
    database as mongo,
    rbac,
    security as sec,
)
from .web_utils import render_template
from utils.classes import Admin
from middleware import csp

# import Python's standard libraries
import logging

maintenance_router = APIRouter(
    include_in_schema=False, 
    prefix="",
    dependencies=sec.get_rate_limiter_dependency(C.ROOT_ROUTER),
    tags=["root"],
)
RBAC_DEPENDENCY = Depends(rbac.ROOT_RBAC, use_cache=False)

@maintenance_router.get("/root")
async def maintenance_db(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.admin_database
    num_of_current_users =  await mongo.get_account_count(db, "admin")
    num_of_current_lock_logs = await mongo.get_locked_logs_counts(db)
    num_of_locked_admins = await mongo.get_locked_admins_counts(db)
    current_user = rbac_res.user_doc
    current_user_username = current_user["username"]

    is_admin = False
    is_root = True
    maintenance_status = await mongo.get_maintenance_mode(db)

    logging.info(f" {current_user_username} has accessed the maintenance dashboard")
    return await render_template(
        name="root/main_dashboard.html",
        context={
            "request": request,
            "display_name": current_user["username"],
            "user_image_url": current_user["profile"]["image"]["url"],
            "current_users": num_of_current_users,
            "csp_nonce": csp.get_nonce(request),
            "is_admin": is_admin,
            "is_root": is_root,
            "current_lock_logs": num_of_current_lock_logs,
            "current_locked_admins": num_of_locked_admins,
            "maintenance_status": maintenance_status,
        },
    )

#Maintenance create admin
@maintenance_router.get("/root/create/admin")
async def maintenance_create_admin(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    num_of_current_users =  await mongo.get_account_count(db, "user")

    current_user = rbac_res.user_doc
    current_user_username = current_user["username"]
    is_admin = False
    is_root = True

    logging.info(f" {current_user_username} has accessed the maintenance create admin")
    return await render_template(
        name="root/create_admin.html",
        context={
            "request": request,
            "display_name": current_user["username"],
            "user_image_url": current_user["profile"]["image"]["url"],
            "current_users": num_of_current_users,
            "csp_nonce": csp.get_nonce(request),
            "is_admin": is_admin,
            "is_root": is_root,
        },
    )

@maintenance_router.get("/root/admins")
async def get_admin(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.admin_database
    
    num_of_current_users =  await mongo.get_account_count(db, "user")
    user_dict = await mongo.get_all_users(db, "admin")
    user_list = [Admin(user_doc) for user_doc in user_dict]

    current_user = rbac_res.user_doc
    current_user_username = current_user["username"]
    is_admin = False
    is_root = True

    logging.info(f" {current_user_username} has accessed the maintenance dashboard")
    return await render_template(
        name="root/admin_list.html",
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

@maintenance_router.get("/root/locked/logs")
async def admin_locked(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    # import the suser class into the list
    db = rbac_res.admin_database
    num_of_current_users =  await mongo.get_account_count(db, "user")
    user_list = await mongo.get_all_locks(db)

    current_user = rbac_res.user_doc
    current_user_username = current_user["username"]
    # get the is admin flag and is root flags
    is_admin = False
    is_root = True

    logging.info(f" {current_user_username} has accessed the admin locked logs list")
    return await render_template(
        name="root/locked_logs.html",
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

@maintenance_router.get("/root/maintenance")
async def maintenance_mode(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    # import the suser class into the list
    db = rbac_res.admin_database
    num_of_current_users =  await mongo.get_account_count(db, "user")
    user_list = await mongo.get_all_locks(db)

    current_user = rbac_res.user_doc
    current_user_username = current_user["username"]

    # get the is admin flag and is root flags
    is_admin = False
    is_root = True
    maintenance_status = await mongo.get_maintenance_mode(db)

    logging.info(f" {current_user_username} has accessed the admin locked logs list")
    return await render_template(
        name="root/maintenance_mode.html",
        context={
            "request": request,
            "display_name": current_user["username"],
            "user_image_url": current_user["profile"]["image"]["url"],
            "current_users": num_of_current_users,
            "userlist": user_list,
            "csp_nonce": csp.get_nonce(request),
            "is_admin": is_admin,
            "is_root": is_root,
            "maintenance_status": maintenance_status,
        },
    )