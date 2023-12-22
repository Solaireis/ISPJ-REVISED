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
    rbac,
    security as sec,
)

# import Python's standard libraries
import logging

allroles_api = APIRouter(
    include_in_schema=True,
    prefix="",
    dependencies=sec.get_rate_limiter_dependency(C.ALLROLES_ROUTER),
    tags=["all_roles"],
)
RBAC_DEPENDENCY = Depends(rbac.ALLROLES_RBAC, use_cache=False)

@allroles_api.get(
    path="/logout",
    description="Removes the session from the database and delete the session cookie.",
    summary="Logout from Mirai.",
)
async def logout(request: Request, rbac_res: rbac.RBACResults = RBAC_DEPENDENCY):
    if request.session.get(C.SESSION_COOKIE) is None:
        return RedirectResponse(url="/")

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    session_id = request.session.get(C.SESSION_COOKIE)
    user_doc = await col.find_one_and_update(
        {"sessions.session_id": session_id},
        {"$pull":
            {"sessions":
                {"session_id": session_id},
            },
        },
    )
    if user_doc is None: # means that the user is an admin or root
        admin_db = rbac_res.admin_database
        admin_col = admin_db[C.ADMIN_COLLECTION]
        user_doc = await admin_col.find_one_and_update(
            {"sessions.session_id": session_id},
            {"$pull":
                {"sessions":
                    {"session_id": session_id},
                },
            },
        )

        # check if the user was an admin or root
        role_arr = user_doc["security"]["role"]
        if "admin" in role_arr:
            logging.info(f"Admin Id: {user_doc['_id']}, Admin Username: {user_doc['username']} logged out.")
        elif "root" in role_arr:
            logging.info(f"Root Id: {user_doc['_id']}, Root Username: {user_doc['username']} logged out.")

    request.session.clear()
    return RedirectResponse(url="/")