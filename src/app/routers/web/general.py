# import third-party libraries
from pymongo.collation import Collation, CollationStrength
from fastapi import (
    APIRouter,
    Request,
    Depends,
    Query,
)
from fastapi.responses import RedirectResponse
from fastapi.exceptions import HTTPException
import bson

# import local Python libraries
from utils.functions import (
    rbac,
    security as sec,
)
from utils import constants as C
from utils.functions import useful
from .web_utils import render_template
from utils.classes import (
    User,
)
import schemas
from middleware import csp

# import Python's standard libraries
import random
import html

general_router = APIRouter(
    include_in_schema=False,
    prefix="",
    dependencies=sec.get_rate_limiter_dependency(C.GENERAL_ROUTER),
    tags=["general"],
)
RBAC_DEPENDENCY = Depends(rbac.GENERAL_RBAC, use_cache=False)

@general_router.get("/search")
async def search(
    request: Request,
    q: str = Query(
        default="",
        min_length=0,
    ),
    search_type: schemas.SearchType = Query(
        default=schemas.SearchType.POST,
        description="The type of search to perform.",
    ),
    offset: str | None = Query(
        default=None,
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
        description="The offset of the search results using a user's ID",
    ),
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    q = q.strip()
    if q == "":
        random_query = random.choice(C.SEARCH_RANDOM_QUERIES)
        return RedirectResponse(url=useful.url_for(request, "search") + f"?q={random_query}")

    if len(q) > C.SEARCH_MAX_LENGTH:
        q = q[:C.SEARCH_MAX_LENGTH]

    user = None
    if rbac_res.user_doc is not None:
        current_user = rbac_res.user_doc
        user = await User.init(current_user, rbac_res.database)

    return await render_template(
        name="general/search_results.html",
        context={
            "request": request,
            "query": q,
            "search_type": search_type.value,
            "offset": offset,
            "csp_nonce": csp.get_nonce(request),
            "user": user,
        },
    )

@general_router.get("/profile/{username}")
async def profile(request: Request, username: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    user_doc = await col.find_one(
        filter={"username": username},
        collation=Collation(locale="en", strength=CollationStrength.PRIMARY),
    )

    current_user = None
    if rbac_res.user_doc is not None:
        current_user = await User.init(rbac_res.user_doc, db)
    if user_doc is None or user_doc["banned"]:
        return await render_template(
            name="general/user_not_found.html",
            context={
                "request": request,
                "username": username,
                "user": current_user,
                "banned": user_doc["banned"] if user_doc else False,
                "csp_nonce": csp.get_nonce(request),
            },
        )
    user_viewed = User(user_doc)
    user_viewed_id = bson.ObjectId(user_viewed.id)

    user_following = None
    social_button_type = None
    blocked_by = None
    public_permissions = None

    if current_user is not None:
        user_following = current_user.following_list
        if user_viewed.id in current_user.requests_list:
            social_button_type = "requests"
        elif user_viewed.id in current_user.following_list:
            social_button_type = "followed"
        else:
            social_button_type = "unfollowed"

        # Current user is blocked?
        blocked_by = await col.find_one({
            "$or": [
                {"_id": current_user.id, "blocked_users": user_viewed_id},
                {"_id": user_viewed_id, "blocked_users": current_user.id},
            ],
        })
        if blocked_by:
            blocked_by = "viewed" \
                        if blocked_by["_id"] == user_viewed_id \
                        else "current"
        public_permissions = any(privacy == C.FRIENDSHIP_TYPE.PUBLIC for privacy in current_user.privacy)

    allowed_permissions = useful.evaluate_permissions(
        target_id=user_viewed.id,
        target_privacy=user_viewed.privacy,
        user_following=user_following if rbac_res.user_doc else [],
    )

    num_of_posts = await db[C.POST_COLLECTION].count_documents({
        "user_id": user_viewed_id,
    })

    user_map = {}
    if current_user is not None:
        user_map = {
            "username" : current_user.display_name,
            "description" : current_user.bio,
            "location" : current_user.location,
            "url" : current_user.url,
        }
    return await render_template(
        name="general/user_profile.html",
        context={
            "request": request,
            "is_ownself": (current_user and current_user.id == user_viewed.id),
            "allowed_permissions": allowed_permissions,
            "public_permissions": public_permissions,
            "blocked_by": blocked_by,
            "social_button_type": social_button_type,
            "user": current_user,
            "num_of_posts": num_of_posts,
            "user_map": useful.format_json_response(user_map, dump_json=True),
            "user_viewed": user_viewed,
            "csp_nonce": csp.get_nonce(request),
        },
    )

@general_router.get("/post/{post_id}")
async def individual_post_redirect(request: Request, post_id: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    post_doc = await db[C.POST_COLLECTION].find_one({"_id": bson.ObjectId(post_id)})
    if post_doc is None:
        raise HTTPException(status_code=404, detail="Post not found")

    post_user = await col.find_one({"_id": bson.ObjectId(post_doc["user_id"])})
    if post_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return RedirectResponse(
        url=useful.url_for(request, "individual_post", username=post_user["username"], post_id=post_id),
    )

@general_router.get("/{username}/post/{post_id}")
async def individual_post(request: Request, username: str, post_id: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    col = db[C.USER_COLLECTION]
    current_user = None

    if rbac_res.user_doc is not None:
        col = db[C.USER_COLLECTION]
        current_user = await User.init(rbac_res.user_doc, rbac_res.database)

    post_user = await col.find_one(
        filter={"username": username},
        collation=Collation(locale="en", strength=CollationStrength.PRIMARY),
    )
    if post_user is None:
        return RedirectResponse(url="/")

    post_user = User(post_user)
    allowed_permissions = useful.evaluate_permissions(
        target_id=post_user.id,
        target_privacy=post_user.privacy,
        user_following=current_user.following_list if current_user else [],
    )

    is_ownself = False
    is_blocked = False
    if current_user is not None:
        is_ownself = (current_user == post_user)

        is_blocked = await col.find_one({
            "$or": [
                {"_id": rbac_res.user_doc["_id"], "blocked_users": post_user.id},
                {"_id": post_user.id, "blocked_users": rbac_res.user_doc["_id"]},
            ],
        })

    if is_blocked or not (is_ownself or allowed_permissions.see_posts):
        raise HTTPException(
            status_code=404,
            detail="Post not found",
        )

    col = db[C.POST_COLLECTION]
    post_doc = await col.find_one(
        filter={"_id": bson.ObjectId(post_id)},
        collation=Collation(locale="en", strength=CollationStrength.PRIMARY),
    )
    if post_doc is None:
        raise HTTPException(status_code=404, detail="Post not found")

    post_doc.update({
        "username": post_user.username,
        "display_name": html.escape(post_user.display_name, quote=False),
        "profile_image": post_user.profile_image,
        "mirai_plus": post_user.mirai_plus,
    })
    doc = useful.format_json_response(post_doc, dump_json=True, escape=False)
    return await render_template(
        name="general/mirai_post.html",
        context={
            "request": request,
            "post_id": post_id,
            "user": current_user,
            "post_user": post_user,
            "post_doc": doc,
            "has_liked": (current_user.id in post_doc.get("likes", [])) if current_user else False,
            "csp_nonce": csp.get_nonce(request),
        },
    )

@general_router.get("/social/{follower_type}/{username}")
async def other_user_followers(request: Request, follower_type: str, username: str, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    if follower_type not in (C.FOLLOWER_TYPE.FOLLOWERS, C.FOLLOWER_TYPE.FOLLOWING):
        return RedirectResponse(
            useful.url_for(
                request=request, 
                name="other_user_followers", 
                username=username, 
                follower_type=C.FOLLOWER_TYPE.FOLLOWERS,
            ))

    context = {
        "request": request,
        "csp_nonce": csp.get_nonce(request),
        "current": follower_type,
    }

    if rbac_res.user_doc is not None:
        current_user = await User.init(rbac_res.user_doc, rbac_res.database)
        context["user"] = current_user

        if rbac_res.user_doc and username == current_user.username:
            return RedirectResponse(
                useful.url_for(
                    request=request,
                    name="followers",
                    follower_type=C.FOLLOWER_TYPE.FOLLOWERS,
                ),
            )

    user_col = rbac_res.database[C.USER_COLLECTION]
    viewed_user = await user_col.find_one(
        filter={"username": username}
    )

    if not viewed_user:
        raise HTTPException(
            status_code=404,
            detail="Username not found."
        )

    context["viewed_user"] = viewed_user
    return await render_template(
        name="general/followers.html",
        context=context,
    )