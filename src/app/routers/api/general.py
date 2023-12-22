# import third-party libraries
import pymongo
import bson
from pymongo.cursor import Cursor
from pymongo.collection import Collection
from pymongo.collation import (
    Collation, 
    CollationStrength,
)
from fastapi import (
    APIRouter, 
    Request, 
    Query,
    Depends,
)
from fastapi.responses import (
    RedirectResponse,
    ORJSONResponse,
)

# import local Python libraries
from utils import constants as C
from utils.functions import (
    rbac,
    security as sec,
    useful,
)
import schemas
from utils.functions.oauth2 import (
    get_facebook_sso, 
    get_google_sso, 
    process_oauth_callback,
)

# import Python's standard libraries
import html

general_api = APIRouter(
    include_in_schema=True,
    prefix=C.API_PREFIX,
    dependencies=sec.get_rate_limiter_dependency(C.GENERAL_ROUTER),
    tags=["general"],
)
RBAC_DEPENDENCY = Depends(rbac.GENERAL_RBAC, use_cache=False)

@general_api.get(
    path="/get/post",
    description="Gets the next (few) posts from the database.",
    summary="Get posts from Mirai.",
)
async def get_post(
    request: Request,
    offset: str | None = Query(
        default=None,
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
        description="The offset of the post results using a post's ID",
    ),
    user_id: str | None = Query(
        default=None,
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
        description="To limit the results to a specific user's posts",
    ),
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    db = rbac_res.database
    post_col = db[C.POST_COLLECTION]

    _filter = {}
    if offset is not None:
        _filter.update({
            "_id": {
                "$lt": bson.ObjectId(offset),
            },
        })

    if user_id is not None:
        _filter.update({"user_id": bson.ObjectId(user_id)})

    user_col = db[C.USER_COLLECTION]
    limit = 7
    post_list = []
    cached_user_info = {}
    async with post_col.find(_filter).sort("_id", pymongo.DESCENDING) as cursor:
        async for doc in cursor:
            if len(post_list) >= limit:
                break

            user_id_str = str(doc["user_id"])
            if user_id_str not in cached_user_info:
                matched_user = await user_col.find_one({"_id": doc["user_id"]})
                if matched_user is None:
                    continue

                allowed_permissions = useful.evaluate_permissions(
                    target_id=doc["user_id"],
                    target_privacy=matched_user["privacy"],
                    user_following=rbac_res.user_doc["social"]["following"] if rbac_res.user_doc else [],
                )
                if not allowed_permissions.see_posts and matched_user != rbac_res.user_doc:
                    continue

                cached_user_info[user_id_str] = {
                    "banned": matched_user["banned"],
                    "username": matched_user["username"],
                    "display_name": matched_user["display_name"],
                    "profile_image": matched_user["profile"]["image"]["url"],
                    "mirai_plus": matched_user["mirai_plus"],
                }
            if cached_user_info[user_id_str]["banned"]:
                continue
            doc.update(cached_user_info[user_id_str])

            if rbac_res.user_doc is not None:
                if rbac_res.user_doc["_id"] != doc["user_id"]:
                    blocked = await user_col.find_one({
                        "$or": [
                            {"_id": rbac_res.user_doc["_id"], "blocked_users": doc["user_id"]},
                            {"_id": doc["user_id"], "blocked_users": rbac_res.user_doc["_id"]},
                        ]
                    })
                    if blocked:
                        continue
                doc.update({"has_liked": (rbac_res.user_doc.get("_id") in doc.get("likes", [])) if rbac_res.user_doc.get("_id") else False})

            doc = useful.format_json_response(doc)
            if "description" in doc and doc["description"] is not None:
                # We will be using DOMPurify to sanitize the HTML client-side
                doc["description"] = html.unescape(doc["description"])

            post_list.append(doc)

    return post_list

@general_api.get(
    path="/get/comments",
    description="Gets the next (few) comments from the database.",
    summary="Get comments from Mirai.",
)
async def get_comments(
    request: Request,
    offset: str | None = Query(
        default=None,
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
        description="The offset of the comment results using a comment's ID",
    ),
    user_id: str | None = Query(
        default=None,
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
        description="To limit the results to a specific user's comments",
    ),
    post_id: str | None = Query(
        default=None,
        min_length=24,
        max_length=24,
        regex=C.BSON_OBJECTID_REGEX,
        description="The post ID to get the comments for",
    ),
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY,
):
    db = rbac_res.database
    comments_col = db[C.COMMENTS_COLLECTION]
    post_col = db[C.POST_COLLECTION]
    user_col = db[C.USER_COLLECTION]

    _filter = {}
    post_user = None
    post_id_is_empty = True
    if post_id is not None:
        post_id_is_empty = False
        post_id_obj = bson.ObjectId(post_id)
        post_doc = await post_col.find_one(
            filter={"_id": post_id_obj}, 
            projection={
                "user_id": 1,
            },
        )
        if post_doc is None:
            return ORJSONResponse(
                status_code=404,
                content={"error": "Post not found"},
            )

        post_user = await user_col.find_one(
            filter={"_id": post_doc["user_id"]},
            projection={
                "username": 1,
            }
        )
        if post_user is None:
            return ORJSONResponse(
                status_code=404,
                content={"error": "Owner of the post not found"},
            )
        _filter.update({"post_id": post_id_obj})

    if offset is not None:
        _filter.update({
            "_id": {
                "$lt": bson.ObjectId(offset),
            },
        })
    if user_id is not None:
        _filter.update({"user_id": bson.ObjectId(user_id)})

    limit = 10
    comment_list = []
    cached_user_info = {}
    cached_post_user_id = {}
    async with comments_col.find(_filter).sort("_id", pymongo.DESCENDING) as cursor:
        async for doc in cursor:
            if len(comment_list) >= limit:
                break

            user_id_str = str(doc["user_id"])
            if user_id_str not in cached_user_info:
                matched_user = await user_col.find_one(
                    {"_id": doc["user_id"]},
                )
                if matched_user is None:
                    continue

                cached_user_info[user_id_str] = {
                    "banned": matched_user["banned"],
                    "username": matched_user["username"],
                    "display_name": matched_user["display_name"],
                    "profile_image": matched_user["profile"]["image"]["url"],
                    "mirai_plus": matched_user["mirai_plus"],
                    "privacy": matched_user["privacy"],
                }
            if cached_user_info[user_id_str]["banned"]:
                continue
            doc.update(cached_user_info[user_id_str])

            if post_id_is_empty:
                post_id_str = str(doc["post_id"])
                if post_id_str not in cached_post_user_id:
                    post_doc = await post_col.find_one(
                        filter={"_id": bson.ObjectId(doc["post_id"])},
                        projection={
                            "user_id": 1,
                        },
                    )
                    if post_doc is None: # post is deleted
                        continue
                    cached_post_user_id[post_id_str] = post_doc["user_id"]

                post_user_id: bson.ObjectId = cached_post_user_id[post_id_str]
                post_user_id_str = str(post_user_id)
                if post_user_id_str not in cached_user_info:
                    post_user = await user_col.find_one(
                        {"_id": post_user_id},
                    )
                    cached_user_info[post_user_id_str] = {
                        "username": post_user["username"],
                        "display_name": post_user["display_name"],
                        "profile_image": post_user["profile"]["image"]["url"],
                        "mirai_plus": post_user["mirai_plus"],
                        "privacy": post_user["privacy"],
                    }
                doc["post_username"] = cached_user_info[post_user_id_str]["username"]

            if rbac_res.user_doc is not None:
                if rbac_res.user_doc["_id"] != doc["user_id"]:
                    blocked = await user_col.find_one({
                        "$or": [
                            {"_id": rbac_res.user_doc["_id"], "blocked_users": doc["user_id"]},
                            {"_id": doc["user_id"], "blocked_users": rbac_res.user_doc["_id"]},
                        ],
                    })
                    if blocked:
                        continue
                doc.update({"has_liked": (rbac_res.user_doc.get("_id") in doc.get("likes", [])) if rbac_res.user_doc.get("_id") else False})

            doc = useful.format_json_response(doc)
            if "description" in doc and doc["description"] is not None:
                # We will be using DOMPurify to sanitize the HTML client-side
                doc["description"] = html.unescape(doc["description"])
            comment_list.append(doc)

    return comment_list

@general_api.get(
    path="/search",
    description="Looks through the MongoDB to find for a match of search query.",
    summary="Return search results",
)
async def api_search(
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
    q = q.strip()
    if q == "":
        return []

    if len(q) > C.SEARCH_MAX_LENGTH:
        q = q[:C.SEARCH_MAX_LENGTH]

    db = rbac_res.database
    if offset is None:
        _filter = {}
    else:
        _filter = {
            "_id": {"$lt": bson.ObjectId(offset)},
        }

    pipelines = []
    cursor: Cursor | None = None
    remote_db_col: Collection | None = None
    user_col = db[C.USER_COLLECTION]
    post_col = db[C.POST_COLLECTION]
    comment_col = db[C.COMMENTS_COLLECTION]
    if search_type == schemas.SearchType.USER:
        if not C.USE_REMOTE_DB:
            if q.startswith("@"):
                _filter.update({
                    "username": {
                        "$regex": q[:1], 
                        "$options": "i",
                    },
                })
                cursor = user_col.find(_filter).collation(
                    Collation(locale="en", strength=CollationStrength.PRIMARY),
                ).sort("_id", pymongo.DESCENDING)
            elif q != "":
                _filter.update({
                    "$or": [
                        {"username": {
                            "$regex": q,
                            "$options": "i",
                        }},
                        {"display_name": {
                            "$regex": q,
                            "$options": "i",
                        }},
                    ]
                })
                cursor = user_col.find(_filter).sort("_id", pymongo.DESCENDING)
            else:
                cursor = user_col.find(_filter).sort("_id", pymongo.DESCENDING)
        else:
            pipelines = [{
                "$search": {
                    "index": "user",
                    "text": {
                        "query": q if not q.startswith("@") else q[1:],
                        "path": {
                            "wildcard": "*",
                        },
                    },
                },
            }]
            remote_db_col = user_col
    elif search_type == schemas.SearchType.POST:
        if not C.USE_REMOTE_DB:
            _filter.update({
                "description": {
                    "$regex": q,
                    "$options": "i",
                },
            })
            cursor = post_col.find(_filter).sort("_id", pymongo.DESCENDING)
        else:
            pipelines = [{
                "$search": {
                    "index": "post",
                    "text": {
                        "query": q,
                        "path": {
                            "wildcard": "*",
                        },
                    },
                },
            }]
            remote_db_col = post_col
    elif search_type == schemas.SearchType.COMMENT:
        if not C.USE_REMOTE_DB:
            _filter.update({
                "description": {
                    "$regex": q,
                    "$options": "i",
                },
            })
            cursor = comment_col.find(_filter).sort("_id", pymongo.DESCENDING)
        else:
            pipelines = [{
                "$search": {
                    "index": "comment",
                    "text": {
                        "query": q,
                        "path": {
                            "wildcard": "*",
                        },
                    },
                },
            }]
            remote_db_col = comment_col
    else:
        return ORJSONResponse(
            status_code=422,
            content={
                "error": "Invalid search type.",
                "accepted_types": [
                    schemas.SearchType.USER.value,
                    schemas.SearchType.POST.value,
                    schemas.SearchType.COMMENT.value,
                ],
            },
        )

    if C.USE_REMOTE_DB:
        if offset is not None:
            pipelines.append({
                "$match": _filter,
            })
        pipelines.append({
            "$sort": {
                "_id": pymongo.DESCENDING,
            },
        })
        cursor = remote_db_col.aggregate(pipelines)

    limit = 25
    results = []
    cached_user_info = {}
    cached_post_user_id = {}
    async for doc in cursor:
        if len(results) >= limit:
            await cursor.close()
            break

        if search_type == schemas.SearchType.USER:
            if doc["banned"]:
                continue

            if rbac_res.user_doc is not None and rbac_res.user_doc["_id"] == doc["_id"]:
                allowed_to_see = True
            else:
                allowed_permissions = useful.evaluate_permissions(
                    target_id=str(doc["_id"]),
                    target_privacy=doc["privacy"],
                    user_following=rbac_res.user_doc["social"]["following"] if rbac_res.user_doc else [],
                )
                allowed_to_see = allowed_permissions.search_indexed

            if allowed_to_see:
                results.append(
                    useful.format_json_response({
                        "_id": doc["_id"],
                        "username": doc["username"],
                        "display_name": doc["display_name"],
                        "profile_image": doc["profile"]["image"]["url"],
                        "bio": doc["profile"]["bio"],
                        "mirai_plus": doc["mirai_plus"],
                    }),
                )
        else: # post or comment
            user_id_str = str(doc["user_id"])
            if user_id_str not in cached_user_info:
                matched_user = await user_col.find_one({"_id": doc["user_id"]})
                if matched_user is None:
                    continue

                cached_user_info[user_id_str] = {
                    "banned": matched_user["banned"],
                    "username": matched_user["username"],
                    "display_name": matched_user["display_name"],
                    "profile_image": matched_user["profile"]["image"]["url"],
                    "privacy": matched_user["privacy"],
                    "mirai_plus": matched_user["mirai_plus"],
                }
            if cached_user_info[user_id_str]["banned"]:
                continue

            doc.update(cached_user_info[user_id_str])
            if rbac_res.user_doc is not None:
                if rbac_res.user_doc["_id"] != doc["user_id"]:
                    blocked = await user_col.find_one({
                        "$or": [
                            {"_id": rbac_res.user_doc["_id"], "blocked_users": doc["user_id"]},
                            {"_id": doc["user_id"], "blocked_users": rbac_res.user_doc["_id"]},
                        ]
                    })
                    if blocked:
                        continue
                doc.update({"has_liked": (rbac_res.user_doc.get("_id") in doc.get("likes", [])) if rbac_res.user_doc.get("_id") else False})

            if search_type == schemas.SearchType.COMMENT:
                post_id_str = str(doc["post_id"])
                if post_id_str not in cached_post_user_id:
                    post_doc = await post_col.find_one(
                        filter={"_id": doc["post_id"]},
                        projection={"user_id": 1},
                    )
                    if post_doc is None: # post is deleted
                        continue
                    cached_post_user_id[post_id_str] = post_doc["user_id"]

                post_user_id: bson.ObjectId = cached_post_user_id[post_id_str]
                post_user_id_str = str(post_user_id)
                if post_user_id_str not in cached_user_info:
                    matched_user = await user_col.find_one({"_id": post_user_id})
                    if matched_user is None:
                        continue
                    if matched_user["banned"]:
                        continue

                    cached_user_info[post_user_id_str] = {
                        "username": matched_user["username"],
                        "display_name": matched_user["display_name"],
                        "profile_image": matched_user["profile"]["image"]["url"],
                        "privacy": matched_user["privacy"],
                        "mirai_plus": matched_user["mirai_plus"],
                    }
                doc["post_username"] = cached_user_info[post_user_id_str]["username"]

                allowed_to_see = True
            elif rbac_res.user_doc is not None and rbac_res.user_doc["_id"] == doc["user_id"]:
                allowed_to_see = True
            else:
                allowed_permissions = useful.evaluate_permissions(
                    target_id=user_id_str,
                    target_privacy=cached_user_info[user_id_str]["privacy"],
                    user_following=rbac_res.user_doc["social"]["following"] if rbac_res.user_doc else [],
                )
                allowed_to_see = allowed_permissions.see_posts

            if allowed_to_see:
                doc = useful.format_json_response(doc)
                if "description" in doc and doc["description"] is not None:
                    # We will be using DOMPurify to sanitize the HTML client-side
                    doc["description"] = html.unescape(doc["description"])

                results.append(doc)

    return results

@general_api.get(
    path="/privacy",
    response_model=schemas.Permission,
    response_model_exclude_unset=True,
)
async def get_privacy(request: Request, username: str | None = None, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_col = db[C.USER_COLLECTION]

    if username is not None:
        data = await user_col.find_one(
            filter = {"username": username},
            projection = {"privacy": True},
        )
    elif request.session.get(C.SESSION_COOKIE) is not None:
        data = rbac_res.user_doc
    else:
        data = None

    if data is not None:
        return data.get("privacy")
    else:
        return {}

@general_api.get(
    path="/followers/{username}",
    description="Looks through the MongoDB to find user's follower/following list.",
)
async def get_other_followers(
    request: Request, 
    username: str, 
    follower_type: str = Query(
        description="The type of search to perform.",
    ),
    offset: int | None = Query(
        description="The offset of the search results",
    ),
    rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY
):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    db = rbac_res.database
    user_col = db[C.USER_COLLECTION]

    if follower_type not in (C.FOLLOWER_TYPE.FOLLOWERS, C.FOLLOWER_TYPE.FOLLOWING):
        follower_type = C.FOLLOWER_TYPE.FOLLOWERS

    if offset is None:
        _projection = {f"social.{follower_type}": {"$slice": 5}}
    else:
        _projection = {f"social.{follower_type}": {"$slice": [offset, 5]}}

    viewed_user = await user_col.find_one(
        filter={"username": username},
        projection=_projection,
    )

    user_info = await user_col.find(
        filter={
            "_id": {"$in": viewed_user["social"][follower_type]},
        },
        projection={
            "username": True, 
            "display_name": True, 
            "profile.bio": True, 
            "profile.image.url": True, 
            "_id": False
        }
    ).to_list(length=10)

    return user_info

@general_api.get(
    path="/auth/google",
    description="Redirect to Google login page.",
)
async def login_google(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    google_sso = get_google_sso(request)
    return await google_sso.get_login_redirect(
        params={"access_type": "offline", "include_granted_scopes": "true"},
    )

@general_api.get(
    path="/auth/google/callback",
    description="Callback from Google OAuth2 login flow for validations",
)
async def login_google_callback(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    google_sso = get_google_sso(request)
    return await process_oauth_callback(
        sso_obj=google_sso,
        request=request,
        oauth_type="google",
        user_doc=rbac_res.user_doc,
    )

@general_api.get(
    path="/auth/facebook",
    description="Redirect to Facebook login page.",
)
async def login_facebook(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    facebook_sso = get_facebook_sso(request)
    return await facebook_sso.get_login_redirect()

@general_api.get(
    path="/auth/facebook/callback",
    description="Callback from Facebook OAuth2 login flow for validations",
)
async def login_facebook_callback(request: Request, rbac_res: rbac.RBACResults | RedirectResponse = RBAC_DEPENDENCY):
    if not isinstance(rbac_res, rbac.RBACResults):
        return rbac_res

    facebook_sso = get_facebook_sso(request)
    return await process_oauth_callback(
        sso_obj=facebook_sso,
        request=request,
        oauth_type="facebook",
        user_doc=rbac_res.user_doc,
    )