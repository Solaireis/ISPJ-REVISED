# import third-party libraries
from pymongo.database import Database
from pymongo.collection import Collection
import pymongo
from fastapi import (
    Request, 
    WebSocket,
)
from fastapi.exceptions import HTTPException
from fastapi.responses import (
    RedirectResponse,
    HTMLResponse,
)

# import local Python libraries
from utils import constants as C
from utils.exceptions import (
    UserBannedException, 
    UserInactiveException,
)
from utils.functions.useful import url_for
from .database import (
    get_user_role, 
    get_db_client,
)
from utils.classes.pretty_orjson import PrettyORJSON
from routers.web.web_utils import render_template

async def verify_access(
    request: Request | WebSocket,
    role_arr: set[str] | str,
    col: Collection | None = None,
    clear_session_if_invalid: bool | None = True,
    admin_db: Database | None = None,
) -> dict | None | RedirectResponse:
    """Verifies the user's access based on their role.

    Args:
        request (Request | WebSocket):
            The user's request to retrieve the session ID from and
            to authorise the user based on their given roles.
        role_arr (tuple[str] | str):
            The list of roles that are allowed to access the route.
            If a string is passed, it will be converted to a list.
        clear_session_if_invalid (bool, optional):
            Whether to clear the session if the session ID is invalid.
            Defaults to True.
        admin_db (Database, optional):
            The admin database to use to get the user document.
            Defaults to None. If None, a new admin database client will be created.

    Returns:
        dict | None | RedirectResponse:
            Returns the user document from mongodb if the user is logged in or
            redirects the user to the home page if they are not authorised.

    Raises:
        UserBannedException:
            If the user is banned.
    """
    if isinstance(role_arr, str):
        role_arr = (role_arr,)
    else:
        role_arr = role_arr

    session_id = request.session.get(C.SESSION_COOKIE, None)
    user_doc, user_roles = await get_user_role(
        request=request,
        session_id=session_id,
        col=col,
        clear_session_if_invalid=clear_session_if_invalid,
    )
    if user_doc is not None and user_doc["banned"]:
        if admin_db is None:
            admin_db = get_db_client(get_admin_db=True)

        # get the lastest ban report
        ban_doc = await admin_db[C.BAN_COLLECTION].find_one(
            filter={
                "user_id": str(user_doc["_id"]),
                "banned_type": "ban",
            },
            sort=[("done_at",pymongo.DESCENDING)],
        )
        raise UserBannedException(
            username=user_doc["username"],
            reason=f"{ban_doc['reason']}",
            expiry="Forever",
            time=f"{ban_doc['done_at']}",
            done_by=f"{ban_doc['done_by']}"
        )

    if user_doc is not None and C.ADMIN in user_roles and user_doc["inactive"]["status"]:
        if admin_db is None:
            admin_db = get_db_client(get_admin_db=True)

        lock_doc = await admin_db[C.LOCK_COLLECTION].find_one(
            filter={
                "username": user_doc["username"],
                "lock_type": "lock",
            },
            sort=[("done_at", pymongo.DESCENDING)],
        )
        # get the lastest lock report
        raise UserInactiveException(
            username=user_doc["username"],
            reason=f"{lock_doc['reason']}",
            expiry="Forever",
            time=f"{lock_doc['done_at']}",
            done_by=f"{lock_doc['done_by']}"
        )

    for role in user_roles:
        if role in role_arr:
            return user_doc
    return RedirectResponse(url="/")

class RBACResults:
    def __init__(self, user_doc: dict | None, database: Database, admin_database: Database) -> None:
        self.user_doc = user_doc
        self.database = database
        self.admin_database = admin_database

class RBACDepends:
    __MAINTENANCE_IMMUNE_ROUTES = (
        # web routes below
        "login", 
        "two_fa", 
        "admin_login",
        "web_logout",

        # api routes below
        "logout",
        "two_fa_sms", 
        "two_fa_submit_token", 
        "disable_two_fa", 
        "api_login", 
        "api_admin_login", 
        "login_google", 
        "login_google_callback", 
        "login_facebook", 
        "login_facebook_callback",
    )
    __PRIVACY_IMMUNE_ROUTES = (
        "logout",
        "web_logout",
    )
    def __init__(self, role_arr: tuple[str] | str, default_endpoint: str | None = None, sensitive: bool | None = False) -> None:
        """Initialises the RBAC_Depends class.

        Args:
            role_arr (tuple[str] | str):
                The list of roles that are allowed to access the route.
                If a string is passed, it will be converted to a list.
            default_endpoint (str | None):
                The default endpoint/function name to redirect the user to if they are not authorised.
                Defaults to "index".
            sensitive (bool, optional):
                Whether the route is sensitive or not.
                Will raise a 404 error if the route is sensitive and the user is not authorised.
        """
        self.__role_arr = role_arr
        self.__sensitive = sensitive
        self.__default_endpoint = default_endpoint or "index"
        self.__cached_endpoint_url = {} # type: dict[str, str]
        self.__maintenance_immune_routes = None # type: set[str] | None
        self.__privacy_immune_routes = None # type: tuple[str] | None

    def get_endpoint_url(self, request: Request, endpoint: str) -> str:
        """Returns the endpoint's URL with a
        slight performance gain by caching the url_for() result.

        Args:
            request (Request):
                The request object.
            endpoint (str):
                The endpoint/function name.

        Returns:
            str:
                The endpoint's URL.
        """
        if endpoint not in self.__cached_endpoint_url:
            # just for slight optimisation
            self.__cached_endpoint_url[endpoint] = url_for(
                request=request,
                name=endpoint,
            )
        return self.__cached_endpoint_url[endpoint]

    async def __check_maintenance_mode(
        self,
        admin_db: Database,
        request: Request,
    ) -> None | PrettyORJSON | HTMLResponse:
        """Checks if maintenance mode is enabled and
        renders the maintenance page if it is unless the user is an admin
        or root or is accessing routes that are immune to maintenance mode.

        Args:
            admin_db (Database):
                The admin database.
            request (Request):
                The request object.

        Returns:
            None | PrettyORJSON | HTMLResponse:
                Returns None if the user is an admin or root or is accessing routes that are immune to maintenance mode.
                Returns a PrettyORJSON or HTMLResponse to render the maintenance page if maintenance mode is enabled.
        """
        #check if maintenance mode is enabled
        maintenance_doc = await admin_db[C.MIRAI_SYSTEM_COLLECTION].find_one(
            filter={"_id": "maintenance_mode"},
            projection={"status": 1},
        )
        maintenance_mode: bool = maintenance_doc["status"] \
                                if maintenance_doc is not None else False # default to False if the document is not found

        request_url = request.url.path
        if maintenance_mode and not request_url.startswith("/static/"):
            if self.__maintenance_immune_routes is None:
                self.__maintenance_immune_routes = set(
                    self.get_endpoint_url(request, endpoint)
                    for endpoint in self.__MAINTENANCE_IMMUNE_ROUTES
                )

            if request_url not in self.__maintenance_immune_routes:
                if request_url.startswith(C.API_PREFIX):
                    return PrettyORJSON(
                        status_code=503,
                        content={
                            "message": "Mirai is under maintenance, please wait and try again later!"
                        },
                    )
                return await render_template(
                    name="errors/maintenance.html",
                    context={
                        "request": request,
                    },
                    status_code=503,
                )

    def return_redirect_response(self, request: Request) -> RedirectResponse:
        """Returns a RedirectResponse to the default endpoint.

        Args:
            request (Request):
                The request object.

        Returns:
            RedirectResponse:
                A RedirectResponse to the default endpoint.

        Raises:
            HTTPException:
                If the route is sensitive and the user is not authorised.
        """
        if self.__sensitive:
            raise HTTPException(
                status_code=404,
                detail="Not found",
            )
        return RedirectResponse(
            url=self.get_endpoint_url(request, self.__default_endpoint),
        )

    async def __call__(self, request: Request) -> None | RedirectResponse | RBACResults:
        """Verifies if the user is authorised to access the route.

        Args:
            request (Request):
                The request object.

        Returns:
            None | RedirectResponse | RBACResults:
                RBACResults if the user is authorised to access the route.
                None or RedirectResponse (if the default_endpoint was given) if the user is not authorised to access the route.
        """
        db = get_db_client(
            get_default=True,
        )
        admin_db = get_db_client(
            get_default=True,
            get_admin_db=True,
        )

        if C.SESSION_COOKIE not in request.session:
            # not logged in
            maintenance_response = await self.__check_maintenance_mode(
                admin_db=admin_db,
                request=request,
            )
            if maintenance_response is not None:
                return maintenance_response

            if C.GUEST in self.__role_arr:
                return RBACResults(
                    user_doc=None,
                    database=db,
                    admin_database=admin_db,
                )

            # Not authorised to view the route
            return self.return_redirect_response(
                request=request,
            )

        user_col = db[C.USER_COLLECTION]
        response = await verify_access(
            request=request,
            role_arr=self.__role_arr,
            col=user_col,
            clear_session_if_invalid=False,
            admin_db=admin_db,
        )
        if isinstance(response, dict):
            maintenance_response = await self.__check_maintenance_mode(
                admin_db=admin_db,
                request=request,
            )
            if maintenance_response is not None:
                return maintenance_response

            request_url = request.url.path
            if self.__privacy_immune_routes is None:
                self.__privacy_immune_routes = tuple(
                    self.get_endpoint_url(request, endpoint)
                    for endpoint in self.__PRIVACY_IMMUNE_ROUTES
                )
            if response.get("setup_incomplete") is not None and request_url not in self.__privacy_immune_routes:
                privacy_setup = self.get_endpoint_url(request, "privacy_settings")
                privacy_setup_api = self.get_endpoint_url(request, "set_privacy")
                if request_url not in (privacy_setup, privacy_setup_api):
                    # New User (Not Admin/Guest)
                    if C.DEBUG_MODE:
                        print(f"Redirecting to \"{privacy_setup}\"")
                    return RedirectResponse(
                        url=privacy_setup,
                    )

            return RBACResults(
                user_doc=response,
                database=db,
                admin_database=admin_db,
            )

        admin_user_col = admin_db[C.ADMIN_COLLECTION]
        response = await verify_access(
            request=request,
            role_arr=self.__role_arr,
            col=admin_user_col,
            clear_session_if_invalid=True,
            admin_db=admin_db,
        )
        if not isinstance(response, RedirectResponse):
            return RBACResults(
                user_doc=response,
                database=db,
                admin_database=admin_db,
            )

        maintenance_response = await self.__check_maintenance_mode(
            admin_db=admin_db,
            request=request,
        )
        if maintenance_response is not None:
            return maintenance_response

        # Not authorised to view the route
        return self.return_redirect_response(
            request=request,
        )

ALLROLES_RBAC = RBACDepends(
    role_arr=C.ALLROLES,
    default_endpoint="index",
)
GUEST_RBAC = RBACDepends(
    role_arr=(C.GUEST,),
    default_endpoint="index",
)
GENERAL_RBAC = RBACDepends(
    role_arr=C.GENERAL,
    default_endpoint="index",
)
USER_RBAC = RBACDepends(
    role_arr=(C.USER,),
    default_endpoint="login",
)
ADMIN_RBAC = RBACDepends(
    role_arr=(C.ADMIN,),
    sensitive=True,
    default_endpoint="login",
)
ROOT_RBAC = RBACDepends(
    role_arr=(C.ROOT,),
    sensitive=True,
    default_endpoint="login",
)