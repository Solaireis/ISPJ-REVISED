# import third-party libraries
from fastapi import Request
from starlette.types import ASGIApp
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import (
    HTTPException,
    RequestValidationError,
)
from starlette.responses import HTMLResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# import local python libraries
from utils import constants as C
from utils.exceptions import (
    UserBannedException,
    UserInactiveException,
)
from routers.web.web_utils import render_template
from utils.classes.pretty_orjson import PrettyORJSON

async def render_error_template(request: Request, status_code: int) -> HTMLResponse | PrettyORJSON:
    """Renders an error HTML Jinja2 template or a JSON response depending if the request is an API request or not.

    Args:
        request (Request):
            The request object.
        status_code (int):
            The status code of the error.

    Returns:
        HTMLResponse | PrettyORJSON:
            The error HTML template or JSON response.
    """
    error_info = C.ERROR_TABLE.get(status_code)
    if error_info is None:
        title =  "Uh Oh, Something Went Wrong!"
        description = "Something went wrong"
    else:
        title = error_info["title"]
        description = error_info["description"]

    if request.url.path.startswith(C.API_PREFIX):
        return PrettyORJSON(
            status_code=status_code,
            content={
                "status_code": status_code,
                "error": title.title(),
                "message": description.capitalize(),
            },
        )

    return await render_template(
        name="errors/error.html", 
        context={
            "request": request,
            "status_code": status_code,
            "title": title.title(),
            "description": description.capitalize(),
        },
        status_code=status_code,
    )

def add_app_exception_handlers(app: ASGIApp) -> None:
    """Adds custom exception handlers to the web application"""
    @app.exception_handler(HTTPException)
    @app.exception_handler(StarletteHTTPException)
    @app.exception_handler(Exception)
    async def general_exec(request: Request, exc: HTTPException | StarletteHTTPException) -> HTMLResponse | PrettyORJSON:
        status_code = exc.status_code if hasattr(exc, "status_code") else 500
        return await render_error_template(request, status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        if not C.DEBUG_MODE and not request.url.path.startswith(C.API_PREFIX):
            return await render_error_template(request, 422)
        return PrettyORJSON(
            status_code=422,
            content=jsonable_encoder({"detail": exc.errors(), "body": exc.body, "params": request.url.query}),
        )

    @app.exception_handler(UserBannedException)
    async def user_banned_exec(request: Request, exc: UserBannedException) -> HTMLResponse | PrettyORJSON:
        request.session.clear()
        if request.url.path.startswith(C.API_PREFIX):
            return PrettyORJSON(
                status_code=403,
                content={
                    "status_code": 403,
                    "message": f"Sorry @{exc.username}, You are banned from using Mirai until {exc.expiry}.",
                    "reason": exc.reason,
                    "done_by": f"@{exc.done_by}",
                    "done_at": exc.time,
                },
            )

        return await render_template(
            name="errors/banned.html",
            context={
                "title": "Account Banned",
                "request": request,
                "username": f"@{exc.username}",
                "reason": exc.reason,
                "expiry": exc.expiry,
                "done_by": f"@{exc.done_by}",
                "done_at": exc.time,

            },
            status_code=403,
        )

    @app.exception_handler(UserInactiveException)
    async def user_banned_exec(request: Request, exc: UserInactiveException) -> HTMLResponse | PrettyORJSON:
        request.session.clear()
        if request.url.path.startswith(C.API_PREFIX):
            return PrettyORJSON(
                status_code=403,
                content={
                    "status_code": 403,
                    "message": f"Sorry @{exc.username}, You are Locked from using Mirai until {exc.expiry}. Please contact your administrator",
                    "reason": exc.reason,
                    "done_by": f"@{exc.done_by}",
                    "done_at": exc.time,
                },
            )

        return await render_template(
            name="errors/inactive.html",
            context={
                "title": "Account Locked",
                "request": request,
                "username": f"@{exc.username}",
                "reason": exc.reason,
                "expiry": exc.expiry,
                "done_by": f"@{exc.done_by}",
                "done_at": exc.time,
            },
            status_code=403,
        )