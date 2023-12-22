# import third-party libraries
from fastapi import (
    Request, 
    Response,
)
from starlette.types import ASGIApp
from starlette.middleware.base import (
    BaseHTTPMiddleware, 
    RequestResponseEndpoint,
)

class XFrameOptions(BaseHTTPMiddleware):
    """XFrameOptions class constructs a ContentTypeOptions Header for the application after each requests.

    To add the middleware:
    >>> app.add_middleware(
            XFrameOptions, 
            same_origin=True, 
            deny=False,
        )
    """
    def __init__(self, app: ASGIApp, same_origin: bool | None = True, deny: bool | None = False) -> None:
        """Constructor for XFrameOptions class

        Args:
            app (ASGIApp): 
                The ASGI application instance
            same_origin (bool, optional):
                The X-Frame-Options option to be used.
                Defaults to True.
            deny (bool, optional):
                The X-Frame-Options option to be used.
                Defaults to False.
        """
        if not (same_origin ^ deny):
            raise ValueError("same_origin or deny cannot be both true or false for X-Frame-Options")

        self.same_origin = same_origin
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        if self.same_origin:
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
            return response

        response.headers["X-Frame-Options"] = "DENY"
        return response