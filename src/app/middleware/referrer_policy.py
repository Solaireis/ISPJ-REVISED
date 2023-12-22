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

class ReferrerPolicy(BaseHTTPMiddleware):
    """ReferrerPolicy class constructs a ReferrerPolicy Header for the application after each requests.

    To add the middleware:
    >>> app.add_middleware(
            ReferrerPolicy,
        )
    """
    CHOICES = (
        "no-referrer", 
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin", 
        "strict-origin-when-cross-origin", 
        "unsafe-url",
    )
    def __init__(self, app: ASGIApp, option: str | None = "same-origin") -> None:
        """Constructor for ReferrerPolicy class.

        Args:
            app (ASGIApp): 
                The ASGI application instance
            option (str | None):
                The Referrer-Policy option to be used.
        """
        super().__init__(app)
        self.option = option
        if self.option not in self.CHOICES:
            raise ValueError("You have entered an invalid option for Referrer-Policy")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["Referrer-Policy"] = self.option
        return response