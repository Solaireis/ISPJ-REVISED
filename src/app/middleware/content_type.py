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

class ContentTypeOptions(BaseHTTPMiddleware):
    """ContentTypeOptions class constructs a ContentTypeOptions Header for the application after each requests.

    To add the middleware:
    >>> app.add_middleware(
            ContentTypeOptions, 
        )
    """
    def __init__(self,app: ASGIApp) -> None:
        """Constructor for HSTS class
        Attributes:
            app (ASGIApp): 
                The ASGI application instance
        """
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response