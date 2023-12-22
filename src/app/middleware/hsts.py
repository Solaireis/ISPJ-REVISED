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

class StrictTransportSecurity(BaseHTTPMiddleware):
    """StrictTransportSecurity class constructs a Strict-Transport-Security Header for the application after each requests.

    To add the middleware:
    >>> app.add_middleware(
            StrictTransportSecurity, 
            max_age="31536000",
            include_sub_domains=False,
            preload=False,
        )
    """
    def __init__(self, app: ASGIApp, max_age: int | str | None = "31536000", include_sub_domains: bool = False, preload: bool = False) -> None:
        """Constructor for HSTS class

        Args:
            app (ASGIApp): 
                The ASGI application instance
            max_age (int | str, optional):
                The Strict-Transport-Security max-age option to be used.
                Defaults to 31536000.
            include_sub_domains (bool, optional):
                The Strict-Transport-Security includeSubDomains option to be used.
                Defaults to False.
            preload (bool, optional):   
                The Strict-Transport-Security preload option to be used.
                Defaults to False.
        """
        if not isinstance(max_age, int | str):
            raise ValueError("Strict-Transport-Security max-age must be a string or integer")

        if isinstance(max_age, int):
            max_age = str(max_age)

        if not max_age.isnumeric() and int(max_age) < 0:
            raise ValueError("Strict-Transport-Security max-age must be a positive integer")

        if not isinstance(include_sub_domains, bool):
            raise ValueError("Strict-Transport-Security includeSubDomains must be a boolean")

        if not isinstance(preload, bool):
            raise ValueError("Strict-Transport-Security preload must be a boolean")

        self.max_age = max_age
        self.include_sub_domains = include_sub_domains
        self.preload = (preload and include_sub_domains) # preload needs includeSubDomains as well
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        hsts = f"max-age={self.max_age}"
        if self.include_sub_domains:
            hsts += "; includeSubDomains"
        if self.preload: 
            hsts += "; preload"

        response.headers["Strict-Transport-Security"] = hsts
        return response