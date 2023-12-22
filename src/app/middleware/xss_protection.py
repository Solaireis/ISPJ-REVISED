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

class XSSProtection(BaseHTTPMiddleware):
    """XSSProtection class constructs a xXSSProtection Header for the application after each requests.

    To add the middleware:
    >>> app.add_middleware(
            XSSProtection, 
            x_xss_protection=True,
            block=False,
            report=False,
        )
    """
    def __init__(self, app: ASGIApp, x_xss_protection: bool | None = True, block: bool | None = False, report: bool | None = False) -> None:
        """Constructor for XSSProtection class.

        Args:
            app (ASGIApp): 
                The ASGI application instance
            x_xss_protection (bool, optional):
                The X-XSS-Protection option to be used.
                Defaults to True.
            block (bool, optional):
                The X-XSS-Protection option to be used.
                Defaults to False.
            report (bool, optional):
                The X-XSS-Protection option to be used.
                Defaults to False.
        """
        if not isinstance(x_xss_protection, bool):
            raise ValueError("X-XSS-Protection must be a boolean")

        if not isinstance(block, bool):
            raise ValueError("block must be a boolean")

        if not isinstance(report, bool):
            raise ValueError("report must be a boolean")

        self.block = block
        self.report = report
        self.x_xss_protection = x_xss_protection
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        if self.x_xss_protection:
            xss = "1"
            if self.block:
                xss += "; block"
            if self.report:
                xss += "; report"
            response.headers["X-XSS-Protection"] = xss

        return response