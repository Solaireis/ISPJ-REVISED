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

class ExpectCT(BaseHTTPMiddleware):
    """ExpectCT class constructs a ExpectCT Header for the application after each requests.

    To add the middleware:
    >>> app.add_middleware(
            ExpectCT, 
            max_age="86400",
            enforce=True,
            report_uri=None,
        )
    """
    def __init__(self, app: ASGIApp, max_age: str | int | None = "86400", enforce: bool | None = True, report_uri: str | None = None) -> None:
        """Constructor for ExpectCT class

        Args:
            app (ASGIApp): 
                The ASGI application instance
            max_age (str | int, optional):
                The ExpectCT max-age option to be used.
                Defaults to 86400.
            enforce (bool, optional):
                The ExpectCT enforce option to be used.
                Defaults to True.
            report_uri (str, optional):
                The ExpectCT report-uri option to be used.
                Defaults to None.
        """
        if not isinstance(max_age, str | int):
            raise ValueError("ExpectCT max-age must be a string or integer")

        if isinstance(max_age, int):
            max_age = str(max_age)

        if not max_age.isnumeric() and int(max_age) < 0:
            raise ValueError("Strict-Transport-Security max-age must be a positive integer")

        if not isinstance(enforce, bool):
            raise ValueError("ExpectCT enforce must be a boolean")

        if report_uri is not None and not isinstance(report_uri, str):
            raise ValueError("ExpectCT report-uri must be a string")

        self.max_age = max_age
        self.enforce = enforce
        self.report_uri = report_uri
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        expect_ct = f"max-age={self.max_age}"
        if self.enforce:
            expect_ct += ", enforce"
        if self.report_uri is not None:
            expect_ct += f", report-uri={self.report_uri}"

        response.headers["Expect-CT"] = expect_ct
        return response