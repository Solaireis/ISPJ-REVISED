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

# import local Python libraries
from utils.classes.hmac import URLSafeSerialiserHMAC
from .error import render_error_template

# import Python's standard libraries
import secrets

class CSRFMiddleware(BaseHTTPMiddleware):
    SAFE_METHODS = ("GET", "HEAD", "OPTIONS", "TRACE")

    def __init__(self, 
        app: ASGIApp, 
        signer: URLSafeSerialiserHMAC,
        cookie_name: str = "csrf-token",
        header_name: str = "X-CSRF-TOKEN",
        max_age: int | None = 3600 * 24 * 14,  # 14 days, in seconds
        path: str | None = "/",
        samesite: str = "strict",
        secure: bool = False,
        domain: str | None = None,
        csrf_length: int = 32,
        exempt_routes: list[str] = []
    ) -> None:
        """Add CSRF protection to the API and the web application.

        Args:
            app (ASGIApp): 
                The ASGI application.
            signer (URLSafeSerialiserHMAC):
                The signer to sign the CSRF cookie.
            cookie_name (str, optional):
                The name of the cookie to store the CSRF token in. Defaults to "csrf-token".
            header_name (str, optional):
                The name of the header to store the CSRF token in. Defaults to "X-CSRF-TOKEN".
            max_age (int | None, optional):
                The maximum age of the CSRF token, in seconds. Defaults to 3600 * 24 * 14 (14 days).
            path (str | None, optional):
                The path of the CSRF token. Defaults to "/".
            samesite (str, optional):
                The SameSite attribute of the CSRF token. Defaults to "strict".
            secure (bool, optional):
                Whether the CSRF token should be secure. Defaults to False.
            domain (str | None, optional):
                The domain of the CSRF token. Defaults to None.
            csrf_length (int, optional):
                The bytes length of the CSRF token. Defaults to 32 bytes.
            exempt_routes (list[str], optional):
                The routes that should be exempt from CSRF protection. Defaults to [].
        """
        self.signer = signer
        self.domain = domain
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.max_age = max_age
        self.path = path
        self.samesite = samesite
        self.secure = secure
        self.csrf_length = csrf_length
        self.exempt_routes = exempt_routes
        super().__init__(app)

    def get_token(self, value: str | None) -> str | None:
        if value is None:
            return None
        return self.signer.get(value)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        set_token_cookie  = False
        cookie_token = self.get_token(
            value=request.cookies.get(self.cookie_name),
        )
        header_token = self.get_token(
            value=request.headers.get(self.header_name),
        )

        request_url = request.url.path
        if  request.method not in self.SAFE_METHODS and request_url not in self.exempt_routes:
            # Validate the CSRF token
            if cookie_token is None:
                # CSRF cookie not set.
                return render_error_template(
                    request=request,
                    status_code=400,
                )
            if cookie_token != header_token:
                # CSRF token does not match.
                return render_error_template(
                    request=request,
                    status_code=400,
                )

        # Generate a new CSRF token if one is not already set.
        if cookie_token is None:
            cookie_token = self.signer.sign(
                data={"csrf_token": secrets.token_urlsafe(self.csrf_length)},
            )
            set_token_cookie = True

        # Wait for response to happen.
        response = await call_next(request)

        # Set CSRF cookie on the response.
        if set_token_cookie:
            response.set_cookie(
                key=self.cookie_name, 
                value=cookie_token, 
                max_age=self.max_age,
                path=self.path, 
                domain=self.domain, 
                secure=self.secure, 
                httponly=False, 
                samesite=self.samesite,
            )

        return response