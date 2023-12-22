# import third-party libraries
from pydantic import BaseModel
from fastapi import (
    Request, 
    Response,
)
from starlette.types import ASGIApp
from starlette.middleware.base import (
    BaseHTTPMiddleware, 
    RequestResponseEndpoint,
)

# import local python libraries
from utils import constants as C

# import Python's standard libraries
import secrets
import enum

def exempt_csp(response: Response) -> None:
    """Exempt the response from the Content Security Policy middleware.

    Args:
        response (Response): 
            The response to be exempted from the Content Security Policy.

    Returns:
        None
    """
    response.headers["X-Exempt-CSP"] = "1"

def get_nonce(request: Request) -> str:
    """Get the nonce string from the 
    request session and remove it from the session.

    Args:
        request (Request):
            The request to get the nonce string from.

    Returns:
        str:
            The nonce string.
    """
    return request.state.csp_nonce

def generate_nonce(request: Request, n_bytes: int | None = 32) -> None:
    """Generate a random nonce string for inline scripts or styles.

    Args:
        n_bytes (int, optional): 
            The number of bytes to generate. Defaults to 32.

    Returns:
        None
    """
    nonce = secrets.token_urlsafe(n_bytes)
    request.state.csp_nonce = nonce

@enum.unique
class ContentSecurityPolicies(str, enum.Enum):
    """The Content Security Policies that are allowed,
    with reference to https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"""
    BASE_URI = "base-uri"
    BLOCK_ALL_MIXED_CONTENT = "block-all-mixed-content"
    CHILD_SRC = "child-src"
    CONNECT_SRC = "connect-src"
    DEFAULT_SRC = "default-src"
    FONT_SRC = "font-src"
    FORM_ACTION = "form-action"
    FRAME_ANCESTORS = "frame-ancestors"
    FRAME_SRC = "frame-src"
    IMG_SRC = "img-src"
    MANIFEST_SRC = "manifest-src"
    MEDIA_SRC = "media-src"
    NAVIGATE_TO = "navigate-to"
    OBJECT_SRC = "object-src"
    # PLUGIN_TYPES = "plugin-types"
    PREFETCH_SRC = "prefetch-src"
    # REFERRER = "referrer"
    REPORT_SAMPLE = "report-sample"
    REPORT_TO = "report-to"
    REPORT_URI = "report-uri"
    REQUIRE_SRI_FOR = "require-sri-for"
    REQUIRE_TRUSTED_TYPES_FOR = "require-trusted-types-for"
    SANDBOX = "sandbox"
    SCRIPT_SRC = "script-src"
    SCRIPT_SRC_ATTR = "script-src-attr"
    SCRIPT_SRC_ELEM = "script-src-elem"
    SCRIPT_DYNAMIC = "script-dynamic"
    STYLE_SRC = "style-src"
    STYLE_SRC_ATTR = "style-src-attr"
    STYLE_SRC_ELEM = "style-src-elem"
    TRUSTED_TYPES = "trusted-types"
    UNSAFE_HASHES = "unsafe-hashes"
    UPGRADE_INSECURE_REQUESTS = "upgrade-insecure-requests"
    WORKER_SRC = "worker-src"

class ContentSecurityPolicySchema(BaseModel):
    """To validate the CSP dictionary"""
    values: dict[ContentSecurityPolicies, list[str]]

class ContentSecurityPolicy(BaseHTTPMiddleware):
    """ContentSecurityPolicy class constructs a CSP header for the application after each requests.
    To add the middleware:
    >>> app.add_middleware(
            ContentSecurityPolicy, 
            script_nonce=True, 
            style_nonce=True,
            csp_options={"script-src": ["'self'"]}
        )
    To get the CSP nonce for passing it to jinja2 templates:
    >>> nonce = get_nonce(request) # or request.state.csp_nonce
    >>> return templates.TemplateResponse(
        name="index.html", 
        context={"request": request, "csp_nonce": nonce}
    )
    To exempt a route from CSP, add a "X-CSP-Exempt" header to the response.
    >>> from fastapi import Response
    >>> from fastapi.responses import ORJSONResponse
    >>> from csp_middleware import exempt_csp
    >>>
    >>> async def index(response: Response):
    >>>     exempt_csp(response) # or response.headers["X-CSP-Exempt"] = "1"
    >>>     return ORJSONResponse({"Message": "Hello, world!"}, headers=response.headers)
    """
    def __init__(self, 
        app: ASGIApp, 
        script_nonce: bool | None = False, 
        style_nonce: bool | None = False, 
        csp_options: dict | None = {
            "default-src": ["'self'"], 
            "base-uri": ["'self'"], 
            "block-all-mixed-content": [], 
            "font-src": ["'self'", 'https:', 'data:'], 
            "frame-ancestors": ["'self'"], 
            "img-src": ["'self'", 'data:'], 
            "object-src": ["'none'"], 
            "script-src": ["'self'"], 
            "script-src-attr": ["'none'"], 
            "style-src": ["'self'","https:","'unsafe-inline'"], 
            "upgrade-insecure-requests": [], 
            "require-trusted-types-for": ["'script'"]
        },
        exempt_routes: list[str] | None = None,
    ) -> None:
        """Constructor for ContentSecurityPolicy class
        Attributes:
            app (ASGIApp): 
                The ASGI application instance
            script_nonce (bool | None, optional):
                Whether to add nonce to script-src or not. Defaults to False.
            style_nonce (bool | None, optional):
                Whether to add nonce to style-src or not. Defaults to False.
            csp_options (dict | None, optional):
                The CSP options to be used.
            exempt_routes (list[str] | None, optional):
                The routes to be exempted from CSP. Defaults to None.
        """
        self.csp_options = ContentSecurityPolicySchema(values=csp_options)
        if script_nonce and "script-src" not in self.csp_options.values:
            raise ValueError("CSP option, \"script-src\", does not exists but script_nonce is set to True.")
        if script_nonce and len(self.csp_options.values["script-src"]) == 0:
            raise ValueError("CSP option, \"script-src\", cannot be empty.")

        if style_nonce and "style-src" not in self.csp_options.values:
            raise ValueError("CSP option, \"style-src\", does not exists but style_nonce is set to True.")
        if style_nonce and len(self.csp_options.values["style-src"]) == 0:
            raise ValueError("CSP option, \"style-src\", cannot be empty.")

        if exempt_routes is not None and not isinstance(exempt_routes, list):
            raise ValueError("exempt_routes must be a list of strings.")

        self.script_nonce = script_nonce
        self.style_nonce = style_nonce
        self.exempt_routes = exempt_routes
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path.startswith(C.API_PREFIX) or (self.exempt_routes is not None and request.url.path in self.exempt_routes):
            # CSP is not required for API endpoints or exempt routes
            return await call_next(request)

        nonce = secrets.token_urlsafe(32)
        request.state.csp_nonce = nonce
        response = await call_next(request)
        exempt_csp = response.headers.get(key="X-Exempt-CSP", default="0")

        if exempt_csp != "1":
            parsed_csp = ""
            for key, value in self.csp_options.values.items():
                key = key.value
                append_nonce = False
                if (self.script_nonce and key == "script-src") or (self.style_nonce and key == "style-src"):
                    append_nonce = True
                parsed_csp += "{key}{nonce}{values}; ".format(
                    key=key,
                    values=f" {' '.join(value)}" if len(value) > 0 else "",
                    nonce=f" 'nonce-{nonce}'" if append_nonce else ""
                )
            response.headers["Content-Security-Policy"] = parsed_csp

        return response