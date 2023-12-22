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

# import Python's standard libraries
import re
from typing import Self

class CacheControlURLRule:
    """Creates an object that contains the path and cache control headers for a route"""
    def __init__(self, path: str | re.Pattern[str], cache_control: str) -> None:
        """Configure the cache control headers for a particular route URL.

        Args:
            path (str | re.Pattern[str]): 
                The url path of the route
            cache_control (str): 
                The cache control headers for the route
        """
        self.__path = path
        self.__cache_control = cache_control

    @property
    def path(self) -> str | re.Pattern[str]:
        """The url path of the route"""
        return self.__path

    @property
    def cache_control(self) -> str:
        """The cache control headers for the route"""
        return self.__cache_control

    def __eq__(self, other: str | Self) -> bool:
        if isinstance(other, str):
            if isinstance(self.path, str):
                return self.path == other
            if isinstance(self.path, re.Pattern):
                return self.path.fullmatch(other) is not None

        if isinstance(other, CacheControlURLRule):
            return self.path == other.path and self.cache_control == other.cache_control

        return NotImplemented

class CacheControlMiddleware(BaseHTTPMiddleware):
    """Adds a Cache-Control header to the specified API routes (Only if the status code is 2XX).
    With reference to: https://github.com/attakei/fastapi-simple-cache_control"""
    def __init__(self, 
        app: ASGIApp, 
        routes: tuple[CacheControlURLRule] | list[CacheControlURLRule],
        default: str | None = "no-store, no-cache, must-revalidate, max-age=0"
    ) -> None:
        """Adds a Cache-Control header to the specified API routes.

        Args:
            cache_control (str):
                The cache-control header value
            routes (tuple | list):
                The API routes to add the cache-control header to
            default (str, optional):
                The default cache-control header value if the route is not in the routes list.
                Defaults to "no-store, no-cache, must-revalidate, max-age=0".
        """
        if not all(isinstance(route, CacheControlURLRule) for route in routes):
            raise TypeError("All routes must be of type CacheControlURLRule")

        self.__default = default
        self.__routes = tuple(routes)
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        user_req_path = request.url.path
        status_code = response.status_code
        if status_code >= 200 and status_code < 300:
            for route in self.__routes:
                if route == user_req_path:
                    response.headers["Cache-Control"] = route.cache_control
                    return response

        response.headers["Cache-Control"] = self.__default
        return response