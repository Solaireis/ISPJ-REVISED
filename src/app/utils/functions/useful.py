# import third-party libraries
import bson
import httpx
import orjson
import ipinfo
import aiofiles
import aiofiles.os as aiofiles_os
from pydantic import BaseModel, HttpUrl
from pydantic.error_wrappers import ValidationError
from fastapi import Request, FastAPI, WebSocket
from fastapi.exceptions import HTTPException

# import local Python libraries
from utils import constants as C

# import Python's standard libraries
import html
import time
import base64
import pathlib
import asyncio
import hashlib
import logging
from typing import Any
from zoneinfo import ZoneInfo
from datetime import datetime

async def filler_task() -> None:
    """A filler task that does nothing.

    Useful if you need a coroutine for a asyncio.gather call.

    E.g. 
    `await asyncio.gather(*[filler_task(), other_coroutine()])`
    """
    return

class UrlModel(BaseModel):
    url: HttpUrl
def check_if_str_is_url(string: str) -> bool:
    """Checks if a string is a URL.

    Args:
        string (str):
            The string to check.

    Returns:
        bool:
            True if the string is a URL, False otherwise.
    """
    try:
        UrlModel(url=string)
    except (ValidationError):
        return False
    else:
        return True

def limit_newlines(text: str, max_nl: int | None = 10) -> str:
    """Limits the number of newlines in a string.

    Args:
        text (str):
            The string to limit the newlines of.
        max_nl (int, optional):
            The maximum number of newlines.
            Defaults to 10.

    Returns:
        str:
            The string with the limited number of newlines.
    """
    if max_nl is None:
        return text

    split_text = text.splitlines()
    if len(split_text) > max_nl:
        return "\n".join(split_text[:max_nl]) + " ".join(split_text[max_nl:])

    return text

def datetime_to_unix_time(datetime_obj: datetime) -> float:
    """Converts a datetime object to a Unix timestamp.

    Args:
        datetime_obj (datetime):
            The datetime object to convert.

    Returns:
        float:
            The Unix timestamp.
    """
    return datetime_obj.replace(tzinfo=ZoneInfo("UTC")).timestamp()

def truncate_text(text: str, max_length: int = 20) -> str:
    """Truncates a string to a maximum length.

    Args:
        text (str):
            The text to truncate.
        max_length (int, optional):
            The maximum length of the string. Defaults to 20.

    Returns:
        str:
            The truncated string.
    """
    if len(text) > max_length:
        return text[:max_length].strip() + "..."
    return text

def get_country_from_request(request: Request | WebSocket) -> str | None:
    """Gets the country from the request headers (Cloudflare proxy).

    Args:
        request (Request):
            The request to get the country from.

    Returns:
        str | None:
            The country or None if the request is not from Cloudflare.
    """
    return request.headers.get("CF-IPCountry")

def get_city_from_request(request: Request | WebSocket) -> str | None:
    """Gets the city from the request headers (Cloudflare proxy).

    Args:
        request (Request):
            The request to get the city from.

    Returns:
        str | None:
            The city or None if the request is not from Cloudflare.
    """
    return request.headers.get("CF-IPCity")

async def get_location_str(request: Request | WebSocket, get_parts: bool | None = False) -> str | tuple[str, str, str]:
    """Gets the location string from the request headers (Cloudflare proxy)

    Args:
        request (Request | WebSocket):
            The request or websocket to get the location string from.
        get_parts (bool, Optional):
            Whether to return the city, country, and location string as a tuple.
            Defaults to False.

    Returns:
        str | tuple[str, str, str]:
            The location string or a tuple of the city, country, and location string.
    """
    ip_addr = get_user_ip(request)
    if ip_addr in ("127.0.0.1", "localhost") or ip_addr == "::1":
        return ("Unknown", "Unknown", "Unknown, Unknown") if get_parts else "Unknown, Unknown"

    city = get_city_from_request(request)
    country = get_country_from_request(request)
    if city is None or country is None:
        # if the request is not from Cloudflare, get the location from the IP address
        ipinfo_client: ipinfo.AsyncHandler = request.app.state.obj_map[ipinfo.AsyncHandler]
        details = await ipinfo_client.getDetails(
            ip_address=ip_addr,
        )
        city = details.city
        country = details.country
        location = f"{city}, {country}"
    else:
        location = city + ", " + country
        location = location.strip()

    if get_parts:
        return (city, country, location)
    return location

def browser_str_to_png_url(request: Request | WebSocket, browser: str) -> str:
    """Converts a browser string to a PNG URL.

    Args:
        browser (str):
            The browser string.

    Returns:
        str:
            The PNG URL. E.g. "/static/img/browsers/chrome_64x64.png"
    """
    suffix_uri = C.BROWSER_TABLE.get(browser, "unknown.webp")
    return url_for(request, "static", path=f"img/browsers/{suffix_uri}")

async def redis_rate_limiter_identifier(request: Request | WebSocket) -> str:
    """Returns the hashed user's IP address as the 
    data is not encrypted in transit to the redis server.

    Args:
        request (Request | WebSocket):
            The request object.

    Returns:
        str:
            The hashed user's IP address.
    """
    user_ip = get_user_ip(request).encode("utf-8")
    return f"{hashlib.sha1(user_ip).hexdigest()}:{request.scope['path']}"

def get_user_ip(request: Request | WebSocket) -> str:
    """Returns the user's IP address as a string.

    For cloudflare proxy, we need to get from the request headers:
    https://developers.cloudflare.com/fundamentals/get-started/reference/http-request-headers/

    Args:
        request (Request | WebSocket):
            The request object.

    Returns:
        str:
            The user's IP address (127.0.0.1 if not found)
    """
    cloudflare_proxy: str | None = request.headers.get(key="CF-Connecting-IP", default=None)
    if cloudflare_proxy is not None:
        return cloudflare_proxy.split(sep=",", maxsplit=1)[0]

    forwarded_for: str | None = request.headers.get(key="X-Forwarded-For", default=None)
    if forwarded_for is not None:
        return forwarded_for.split(sep=",", maxsplit=1)[0]

    requestIP = request.client
    if requestIP is not None:
        return requestIP.host

    return "127.0.0.1"

def url_for(request: Request | WebSocket, name: str, external: bool = False, **path_params: Any) -> str:
    """Returns the URL path for the given endpoint name.

    Args:
        request (Request | WebSocket):
            The request object.
        name (str):
            The endpoint name
        external (bool):
            Whether to return an absolute URL path
        **path_params (Any):
            The path parameters

    Returns:
        str:
            The URL path
    """
    app: FastAPI = request.app
    relative_path = app.url_path_for(name, **path_params)
    if external:
        return C.DOMAIN + relative_path
    else:
        return relative_path

def flash(request: Request, message: str, category: str = "primary") -> None:
    """Adds a message to the session.

    Note: Use the get_flashed_messages function in Jinja2 to retrieve the messages.

    Args:
        request (Request):
            The request object.
        message (str):
            The message to add
        category (str):
            The category of the message

    Returns:
        None
    """
    flash_message = {"message": message, "category": category}
    if C.FLASH_MESSAGES not in request.session:
        request.session[C.FLASH_MESSAGES] = []
    request.session[C.FLASH_MESSAGES].append(flash_message)

async def do_request(
    url: str, 
    method: str, 
    get_json:bool = False, 
    check_status: bool = True, 
    http2: bool = True,
    get_response: bool = False, 
    client_kwargs: dict = {}, 
    request_kwargs: dict = {},
    retries: int = 3,
) -> httpx.Response | dict | tuple[httpx.Response, dict]:
    """Makes a request asynchronously to the given URL with error handling.

    Args:
        url (str):
            The URL to make the request to
        method (str):
            The HTTP method to use
        get_json (bool, optional):
            Whether to return the response in JSON. Defaults to False.
        check_status (bool, optional):
            Whether to check the status code of the response and if it is not 200 OK, the error will be logged. 
            Defaults to True.
        get_response (bool, optional):
            Whether to return the response object if get_json was True. Defaults to False.
        client_kwargs (dict, optional):
            The keyword arguments to pass to the httpx.AsyncClient. Defaults to {}.
        request_kwargs (dict, optional):
            The keyword arguments to pass to the request. Defaults to {}.
        retries (int, optional):
            The number of times to retry the request if it fails. Defaults to 3.

    Returns:
        httpx.Response | dict:
            The response or the response in JSON
    """
    log_msg = ""
    async with httpx.AsyncClient(http2=http2, **client_kwargs) as client:
        for _ in range(retries):
            log_msg = "" # Reset the log message
            try:
                response = await client.request(
                    method=method,
                    url=url,
                    **request_kwargs,
                )
                if check_status:
                    response.raise_for_status()

                json_res = {}
                if get_json:
                    json_res = orjson.loads(response.content)
            except (httpx.HTTPStatusError) as e:
                log_msg = f"Request to {url} was not successful as status code {e.response.status_code} {e.response.reason_phrase} response was received instead of 200 OK."
            except (orjson.JSONDecodeError) as e:
                log_msg = f"Request to {url} was not successful as the response could not be decoded as JSON."
            except (httpx.HTTPError) as e:
                # Usually this is a connection error on our end
                log_msg = f"HTTP Exception for {url} - {e}"
            else:
                if get_json and get_response:
                    return response, json_res
                if get_json:
                    return json_res
                return response

            # Sleep for a second before retrying
            await asyncio.sleep(1)

    if C.DEBUG_MODE:
        print(log_msg)
    else:
        logging.error(log_msg)
    raise HTTPException(
        status_code=500, 
        detail="An error has occurred. Please try again later.",
    )

async def async_mkdir(folder_path: pathlib.Path, 
                      parents: bool | None = False, exist_ok: bool | None = False) -> None:
    """Create the folder if it doesn't exist asynchronously.
    Args:
        folder_path (pathlib.Path):
            The folder path to create.
        parents (bool | None, optional):
            Whether to create the parent folders if they don't exist. Defaults to False.
        exist_ok (bool | None, optional):
            Whether to not throw an error if the folder already exists. Defaults to False.
    Returns:
        None
    """
    if parents:
        return await aiofiles_os.makedirs(folder_path, exist_ok=exist_ok)

    try:
        return await aiofiles_os.mkdir(folder_path)
    except (OSError):
        if not exist_ok:
            raise

async def download_url(
    url: str, 
    method: str, 
    file_path: pathlib.Path | None = None, 
    download_bytes: bool | None = True,
    client_kwargs: dict = {}, 
    request_kwargs: dict = {},
    retries: int = 3,
) -> bytes | str | None:
    """Downloads the given URL to the given file path.

    Args:
        url (str):
            The URL to download
        method (str):
            The HTTP method to use
        file_path (pathlib.Path):
            The file path to download to
        download_bytes (bool, optional):
            Whether to return the response content in bytes. 
            Otherwise, return the response content in text. Defaults to True.
        client_kwargs (dict, optional):
            The keyword arguments to pass to the httpx.AsyncClient. Defaults to {}.
        request_kwargs (dict, optional):
            The keyword arguments to pass to the request. Defaults to {}.
        retries (int, optional):
            The number of times to retry the request if it fails. Defaults to 3.

    Returns:
        bytes | str | None:
            The response content in bytes or string depending on download_bytes flag 
            if file_path is None, otherwise None as the response content is written to the file path.
    """
    log_msg = ""
    if file_path is not None:
        await async_mkdir(file_path.parent, parents=True, exist_ok=True)

    async with httpx.AsyncClient(http2=True, **client_kwargs) as client:
        for _ in range(retries):
            log_msg = "" # Reset the log message
            try:
                async with client.stream(method, url, **request_kwargs) as response:
                    response.raise_for_status()
                    if file_path is None:
                        # return the response content
                        return await response.aread() \
                                if download_bytes else "".join([part async for part in response.aiter_text()])

                    if download_bytes:
                        iterator = response.aiter_bytes()
                        file_mode = "wb"
                        encoding = None
                    else:
                        iterator = response.aiter_text()
                        file_mode = "w"
                        encoding = "utf-8"

                    async with aiofiles.open(file=file_path, mode=file_mode, encoding=encoding) as f:
                        async for data in iterator:
                            await f.write(data)
            except (httpx.HTTPStatusError) as e:
                log_msg = f"Request to {url} was not successful as status code {e.response.status_code} {e.response.reason_phrase} response was received instead of 200 OK."
            except (httpx.HTTPError) as e:
                # Usually this is a connection error on our end
                log_msg = f"HTTP Exception for {url} - {e}"
            else:
                return

            # Sleep for a second before retrying
            await asyncio.sleep(1)

    logging.error(log_msg)
    raise HTTPException(
        status_code=500, 
        detail="An error has occurred. Please try again later.",
    )

def __format_value_for_json(value: Any, escape: bool | None = True) -> Any:
    """Format the value for JSON deserialisation/dumps.

    Args:
        value (Any):
            The value to format.
        escape (bool, optional):
            Whether to escape the value. Defaults to True.

    Returns:
        Any:
            The formatted value.
    """
    if isinstance(value, str) and escape:
        return html.escape(value)

    if isinstance(value, bson.ObjectId):
        return html.escape(str(value)) if escape else str(value)

    if isinstance(value, datetime):
        return datetime_to_unix_time(value)

    if isinstance(value, bytes):
        return base64.b64encode(value).decode("utf-8")

    if isinstance(value, dict):
        return {key: __format_value_for_json(value, escape=escape) for key, value in value.items()}

    if isinstance(value, list):
        return [__format_value_for_json(item, escape=escape) for item in value]

    return value

def format_json_response(value: Any, escape: bool | None = True, dump_json: bool | None = False) -> Any:
    """Format the value for JSON deserialisation/dumps.

    Args:
        value (Any):
            The value to format.
        escape (bool, optional):
            Whether to escape the value. Defaults to True.
        dump_json (bool, optional):
            Whether to dump the value to JSON. Defaults to False.

    Returns:
        Any:
            The formatted value.
    """
    formatted_value = __format_value_for_json(value, escape=escape)
    return orjson.dumps(formatted_value).decode("utf-8") if dump_json else formatted_value

def get_following_status(
    _id: bson.ObjectId, 
    following_list: list[bson.ObjectId], 
    pending_list: list[bson.ObjectId], 
    requests_list: list[bson.ObjectId]
) -> str:
    if _id in pending_list:
        return "pending"
    elif _id in requests_list:
        return "requests"
    elif _id in following_list:
        return "followed"
    else:
        return "unfollowed"

def evaluate_permissions(target_id: str, target_privacy: dict | C.PERMISSIONS, user_following: list[bson.ObjectId]) -> C.PERMISSIONS:
    # Do not use with "be_follower" or "last_updated"
    allowed_permissions = {}
    if isinstance(target_privacy, C.PERMISSIONS):
        target_privacy = target_privacy._asdict()

    if not user_following:
        for permission, friendship in target_privacy.items():
            allowed_permissions[permission] = (friendship == C.FRIENDSHIP_TYPE.PUBLIC)
    else:
        target_id = bson.ObjectId(target_id)
        for permission, friendship in target_privacy.items():
            is_follower = (
                friendship == C.FRIENDSHIP_TYPE.FOLLOWERS and 
                target_id in user_following
            )
            is_public = (friendship == C.FRIENDSHIP_TYPE.PUBLIC)

            allowed_permissions[permission] = is_follower or is_public

    return C.PERMISSIONS(**allowed_permissions)

def get_authenticated_status(request: Request, user_doc: dict) -> bool:
    """Returns whether the user is authenticated.

    Args:
        request (Request):
            The request object.
        user_doc (dict):
            The user document.

    Returns:
        bool:
            Whether the user is authenticated.
    """
    if bool(user_doc.get("password")):
        if "authenticated" not in request.session:
            return False

        authenticated_flag = True
        info: dict = request.session["authenticated"]
        if info.get("status", False) and time.time() >= info.get("expiry", 0):
            request.session.pop("authenticated")
            authenticated_flag = False
        return authenticated_flag
    return True