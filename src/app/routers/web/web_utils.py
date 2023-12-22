# import third-party libraries
import minify_html
from jinja2 import pass_context
from fastapi import (
    Request, 
    Response,
)
from fastapi.responses import HTMLResponse

# import local Python libraries
from utils import constants as C
from utils.classes import (
    User, 
    Jinja2TemplatesAsync,
)
import utils.functions.useful as useful
from gcp import (
    CloudStorage,
    GoogleComputerVision,
)

# import Python's standard libraries
from typing import Any

JINJA2_HANDLER = Jinja2TemplatesAsync(
    directory=str(C.APP_ROOT_PATH.joinpath("templates")), 
    trim_blocks=True,
    lstrip_blocks=True,
    enable_async=True,
)

# Overwrite the existing url_for global function in Jinja2 env
# As the url_for function by default will only return an absolute URL path
@pass_context
def __url_for(context: dict, name: str, external: bool = False, **path_params: Any) -> str:
    return useful.url_for(context["request"], name, external, **path_params)

@pass_context
def get_flashed_messages(context: dict) -> list[dict]:
    request: Request = context["request"]
    if C.FLASH_MESSAGES in request.session:
        return request.session.pop(C.FLASH_MESSAGES)
    else:
        return []

@pass_context
def get_csrf_token(context: dict) -> str:
    request: Request = context["request"]
    return request.session.get(C.CSRF_TOKEN_NAME)

@pass_context
def __browser_str_to_png_url(context: dict, browser_str: str) -> str:
    request: Request = context["request"]
    return useful.browser_str_to_png_url(request, browser_str)

def __get_post_max_length(user: User) -> int:
    return C.MAX_POST_LENGTH[user.mirai_plus]

# Set constants
JINJA2_HANDLER.env.globals["CSRF_HEADER_NAME"] = C.CSRF_HEADER_NAME
JINJA2_HANDLER.env.globals["DEBUG_MODE"] = C.DEBUG_MODE
JINJA2_HANDLER.env.globals["MAX_CHUNK_SIZE"] = C.MAX_CHUNK_SIZE
JINJA2_HANDLER.env.globals["SHOWN_IMAGE_MIMETYPES"] = list(GoogleComputerVision.supported_formats)
JINJA2_HANDLER.env.globals["SESSION_COOKIE"] = C.SESSION_COOKIE
JINJA2_HANDLER.env.globals["err_msg"] = "An error has occurred. Please try again later."
JINJA2_HANDLER.env.globals["validate_err"] = "Sorry! Please make sure that you have entered all the required fields correctly."
JINJA2_HANDLER.env.globals["MIRAI_SITE_KEY"] = C.MIRAI_SITE_KEY
JINJA2_HANDLER.env.globals["MESSAGE_TIMER_INT_TO_STR"] = C.MESSAGE_TIMER_INT_TO_STR

# Set functions
JINJA2_HANDLER.env.globals["url_for"] = __url_for
JINJA2_HANDLER.env.globals["get_csrf_token"] = get_csrf_token
JINJA2_HANDLER.env.globals["get_post_max_length"] = __get_post_max_length
JINJA2_HANDLER.env.globals["datetime_to_unix_time"] = useful.datetime_to_unix_time
JINJA2_HANDLER.env.globals["browser_str_to_png_url"] = __browser_str_to_png_url
JINJA2_HANDLER.env.globals["get_flashed_messages"] = get_flashed_messages
JINJA2_HANDLER.env.globals["truncate_text"] = useful.truncate_text
JINJA2_HANDLER.env.globals["generate_public_bucket_url"] = CloudStorage.generate_public_bucket_url

async def render_template(headers: dict[str, str] = None, *args: Any, **kwargs: Any) -> HTMLResponse:
    """Renders the Jinja2 template.
    Note: This function is the same as:
    >>> templates_handler.TemplateResponse(*args, **kwargs)

    FastAPI Jinja2 documentation:
    https://fastapi.tiangolo.com/advanced/templates/

    Args:
        name (str): 
            The file path of the HTML template to render.
        context (dict):
            The context to pass to the template.
            Note: Must include the request object.
        status_code (int):
            The status code to return.
        headers (dict):
            The headers to return.
        media_type (str):
            The media type to return.
        background (BackgroundTask):
            The background task to return.

    Returns:
        HTMLResponse:
            The rendered Jinja2 template
    """
    jinja2_response: Response = await JINJA2_HANDLER.TemplateResponse(*args, **kwargs)
    if not C.DEBUG_MODE:
        decoded_html_body = jinja2_response.body.decode(jinja2_response.charset)
        minified_html = minify_html.minify(
            code=decoded_html_body, 
            minify_js=True, 
            minify_css=True,
        )
        jinja2_response.body = minified_html.encode(jinja2_response.charset)
    jinja2_response.init_headers(headers)
    return jinja2_response