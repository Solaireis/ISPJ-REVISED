# import third-party libraries
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask
from starlette.responses import Response
from starlette.types import (
    Receive, 
    Scope, 
    Send,
)

# import Python's standard libraries
from typing import (
    Any, 
    Self,
)

class _TemplateResponse(Response):
    media_type = "text/html"

    def __init__(self, template: Any, context: dict, *args: Any, **kwargs: Any) -> None:
        self.template = template
        self.context = context
        super().__init__(*args, **kwargs)

    @classmethod
    async def init(
        cls,
        template: Any,
        context: dict,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        media_type: str | None = None,
        background: BackgroundTask | None = None,
    ) -> Self:
        content = await template.render_async(context)
        return cls(template, context, content, status_code, headers, media_type, background)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        request = self.context.get("request", {})
        extensions = request.get("extensions", {})
        if "http.response.template" in extensions:
            await send(
                {
                    "type": "http.response.template",
                    "template": self.template,
                    "context": self.context,
                }
            )
        await super().__call__(scope, receive, send)

class Jinja2TemplatesAsync(Jinja2Templates):
    """Jinja2 templates with async support."""
    async def TemplateResponse(
        self,
        name: str,
        context: dict,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        media_type: str | None = None,
        background: BackgroundTask | None = None,
    ) -> _TemplateResponse:
        if "request" not in context:
            raise ValueError('context must include a "request" key')
        template = self.get_template(name)
        return await _TemplateResponse.init(
            template,
            context,
            status_code=status_code,
            headers=headers,
            media_type=media_type,
            background=background,
        )