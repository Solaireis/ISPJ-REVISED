# import third-party libraries
import orjson
from fastapi.responses import ORJSONResponse

class PrettyORJSON(ORJSONResponse):
    """A modified version of the ORJSONResponse 
    class that returns an indented JSON response.
    """
    def render(self, content: dict[str, str]) -> bytes:
        return orjson.dumps(
            content, 
            option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_NUMPY | orjson.OPT_INDENT_2,
        )