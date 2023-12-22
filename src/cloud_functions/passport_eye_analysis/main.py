# import third-party libraries
from fastapi import (
    FastAPI,
    Request,
)
from fastapi.logger import logger
from fastapi.responses import ORJSONResponse
import passporteye
from pydantic import (
    BaseModel, 
    Field,
)

# import Python's standard libraries
import io
import base64
from binascii import Error as BinasciiError

class RequestJson(BaseModel):
    """The JSON data sent to the Cloud Function."""
    image: str = Field(
        min_length=1,
        description="Base64 encoded image bytes",
    )

DEBUG_MODE = False
app = FastAPI(
    title="Mirai PassportEye",
    debug=DEBUG_MODE,
    version="1.0.0",
    default_response_class=ORJSONResponse,
    docs_url="/docs" if DEBUG_MODE else None,
    redoc_url="/redoc" if DEBUG_MODE else None,
    openapi_url="/openapi.json" if DEBUG_MODE else None,
    swagger_ui_oauth2_redirect_url=None
)

@app.post("/")
def image_analysis(request: Request, request_json: RequestJson):
    """Passport Eye image OCR analysis"""
    try:
        image_bytes: bytes = base64.b64decode(request_json.image)
    except (BinasciiError, ValueError, TypeError) as e:
        logger.error(f"Invalid Encoded Image Error:\n{e}")
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "Invalid image!",
            },
        )

    with io.BytesIO(image_bytes) as image_buf:
        try:
            mrz = passporteye.read_mrz(image_buf)
        except ValueError as e:
            logger.error(f"Error: {e}\nProbably due to unsupported image format.")
            return ORJSONResponse(
                status_code=400,
                content={
                    "message": "Unsupported image format!",
                },
            )

        if mrz is not None:
            return {
                "message": "Passport found!",
                "contains_passport": True,
            }

    return {
        "message": "No passport found!",
        "contains_passport": False,
    }