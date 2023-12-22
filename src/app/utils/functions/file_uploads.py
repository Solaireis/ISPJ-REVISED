# import third-party libraries
import bson
from PIL import (
    Image, 
    ImageSequence,
)
from pymongo.errors import DuplicateKeyError
from pymongo.database import Database
from pymongo.collection import (
    Collection,
    ReturnDocument,
)
from fastapi import (
    Request, 
    UploadFile,
)
from fastapi.responses import ORJSONResponse
from fastapi.exceptions import HTTPException

# import local Python libraries
from utils import constants as C
from gcp import (
    CloudStorage,
    GoogleComputerVision,
    CloudFunction,
    crc32c,
)
from utils.functions.data_masking import(
    call_ai_api_and_analyse_text,

)
from utils.classes import (
    VtAnalysis,
)

# import Python's standard libraries
import io
import base64
import asyncio
import hashlib
import logging
from datetime import datetime

def validate_content_range(request: Request) -> ORJSONResponse | str:
    """Validates the content range header.

    Args:
        request (Request):
            The request object.

    Returns:
        ORJSONResponse | str:
            The content range header if it is valid. Otherwise, an error response.
    """
    content_range = request.headers.get("Content-Range")
    if content_range is None:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Missing content range.",
            },
        )
    if C.RANGE_CONTENT_REGEX.fullmatch(content_range) is None:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Invalid content range.",
            },
        )
    return content_range

def get_max_file_size(user_doc: dict, is_image_or_pdf: bool, is_video: bool) -> int:
    """Gets the maximum file size for the user.

    Args:
        user_doc (dict):
            The user document.
        is_image_or_pdf (bool):
            Whether the file is an image or a PDF.
        is_video (bool):
            Whether the file is a video.

    Returns:
        int:
            The maximum file size for the user.

    Raises:
        ValueError:
            If both is_image_or_pdf and is_video are True.
    """
    if is_image_or_pdf and is_video:
        raise ValueError("is_image_or_pdf and is_video cannot be both True.")

    has_mirai_plus = user_doc["mirai_plus"]
    if is_video:
        return C.PREM_MAX_VIDEO_SIZE if has_mirai_plus else C.MAX_VIDEO_SIZE

    if is_image_or_pdf:
        return C.PREM_MAX_IMAGE_PDF_SIZE if has_mirai_plus else C.MAX_IMAGE_PDF_SIZE

    return C.PREM_MAX_FILE_SIZE if has_mirai_plus else C.MAX_FILE_SIZE

def validate_file_size(content_range: str, user_doc: dict, is_image_or_pdf: bool, is_video: bool) -> ORJSONResponse | int:
    """Validates the file size for the user.

    Args:
        content_range (str):
            The content range header.
        user_doc (dict):
            The user document.
        is_image_or_pdf (bool):
            Whether the file is an image or a PDF.
        is_video (bool):
            Whether the file is a video.

    Returns:
        ORJSONResponse | int:
            The file size if it is valid. Otherwise, an error response.
    """
    max_file_size = get_max_file_size(
        user_doc=user_doc,
        is_image_or_pdf=is_image_or_pdf,
        is_video=is_video,
    )
    file_size = int(content_range.rsplit(sep="/", maxsplit=1)[1])
    if file_size > max_file_size:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": f"File is too large. Please upload a file smaller than {max_file_size} Bytes.",
            },
        )
    return file_size

def check_text_integrity(data: str, client_md5: str, client_cr32c: int) -> ORJSONResponse | None:
    """Checks the integrity of the text.

    Args:
        data (str):
            The text to check.
        client_md5 (str):
            The MD5 checksum received from the client.
        client_cr32c (int):
            The CRC32C checksum received from the client.

    Returns:
        ORJSONResponse | None:
            An error response if the text is corrupted. Otherwise, None.
    """
    if data is None:
        return

    if hashlib.md5(data.encode("utf-8")).hexdigest() != client_md5:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Text md5 checksum does not match.",
            },
        )
    if crc32c(data) != client_cr32c:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Text crc32c checksum does not match.",
            },
        )

def check_data_integrity(data: bytes, client_hash: str) -> ORJSONResponse | None:
    """Checks the integrity of the data by
    comparing the hash of the data to the client hash using SHA3-256.

    Args:
        data (bytes):
            The data to check.
        client_hash (str):
            The hash received from the client.

    Returns:
        ORJSONResponse | None:
            An error response if the data is corrupted. Otherwise, None.
    """
    uploaded_file_hash = hashlib.sha3_256(data).hexdigest()
    if uploaded_file_hash != client_hash:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "File hash does not match.",
            },
        )

def get_image_size_for_resizing(width: int, height: int, 
                                min_width: int, max_width: int,
                                min_height: int, max_height: int) -> tuple[int, int]:
    """Checks the width of the image if it is within the range of 
    the minimum to the maximum height/width.
    Otherwise, it will return the closest value to the range for resizing.

    It will detect if the image is landscape or portrait and 
    use the height and width arguments accordingly.

    Args:
        width (int):
            The width of the image.
        min_width (int):
            The minimum width of the image.
        max_width (int):
            The maximum width of the image.

    Returns:
        tuple[int, int]:
            The width and height of the image for resizing
    """
    # calculate the image ratio
    image_ratio = width / height

    # check if the image is landscape or portrait
    if image_ratio > 1:
        # image is landscape
        if width < min_width:
            width = min_width
        elif width > max_width:
            width = max_width
        height = int(width / image_ratio)
    else:
        # image is portrait
        if height < min_height:
            height = min_height
        elif height > max_height:
            height = max_height
        width = int(height * image_ratio)

    return width, height

async def compress_and_save_image(
    request: Request,
    image: Image.Image, bucket: str, blob_name: str, 
    fixed_size: bool | None = False, 
    is_animated: bool | None = False,
    cache_controls: str | None = C.DEFAULT_CACHE_CONTROLS,
    optimise: bool | None = True, quality: int | None = 80,
    min_width: int | None = 320, max_width: int | None = 1080,
    min_height: int | None = 320, max_height: int | None = 1080
) -> str | None:
    """Compresses the image to WEBP and saves it to the GCS bucket.

    Args:
        request (Request):
            The request object.
        image (Image.Image):
            The image to compress.
        bucket (str):
            The GCS bucket to save the image to.
        blob_name (str):
            The GCS blob name to save the image to.
        fixed_size (bool):
            Whether to resize the image to a fixed size.
            If this is True, the image will be resized to the max_width and max_height.
        is_animated (bool):
            Whether the image is animated. If not provided, the check will be done within the function.
        cache_controls (str | None):
            The cache control headers to set for the uploaded file. 
            Defaults to C.DEFAULT_CACHE_CONTROLS.
        optimise (bool | None):
            Whether to optimise the image.
        quality (int | None):
            The quality of the image. Defaults to 80.
        min_width (int | None):
            The minimum width of the image. Defaults to 320.
        max_width (int | None):
            The maximum width of the image. Defaults to 1080.
        min_height (int | None):
            The minimum height of the image. Defaults to 320.
        max_height (int | None):
            The maximum height of the image. Defaults to 1080.

    Returns:
        str | None:
            The GCS blob name of the compressed image if it is not animated. Otherwise, None.
    """
    if is_animated or (hasattr(image, "is_animated") and image.is_animated):
        heights = set()
        widths = set()
        frame: Image.Image
        images: list[Image.Image] = []
        for frame in ImageSequence.Iterator(image):
            widths.add(frame.width)
            heights.add(frame.height)
            images.append(frame.copy())

        # Resize the image to the width
        if not fixed_size:
            width, height = get_image_size_for_resizing(
                width=max(widths),
                min_width=min_width,
                max_width=max_width,
                height=max(heights),
                min_height=min_height,
                max_height=max_height,
            )
        else:
            width, height = max_width, max_height

        images = [frame.resize((width, height)) for frame in images]

        with io.BytesIO() as buffer:
            images[0].save(
                buffer,
                format="WEBP",
                save_all=True,
                append_images=images[1:],
                optimize=optimise,
                quality=quality,
            )
            image_bytes = buffer.getvalue()
    else:
        # Resize the image to the width
        if not fixed_size:
            width, height = get_image_size_for_resizing(
                width=image.width,
                min_width=min_width,
                max_width=max_width,
                height=image.height,
                min_height=min_height,
                max_height=max_height,
            )
        else:
            width, height = max_width, max_height

        image = image.resize((width, height))
        with io.BytesIO() as buffer:
            image.save(buffer, format="WEBP", optimise=optimise, quality=quality)
            image_bytes = buffer.getvalue()

    blob_parts = blob_name.rsplit(sep="/", maxsplit=1)
    blob_dirs = blob_parts[0]
    blob_filename = blob_parts[1]
    if not blob_filename.endswith(".webp"):
        blob_filename = blob_filename.rsplit(sep=".", maxsplit=1)[0] + ".webp"

    blob_name = f"{blob_dirs}/compressed/{blob_filename}"
    cloud_storage: CloudStorage = request.app.state.obj_map[CloudStorage]
    await cloud_storage.upload_blob_from_memory(
        bucket=bucket,
        data=image_bytes,
        destination_blob_name=blob_name,
        mimetype="image/webp",
        cache_controls=cache_controls,
    )
    return blob_name

async def analyse_image_or_pdf(
    request: Request,
    file_hash: str, 
    is_pdf: bool,
    mimetype: str, 
    bucket_name: str,
    blob_name: str, 
    file_col: Collection,
    file_doc_id: bson.ObjectId,
    matched_file_doc: dict | None,
) -> ORJSONResponse | dict | None:
    """Analyses the image or PDF using Google Computer Vision API.

    Args:
        request (Request):
            The request object.
        file_hash (bytes):
            The SHA3-256 hash of the file.
        is_pdf (bool):
            Whether the file is a PDF.
        mimetype (str):
            The mimetype of the file.
        blob_name (str):
            The name of the blob in GCS.
        bucket_name (str):
            The name of the bucket in GCS.
        file_col (Collection):
            The file collection in the database.
        matched_file_doc (dict | None):
            The file document from the database if it exists.

    Returns:
        None:
            If the mimetype is not supported by Google Computer Vision API, return None.
        ORJSONResponse:
            If the request to Google Computer Vision API fails or 
            the image contains sensitive data like NRIC, return an error response.
            Note that this would also result in the blob being deleted from GCS.
        dict:
            The safe search annotation.
    """
    if mimetype not in GoogleComputerVision.supported_formats:
        # Even though RAW images are supported by Google Vision API,
        # it would be better to show them as a file rather than an image.
        return

    sensitive_data_response = ORJSONResponse(
        status_code=422,
        content={
            "message": f"{'PDF' if is_pdf else 'Image'} file contains sensitive data which is not allowed.",
        },
    )
    error_response = ORJSONResponse(
        status_code=400,
        content={
            "message": f"Something went wrong while processing the {'PDF' if is_pdf else 'image'} file.",
        }
    )

    if matched_file_doc is not None and "safe_search_annotations" in matched_file_doc and "contain_sensitive_data" in matched_file_doc:
        if matched_file_doc["contain_sensitive_data"]:
            return sensitive_data_response
        return matched_file_doc["safe_search_annotations"]

    cloud_storage: CloudStorage = request.app.state.obj_map[CloudStorage]
    cloud_cv: GoogleComputerVision = request.app.state.obj_map[GoogleComputerVision]
    if not is_pdf:
        analysis_result = await cloud_cv.analyse_image(
            cloud_storage.get_gcs_uri(
                bucket=bucket_name,
                blob_name=blob_name,
            ),
        )
    else:
        gcs_output_files_uri = await cloud_cv.analyse_pdf(
            cloud_storage.get_gcs_uri(
                bucket=bucket_name,
                blob_name=blob_name,
            ),
        )
        analysis_result = await cloud_storage.list_blob(
            bucket=bucket_name,
            prefix=gcs_output_files_uri,
        )
        if not analysis_result:
            return error_response 

    safe_search_annotations = {}
    try:
        if not is_pdf:
            safe_search_annotations = cloud_cv.process_safe_search_results(
                json_response=analysis_result,
            )
        detected_text = await cloud_cv.process_text_detection_results(
            request=request,
            json_response=analysis_result,
            is_pdf=is_pdf,
        )
    except (ValueError):
        logging.exception(f"Error while processing Google Vision API results.\nAnalysis Result: {analysis_result}")
        await cloud_storage.delete_blob(
            bucket=bucket_name,
            blob_name=blob_name,
        )
        return error_response

    contain_sensitive_data = False
    if await call_ai_api_and_analyse_text(request, detected_text):
        await cloud_storage.delete_blob(
            bucket=bucket_name,
            blob_name=blob_name,
        )
        contain_sensitive_data = True

    try:
        await file_col.update_one(
            filter={"_id": file_doc_id},
            update={
                "$set": {
                    "identifier": file_hash,
                    "contain_sensitive_data": contain_sensitive_data,
                    "safe_search_annotations": safe_search_annotations,
                    "updated_at": datetime.utcnow(),
                },
            },
            upsert=True,
        )
    except (DuplicateKeyError):
        pass

    return sensitive_data_response if contain_sensitive_data else safe_search_annotations 

async def analyse_image_for_mrz(
    request: Request,
    file_hash: str, 
    chunk_bytes: bytes, 
    file_col: Collection, 
    file_doc_id: bson.ObjectId,
    matched_file_doc: dict | None,
) -> ORJSONResponse | None:
    """Analyse the image for Machine Readable Zone (MRZ).

    Args:
        request (Request):
            The request object.
        file_hash (str):
            The hash of the file (SHA3-256).
        chunk_bytes (bytes):
            The bytes of the chunk that was uploaded.
        file_col (Collection):
            MongoDB collection object for the file collection.
        file_doc_id (bson.ObjectId):
            The MongoDB document ID of the file.
        matched_file_doc (dict | None):
            The MongoDB document of the file if it exists.

    Returns:
        ORJSONResponse | None:
            Returns a response if the image contains a MRZ, else returns None.
    """
    contains_passport_response = ORJSONResponse(
        status_code=422,
        content={
            "message": "Passport detected in image which is not allowed.",
        },
    )
    if matched_file_doc is not None and "contains_passport" in matched_file_doc:
        if matched_file_doc["contains_passport"]:
            return contains_passport_response
        return

    cloud_function: CloudFunction = request.app.state.obj_map[CloudFunction]
    passport_eye_response = await cloud_function.invoke_instance(
        url=C.PASSPORT_EYE_URL_FUNCTION,
        json={
            "image": base64.b64encode(chunk_bytes).decode("utf-8"),
        },
        timeout=120, # longer timeout due to cold start
    )
    contains_passport = passport_eye_response["contains_passport"]
    await file_col.update_one(
        filter={"_id": file_doc_id},
        update={
            "$set": {
                "identifier": file_hash,
                "contains_passport": contains_passport,
                "updated_at": datetime.utcnow(),
            },
        },
        upsert=True,
    )
    if contains_passport:
        logging.info(f"Passport detected in the image with a hash of {file_hash}.")
        return contains_passport_response

async def main_analysis_process(
    request: Request,
    db: Database,
    chunk_hash: str,
    chunk_bytes: bytes,
    is_pdf: bool,
    mimetype: str,
    bucket_name: str,
    blob_name: str,
    is_image: bool,
    is_animated_image: bool,
) -> ORJSONResponse | tuple[dict, bool]:
    """The main analysis process for the uploaded file.

    Args:
        request (Request):
            The request object.
        db (Database):
            MongoDB database object.
        chunk_hash (str):
            The hash of the chunk that was uploaded.
        chunk_bytes (bytes):
            The bytes of the chunk that was uploaded.
        is_pdf (bool):
            Whether the file is a PDF.
        mimetype (str):
            The mimetype of the file.
        bucket_name (str):
            The name of the bucket that the file was uploaded to.
        blob_name (str):
            The name of the blob that the file was uploaded to.
        is_image (bool):
            Whether the file is an image.
        is_animated_image (bool):
            Whether the file is an animated image.

    Returns:
        ORJSONResponse | tuple[dict, bool]:
            Returns a response if the file contains sensitive data, else returns a tuple of the safe search annotations and whether the image is valid.
    """
    chunk_hash = chunk_hash.lower()
    file_col = db[C.FILE_ANALYSIS_COLLECTION]
    matched_file_doc = await file_col.find_one(
        filter={"identifier": chunk_hash},
    )
    file_doc_id = bson.ObjectId() if matched_file_doc is None else matched_file_doc["_id"]

    analysis_tasks = []
    analysis_tasks.append(
        analyse_image_or_pdf(
            request=request,
            file_hash=chunk_hash, # Note: images and pdf are uploaded in one chunk
            is_pdf=is_pdf,
            mimetype=mimetype,
            bucket_name=bucket_name,
            blob_name=blob_name,
            file_col=file_col,
            file_doc_id=file_doc_id,
            matched_file_doc=matched_file_doc,
        ),
    )
    if is_image and not is_animated_image:
        analysis_tasks.append(
            analyse_image_for_mrz(
                request=request,
                file_hash=chunk_hash,
                chunk_bytes=chunk_bytes,
                file_col=file_col,
                file_doc_id=file_doc_id,
                matched_file_doc=matched_file_doc,
            ),
        )

    try:
        analysis_tasks = await asyncio.gather(*analysis_tasks)
    except HTTPException:
        return ORJSONResponse(
            status_code=500,
            content={
                "message": "Error occurred while analysing image or PDF.",
            },
        )

    if is_image and not is_animated_image:
        passport_eye_response = analysis_tasks[1]
        if isinstance(passport_eye_response, ORJSONResponse):
            return passport_eye_response # image has sensitive data like a passport with MRZ

    safe_search_annotation = {}
    treat_image_as_file = False
    safe_search_response = analysis_tasks[0]
    if isinstance(safe_search_response, ORJSONResponse):
        if safe_search_response.status_code == 500:
            treat_image_as_file = True # caused by errors like bad image data
        else:
            return safe_search_response # image has sensitive data like NRIC
    elif safe_search_response is not None:
        safe_search_annotation = safe_search_response

    return (safe_search_annotation, treat_image_as_file)

def analyse_safe_search_annotations(safe_search_annotations: dict) -> bool:
    """Analyse the safe search annotations from Google Cloud Vision API.

    Args:
        safe_search_annotations (dict):
            The safe search annotations from Google Cloud Vision API.

    Returns:
        bool:
            Returns True if the image is safe, else returns False.
    """
    image_is_safe = True
    for key, value in safe_search_annotations.items():
        if key in ("adult", "violence") and value in ("LIKELY", "VERY_LIKELY"):
            image_is_safe = False
            break
    return image_is_safe

async def finalise_file_upload(
    request: Request,
    db: Database,
    upload_id: str,
    chunk_hash: str,
    chunk_bytes: bytes,
    mimetype: str,
    filename: str,
    file_size: int,
    bucket_name: str,
    blob_name: str,
    compressed_blob_name: str,
    is_image: bool,
    is_animated_image: bool,
    treat_image_as_file: bool,
    is_pdf: bool | None = False,
    only_one_video: bool | None = False,
) -> ORJSONResponse | dict:
    """Finalise the file upload by doing some checks and 
    deleting the upload_id document from the database once the checks are done.

    Args:
        db (Database): 
            MongoDB database client object.
        upload_id (str):
            The upload ID that the user used when uploading to Mirai.
        chunk_hash (str):
            The hash of the chunk that was uploaded (SHA3-256).
        chunk_bytes (bytes):
            The chunk bytes that were uploaded.
        mimetype (str):
            The MIME type of the file.
        filename (str):
            The filename of the file.
        file_size (int):
            The size of the file.
        bucket_name (str):
            The name of the bucket in GCS.
        blob_name (str):
            The name of the blob in GCS.
        compressed_blob_name (str):
            The name of the compressed blob in GCS.
        is_image (bool):
            Whether the file is an image.
        treat_image_as_file (bool):
            Whether the image should be treated as a file.
        is_pdf (bool, optional):
            Whether the file is a PDF. Defaults to False.
        only_one_video (bool, optional):
            Used for Mirai posts where either only one video 
            is allowed or up to 4 images at a time. Defaults to False.

    Returns:
        ORJSONResponse | dict:
            Returns ORJSONResponse if the checks fail or 
            if all the files have not been uploaded yet.
            else returns dict of the updated upload doc.
    """
    safe_search_annotation = {}
    do_image_pdf_analysis = (is_pdf or (is_image and not treat_image_as_file))
    vt_api_key: str = request.app.state.vt_api_key
    async with VtAnalysis(vt_api_key) as vt_client:
        tasks = [
            vt_client.check_blob(
                request=request,
                bucket=bucket_name,
                blob_name=blob_name,
            ),
        ]
        if do_image_pdf_analysis:
            tasks.append(
                main_analysis_process(
                    request=request,
                    db=db,
                    chunk_hash=chunk_hash,
                    chunk_bytes=chunk_bytes,
                    is_pdf=is_pdf,
                    mimetype=mimetype,
                    bucket_name=bucket_name,
                    blob_name=blob_name,
                    is_image=is_image,
                    is_animated_image=is_animated_image,
                ),
            )
        finished_tasks = await asyncio.gather(*tasks)

    if do_image_pdf_analysis:
        analysis_result = finished_tasks[1]
        if isinstance(analysis_result, ORJSONResponse):
            return analysis_result

        safe_search_annotation, treat_image_as_file = analysis_result

    if finished_tasks[0]:
        return ORJSONResponse(
            status_code=422,
            content={
                "message": "Uploaded file has been flagged as malicious."
            }
        )

    data = {
        "blob_id": bson.ObjectId(),
        "type": mimetype,
        "bucket_name": bucket_name,
        "blob_name": blob_name,
        "filename": filename,
        "file_size": file_size,
        "safe_search_annotation": safe_search_annotation,
    }
    if is_image:
        data["spoiler"] = filename.upper().startswith("SPOILER_")
        data["treat_image_as_file"] = treat_image_as_file
        if compressed_blob_name is not None:
            data["compressed_blob_name"] = compressed_blob_name

    upload_ids_col = db[C.UPLOAD_IDS_COLLECTION]
    latest_upload_doc: dict | None = await upload_ids_col.find_one_and_update(
        filter={"_id": upload_id},
        update={
            "$pull": {
                "files": {
                    "blob_name": blob_name,
                },
            },
            "$addToSet": {
                "uploaded_files": data,
            }
        },
        return_document=ReturnDocument.AFTER,
    )
    if latest_upload_doc is None:
        # Shouldn't happen but just in case
        return ORJSONResponse(
            status_code=404,
            content={
                "message": "Upload ID not found.",
            },
        )

    if only_one_video:
        err_msg = "You can only either upload a video or up to 4 images at once.\nPlease re-upload with a new upload ID."
        has_video = False
        has_image = False
        for file in latest_upload_doc["uploaded_files"]:
            if file["type"].startswith("video"):
                has_video = True
            else:
                has_image = True

        if (has_video and len(latest_upload_doc["uploaded_files"]) > 1) or (has_video and has_image):
            await upload_ids_col.delete_one({"_id": upload_id})
            return ORJSONResponse(
                status_code=400,
                content={
                    "message": err_msg,
                },
            )

    if len(latest_upload_doc["uploaded_files"]) != latest_upload_doc["number_of_files"]:
        return ORJSONResponse(
            status_code=200,
            content={
                "message": f"{filename} uploaded successfully.",
            },
        )

    if len(latest_upload_doc["files"]) != 0:
        return ORJSONResponse(
            status_code=400,
            content={
                "message": "You have not uploaded all the files yet!",
            },
        )

    await upload_ids_col.delete_one({"_id": upload_id})
    return latest_upload_doc