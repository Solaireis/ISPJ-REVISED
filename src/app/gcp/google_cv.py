# import third-party libraries
import orjson
from fastapi import Request

# import local Python libraries
from utils import constants as C
from .storage import CloudStorage
from .google_ai import GoogleAI
from .secret_manager import SecretManager
from utils.functions.useful import do_request

# import Python's standard libraries
import time
import asyncio
from typing import Self

class GoogleComputerVision(GoogleAI):
    """Google Computer Vision object to access the Computer Vision API.

    Docs: https://cloud.google.com/vision/docs/reference/rest
    """
    supported_formats = (
        # https://cloud.google.com/vision/docs/supported-files
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/bmp",
        "image/webp",
        "image/x-icon",
        "image/ico",
        "image/vnd.microsoft.icon",
        "image/tiff",
        "application/pdf",
    )
    max_size = 20 * 1024 * 1024
    base_url = "https://vision.googleapis.com"

    def __init__(self, credentials: dict | str | None = None) -> None:
        super().__init__(
            credentials=credentials,
            scopes=[
                "https://www.googleapis.com/auth/cloud-vision",
                "https://www.googleapis.com/auth/devstorage.read_only",
                "https://www.googleapis.com/auth/devstorage.read_write",
            ]
        )

    @classmethod
    async def init(cls, secret_manager: SecretManager | None = None, async_mode: bool | None = True) -> Self:
        """Initialise the class.

        Args:
            secret_manager (SecretManager | None):
                The SecretManager class to use. 
                Defaults to None and will create a new instance.
            async_mode (bool | None):
                Whether to use async mode or not.
                Defaults to None and will use async mode.
                Use it if the function is blocking any async I/O. 
                Otherwise, leave it as False to improve performance.

        Returns:
            GoogleComputerVision:
                The initialised class.
        """
        credentials = await cls.get_credentials_async(
            secret_manager=secret_manager,
            async_mode=async_mode,
        )
        return cls(
            credentials=credentials,
        )

    async def analyse_image(self, image_uri: str) -> dict:
        """Analyse an image for content moderation and sensitive data.

        Args:
            image_uri (str): 
                The GCS URI of the image.

        Returns:
            dict: 
                The response from the Computer Vision API.
        """
        headers = await self.get_authorised_headers()
        return await do_request(
            method="POST",
            url=f"{self.base_url}/v1/images:annotate",
            request_kwargs={
                "json": {
                    "requests": [
                        {
                            "image": {
                                "source": {
                                    "imageUri": image_uri,
                                },
                            },
                            "features": [
                                {
                                    "type": "SAFE_SEARCH_DETECTION",
                                },
                                {
                                    "type":"TEXT_DETECTION",
                                }
                            ],
                        },
                    ],
                },
                "headers": headers,
                "timeout": 30,
            },
            get_json=True,
        )

    async def get_operation_status(self, operation_name: str) -> dict:
        """Get the status of an operation.

        Args:
            operation_name (str): 
                The name of the operation. E.g. "operations/abc123"

        Returns:
            dict: 
                The response from the Computer Vision API.
        """
        headers = await self.get_authorised_headers()
        return await do_request(
            method="GET",
            url=f"{self.base_url}/v1/{operation_name}",
            request_kwargs={
                "headers": headers,
                "timeout": 10,
            },
            get_json=True,
        )

    async def analyse_pdf(self, pdf_uri: str) -> str:
        """Analyse a PDF for content moderation and sensitive data.

        Args:
            pdf_uri (str): 
                The URL of the PDF.

        Returns:
            str: 
                The URL of the output files in GCS.
        """
        headers = await self.get_authorised_headers()
        output_dir_uri = pdf_uri.rsplit(sep="/", maxsplit=1)[0] + "/analysis/"
        response = await do_request(
            method="POST",
            url=f"{self.base_url}/v1/files:asyncBatchAnnotate",
            request_kwargs={
                "json": {
                    "requests": [
                        {
                            "inputConfig": {
                                "gcsSource": {
                                    "uri": pdf_uri,
                                },
                                "mimeType": "application/pdf",
                            },
                            "features": [
                                {
                                    "type": "TEXT_DETECTION",
                                },
                            ],
                            "outputConfig": {
                                "gcsDestination": {
                                    "uri": output_dir_uri,
                                },
                                "batchSize": 5,
                            },
                        },
                    ],
                },
                "headers": headers,
                "timeout": 30,
            },
            get_json=True,
        )

        output_uri = ""
        start_time = time.time()
        operation_name = response["name"]
        done = False
        while not done:
            await asyncio.sleep(3)
            response = await self.get_operation_status(operation_name)
            done = response.get("done", False)
            error = response.get("error", {})
            if error:
                raise ValueError(error)

            if done:
                output_uri = response["response"]["responses"][0]["outputConfig"]["gcsDestination"]["uri"]

            if not done and time.time() - start_time > C.LONG_RUNNING_TASK_TIMEOUT:
                raise TimeoutError("Operation timed out.")

        return output_uri.split(sep="/", maxsplit=3)[-1]

    @staticmethod
    def process_safe_search_results(json_response: dict) -> dict:
        """Process the results of a safe search detection.

        Args:
            json_response (dict): 
                The response from the Computer Vision API.

        Returns:
            dict: 
                The processed results, e.g. {
                    "adult": "VERY_UNLIKELY",
                    "spoof": "VERY_UNLIKELY",
                    "medical": "VERY_UNLIKELY",
                    "violence": "VERY_UNLIKELY",
                    "racy": "VERY_UNLIKELY",
                }

        Raises:
            ValueError:
                If no safe search annotation is found.
        """
        for response in json_response["responses"]:
            if response.get("safeSearchAnnotation") is not None:
                return response["safeSearchAnnotation"]
        else:
            raise ValueError("No safe search annotation found.")

    @staticmethod
    async def process_text_detection_results(request: Request, json_response: dict, is_pdf: bool) -> str:
        """Process the results of a text detection.

        Args:
            request (Request):
                The request object.
            response (dict): 
                The response from the Computer Vision API.
            is_pdf (bool):
                Whether the text detection was performed on a PDF.

        Returns:
            str:
                The text detected in the image.
        """
        responses = []
        if is_pdf:
            cloud_storage: CloudStorage = request.app.state.obj_map[CloudStorage]
            # Download the blobs
            downloaded_blobs = await asyncio.gather(*[
                cloud_storage.download_blob(
                    bucket=blob["bucket"],
                    blob_name=blob["name"],
                ) for blob in json_response
            ])
            # Process the blobs and get the JSON data
            for blob in downloaded_blobs:
                blob_json = orjson.loads(blob)
                for response in blob_json.get("responses", []):
                    responses.append(response)
            # Delete the downloaded blobs from GCS 
            # since we don't need them anymore.
            await asyncio.gather(*[
                cloud_storage.delete_blob(
                    bucket=blob["bucket"],
                    blob_name=blob["name"],
                ) for blob in json_response
            ])

            json_response = {
                "responses": responses,
            }

        final_text = ""
        for response in json_response["responses"]:
            if response.get("fullTextAnnotation") is not None:
                final_text += f" {response['fullTextAnnotation']['text']}"

            if response.get("textAnnotations") is not None:
                for text in response["textAnnotations"]:
                    if text.get("locale") is not None:
                        final_text += f" {text}"

        return final_text

__all__ = [
    "GoogleComputerVision",
]