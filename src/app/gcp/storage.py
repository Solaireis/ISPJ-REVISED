# import third-party libraries
import six
import bson
from fastapi import Request
from fastapi.responses import ORJSONResponse
from fastapi.exceptions import HTTPException
from pymongo.database import Database
from google_crc32c import Checksum as g_crc32c

# import local Python libraries
from .secret_manager import SecretManager
from .gcp_rest import GcpRestApi
from .kms import GcpAesGcm
from utils import constants as C
from utils.functions import (
    useful,
    security as sec,
)

# import Python"s standard libraries
import base64
import pathlib
import hashlib
import datetime
from typing import Any, Self
import urllib.parse as urlparse

class CloudStorage(GcpRestApi):
    @classmethod
    async def init(cls, secret_manager: SecretManager | None = None, async_mode: bool | None = True) -> Self:
        """Initialises the class.

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
            Self:
                The initialised class.
        """
        if secret_manager is None:
            if async_mode:
                secret_manager = await SecretManager.init()
            else:
                secret_manager = SecretManager()

        if async_mode:
            credentials = await secret_manager.get_secret_payload_async("cloud-storage")
        else:
            credentials = secret_manager.get_secret_payload("cloud-storage")
        return cls(
            credentials=credentials, 
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

    @staticmethod
    def parse_object_name(blob_name: str) -> str:
        """Parses an blob name via URL encoding."""
        return urlparse.quote(blob_name, safe="")

    @staticmethod
    def get_content_type(mimetype: str | None) -> str:
        if mimetype is None or mimetype.strip() == "":
            mimetype = "application/octet-stream"
        return mimetype

    @staticmethod
    def get_md5_checksum(data: bytes) -> str:
        """Get a base64 encoded MD5 checksum of the provided data."""
        return base64.b64encode(hashlib.md5(data).digest()).decode("utf-8")

    @staticmethod
    def get_crc32c_checksum(data: bytes) -> str:
        """Get a base64 encoded CRC32C checksum of the provided data."""
        return base64.b64encode(
            g_crc32c(initial_value=six.ensure_binary(data, encoding="utf-8")).digest()
        ).decode("utf-8")

    @staticmethod
    def generate_url(bucket_name: str, blob_name: str) -> str:
        """Generates a URL for a blob in a bucket.

        Args:
            bucket_name (str):
                The name of the bucket that the file was uploaded in.
            blob_name (str):
                The name of the blob that was uploaded (e.g. "profile/my_file.txt").

        Returns:
            str: The URL for the blob.
        """
        return f"https://storage.googleapis.com/{bucket_name}/{blob_name}"

    def generate_public_bucket_url(self, blob_name: str) -> str:
        """Generates a URL for a blob in a public bucket.

        Args:
            blob_name (str):
                The name of the blob that was uploaded (e.g. "profile/my_file.txt").

        Returns:
            str: The URL for the blob.
        """
        return self.generate_url(C.PUBLIC_BUCKET, blob_name)

    @staticmethod
    def get_gcs_uri(bucket: str, blob_name: str) -> str:
        """Gets the GCS URI for a blob.

        Args:
            bucket (str):
                The bucket to upload to.
            blob_name (str):
                The name of the blob to upload to in the bucket (e.g. "profile/my_file.txt").

        Returns:
            str:
                The GCS URI for the blob.
        """
        return f"gs://{bucket}/{blob_name}"

    async def upload_blob_from_memory(self, 
        bucket: str, 
        data: bytes, 
        destination_blob_name: str, 
        mimetype: str | None = None, 
        cache_controls: str | None = None,
    ) -> None:
        """Uploads a file to a bucket in Google Cloud Storage using their XML API.

        Args:
            bucket (str):
                The name of the bucket to upload to.
            data (bytes):
                The data to upload.
            destination_blob_name (str):
                The name of the blob to upload to in the bucket (e.g. "profile/my_file.txt").
            mimetype (str | None):
                The mimetype of the data. E.g. "image/png". 
                If None, Cloud Storage defaults to application/octet-stream when it serves the uploaded object.
            cache_controls (str | None):
                The cache control headers to set for the uploaded file.
                Defaults to C.DEFAULT_CACHE_CONTROLS.

        Returns:
            None
        """
        headers = await self.get_authorised_headers()
        headers.update({
            "Content-Type": self.get_content_type(mimetype),
            "Content-Length": str(len(data)),
            "Content-MD5": self.get_md5_checksum(data),
            "x-goog-hash": f"crc32c={self.get_crc32c_checksum(data)}",
            "Cache-Control": cache_controls if cache_controls is not None \
                                            else C.DEFAULT_CACHE_CONTROLS,
        })

        blob_name = self.parse_object_name(destination_blob_name)
        await useful.do_request(
            method="PUT",
            url=f"https://{bucket}.storage.googleapis.com/{blob_name}",
            request_kwargs={
                "headers": headers,
                "data": data,
            },
        )

    async def generate_upload_token(self,
        request: Request,
        db: Database, 
        user_id: str, 
        bucket_name: str, 
        number_of_files: int, 
        purpose: str, 
        encrypt_msg: bool, 
        text_msg: str | None = None, 
        extra_data: dict[str, Any] | None = None,
    ) -> str:
        """Generates an upload token for a resumable upload and stores it in the database.

        Args:
            request (Request):
                The request object.
            db (Database):
                The pymongo database object.
            user_id (str):
                The ID of the user who is uploading the file.
            bucket_name (str):
                The name of the bucket to upload to.
            number_of_files (int):
                The number of files that are being uploaded.
            purpose (str):
                The purpose of the upload.
            text_msg (str | None):
                The text message that the file is being uploaded for.
            encrypt_msg (bool):
                Whether or not to encrypt the text message. 
            extra_data (dict[str, Any] | None):
                Extra data to add to the file document.

        Returns:
            str:
                The encrypted and signed upload token.

        Raises:
            ValueError: 
                If the purpose is invalid.
        """
        if text_msg is not None:
            stripped_text = text_msg.strip()
            if not stripped_text:
                text_msg = None
            else:
                text_msg = stripped_text

        if encrypt_msg and text_msg is not None:
            aes_gcm: GcpAesGcm = request.app.state.obj_map[GcpAesGcm]
            text_msg = await aes_gcm.symmetric_encrypt(
                plaintext=text_msg,
                key_id=C.DATABASE_KEY,
            )
            text_msg = bson.Binary(text_msg)

        col = db[C.UPLOAD_IDS_COLLECTION]
        data = extra_data \
                if extra_data is not None else {}
        data.update({
            "_id": bson.ObjectId(),
            "purpose": purpose,
            "created_at": datetime.datetime.utcnow(),
            "created_by": user_id,
            "message": text_msg,
            "bucket_name": bucket_name,
            "number_of_files": number_of_files,
            "files": [],
        })

        await col.insert_one(data)
        signer = sec.get_hmac_signer(C.UPLOAD_ID_EXPIRY)
        upload_token = signer.sign({"upload_id": str(data["_id"])})
        return await sec.encrypt_token(
            request=request,
            token=upload_token,
            key_id=C.TOKEN_KEY,
        )

    @staticmethod
    async def decrypt_and_unsign_upload_id(request: Request, encrypted_token: str) -> str | ORJSONResponse:
        """Decrypts and unsigns the upload token to get the upload id for GCS resumable uploads.

        Args:
            request (Request):
                The request object.
            encrypted_token (str):
                The encrypted and signed upload token.

        Returns:
            str | ORJSONResponse:
                The unsigned upload id if it is valid. Otherwise, an error response.
        """
        decrypted_token = await sec.decrypt_token(request, encrypted_token)
        signer = sec.get_hmac_signer(C.UPLOAD_ID_EXPIRY)
        token = signer.get(decrypted_token)
        if token is None or token.get("upload_id") is None:
            return ORJSONResponse(
                status_code=422,
                content={
                    "message": "Invalid or expired upload id.",
                },
            )
        return token["upload_id"]

    async def append_file_to_document(self, 
        request: Request,
        db: Database,
        user_id: str, 
        filename: str,
        file_md5_checksum: str, 
        file_crc32c_checksum: str, 
        destination_blob_name: str, 
        mimetype: str, 
        upload_token: str,
    ) -> tuple[dict[str, str] | ORJSONResponse, bson.ObjectId | None, dict[str, Any] | None]:
        """Generates or returns an GCS upload URL for a resumable upload for a file.

        Args:
            request (Request):
                The request object.
            db (Database):
                The pymongo database object.
            user_id (str):
                The ID of the user who is uploading the file.
            filename (str):
                The name of the file.
            file_md5_checksum (str):
                The MD5 checksum of the entire file.
            file_crc32c_checksum (str):
                The CRC32C checksum of the entire file.
            destination_blob_name (str):
                The name of the blob in GCS.
            mimetype (str):
                The mimetype of the file.
            upload_token (str):
                The upload token.

        Returns:
            tuple[dict[str, str] | ORJSONResponse, bson.ObjectId | None, dict[str, Any] | None]:
                The file information of the blob in the database or 
                an ORJSONResponse if the upload id is not found, 
                user is not the owner of the upload token, 
                or the user is uploading more than the max files specified.
                Also returns the upload ID and the whole upload ID document if it was found.
        """
        upload_id = await self.decrypt_and_unsign_upload_id(
            request=request,
            encrypted_token=upload_token,
        )
        if isinstance(upload_id, ORJSONResponse):
            return upload_id, None, None

        upload_id = bson.ObjectId(upload_id)
        mimetype = self.get_content_type(mimetype)
        col = db[C.UPLOAD_IDS_COLLECTION]
        existing_file_doc = await col.find_one({
            "_id": upload_id,
        })
        if existing_file_doc is None:
            return ORJSONResponse(
                status_code=404,
                content={
                    "message": "Upload ID not found.",
                },
            ), None, None

        bucket_name = existing_file_doc["bucket_name"]
        if existing_file_doc["created_by"] != user_id:
            return ORJSONResponse(
                status_code=400,
                content={
                    "message": "You are not the owner of this message.",
                },
            ), None, None

        max_files: int = existing_file_doc["number_of_files"]
        file_info: dict[str, str] = {}
        files: list[dict[str, str]] = existing_file_doc["files"]
        for file in files:
            if file["filename"] == filename:
                file_info = file
                break
        else:
            if len(files) >= max_files:
                return ORJSONResponse(
                    status_code=400,
                    content={
                        "message": f"Maximum number of files ({max_files}) reached.",
                    },
                ), None, None

            upload_url = await self.initiate_resumable_upload(
                bucket_name=bucket_name,
                destination_blob_name=destination_blob_name,
                mimetype=mimetype,
                md5_checksum=file_md5_checksum,
                crc32c_checksum=file_crc32c_checksum,
            )
            file_info = {
                "filename": filename,
                "upload_url": upload_url,
                "blob_name": destination_blob_name,
                "mimetype": mimetype,
            }
            await col.update_one({
                "_id": upload_id,
            }, {
                "$addToSet": {
                    "files": file_info,
                }
            })
        return file_info, upload_id, existing_file_doc

    async def initiate_resumable_upload(self, 
        bucket_name: str, 
        destination_blob_name: str, 
        md5_checksum: str, 
        crc32c_checksum: str,
        mimetype: str | None = None, 
        cache_controls: str | None = None, 
    ) -> str:
        """Initiates a resumable upload to a bucket in Google Cloud Storage using their XML API.

        Args:
            bucket_name (str):
                The name of the bucket to upload to.
            destination_blob_name (str):
                The name of the blob to upload to in the bucket (e.g. "profile/my_file.txt").
            md5_checksum (str):
                The base64 encoded MD5 checksum of the file.
            crc32c_checksum (str):
                The base64 encoded CRC32C checksum of the file.
            mimetype (str | None):
                The mimetype of the data. E.g. "image/png".
                Defaults to "application/octet-stream" if None.
            cache_controls (str | None):
                The cache control headers to set for the uploaded file.
                Defaults to C.CHAT_CACHE_CONTROLS if None.

        Returns:
            str:
                The upload ID for the resumable upload.
        """
        headers = await self.get_authorised_headers()
        headers.update({
            "x-goog-resumable": "start",
            "Content-Type": self.get_content_type(mimetype),
            "Content-MD5": md5_checksum,
            "x-goog-hash": f"crc32c={crc32c_checksum}",
            "Cache-Control": cache_controls if cache_controls is not None \
                                            else C.CHAT_CACHE_CONTROLS,
        })

        blob_name = self.parse_object_name(destination_blob_name)
        response = await useful.do_request(
            method="POST",
            url=f"https://{bucket_name}.storage.googleapis.com/{blob_name}",
            request_kwargs={
                "headers": headers,
            },
        )
        return response.headers["location"]

    async def resumable_upload_blob_from_memory(self, data: bytes, content_range: str, upload_url: str) -> int:
        """Uploads a file to a bucket in Google Cloud Storage using their XML API.

        Args:
            data (bytes):
                The data to upload.
            content_range (str):
                The content range of the data. E.g. "bytes 0-1023/1024".
            upload_url (str):
                The upload URL for the resumable upload.

        Returns:
            int:
                200 if the upload is complete, 308 if the upload is incomplete.
        """
        headers = await self.get_authorised_headers()
        headers.update({
            "Content-Length": str(len(data)),
            "Content-Range": content_range,
        })
        response = await useful.do_request(
            method="PUT",
            url=upload_url,
            request_kwargs={
                "headers": headers,
                "data": data,
            },
            check_status=False,
            get_response=True,
        )

        if response.status_code == 308 or response.status_code == 200:
            return response.status_code
        raise HTTPException(
            status_code=response.status_code, 
            detail="Failed to upload file.",
        )

    async def download_blob(self, bucket: str, blob_name: str, file_path: pathlib.Path | None = None) -> bytes | None:
        """Downloads a blob from Google Cloud Storage using their JSON API.

        Args:
            bucket (str):
                The name of the bucket to download from.
            blob_name (str):
                The name of the blob to download from the bucket (e.g. "profile/my_file.txt").
            file_path (pathlib.Path, optional):
                The path to save the file to. Defaults to None where the blob is downloaded to memory.

        Returns:
            bytes | None:
                The data of the blob if downloaded to memory, None if downloaded to a file.
        """
        headers = await self.get_authorised_headers()
        blob_name = self.parse_object_name(blob_name)
        return await useful.download_url(
            method="GET",
            url=f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{blob_name}?alt=media",
            file_path=file_path,
            request_kwargs={
                "headers": headers,
            },
        )

    async def list_blob(self, bucket: str, prefix: str | None = None, delimiter: str | None = None) -> list[dict]:
        """Lists all blobs in a bucket that match a pattern using their JSON API.

        Args:
            bucket (str):
                The name of the bucket to list blobs from.
            pattern (str, optional):
                The pattern to match the blob names against. Defaults to None.
            delimiter (str, optional):
                The delimiter to use to separate the blob names. Defaults to None.

        Returns:
            list[dict]:
                The JSON response from the API.
        """
        headers = await self.get_authorised_headers()
        blobs_arr, page_token = [], None
        params = {}
        if prefix is not None:
            params["prefix"] = prefix
        if delimiter is not None:
            params["delimiter"] = delimiter

        while True:
            if page_token is not None:
                params["pageToken"] = page_token
            else:
                params.pop("pageToken", None)

            response = await useful.do_request(
                method="GET",
                url=f"https://storage.googleapis.com/storage/v1/b/{bucket}/o",
                request_kwargs={
                    "params": params,
                    "headers": headers,
                },
                get_json=True,
            )
            if "items" in response:
                blobs_arr.extend(response["items"])

            page_token = response.get("nextPageToken")
            if page_token is None:
                break

        return blobs_arr

    async def delete_blob(self, bucket: str, blob_name: str) -> None:
        """Deletes a blob from Google Cloud Storage using their JSON API.

        Args:
            blob_name (str):
                The name of the blob to delete in the bucket (e.g. "profile/my_file.txt").

        Returns:
            None
        """
        headers = await self.get_authorised_headers()
        blob_name = self.parse_object_name(blob_name)
        await useful.do_request(
            method="DELETE",
            url=f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{blob_name}",
            request_kwargs={
                "headers": headers,
            },
            check_status=False,
        )

__all__ = [
    "CloudStorage"
]