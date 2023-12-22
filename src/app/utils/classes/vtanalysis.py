# import third-party libraries
import vt
from fastapi import (
    UploadFile,
    Request,
)
from pymongo.collection import Collection

# import local Python libraries
from utils.functions import useful
from utils import constants as C

# import Python's standard libraries
import time
import types
from typing import Self, Type

# Will do after successful completion of VT API integration
class VtAnalysis:
    def __init__(self, api_key: str) -> None:
        self.__vt_client = vt.Client(
            apikey=api_key,
        )

    async def check_file(self, file: UploadFile, file_hash: str) -> bool:
        try:
            file_check = await self.__vt_client.get_object_async(f"/files/{file_hash}")
            # Not needed to check for file age, as we are checking for file hash
            # diff = (datetime.strptime(date.today().strftime("%m-%d-%Y"), "%m-%d-%Y") - datetime.strptime(file_check.last_analysis_date.strftime("%m-%d-%Y"), "%m-%d-%Y")).days
            # if diff > 30:
            #     print("File found on VirusTotal, but is older than 30 days.")
            #     raise vt.error.APIError
            analysis_stats = file_check.last_analysis_stats
        except vt.error.APIError:
            if C.DEBUG_MODE:
                print("No file found on VirusTotal.\n Now scanning File to Virus Total")
            # file_scan = await self.__vt_client.scan_file(file.file, wait_for_completion=True)
            # analysis_stats = file_scan.stats

            file_scan = await self.__vt_client.scan_file_async(file.file)
            while True:
                analysis = await self.__vt_client.get_object_async(f"/analyses/{file_scan.id}")
                if analysis.status == 'completed':
                    break
            analysis_stats = analysis.stats

        if analysis_stats["suspicious"] > 0 or analysis_stats["malicious"] > 0:
            return False
        return True

    async def check_blob(self, request: Request, bucket: str, blob_name: str) -> bool:
        """Checks if the blob is malicious or not by creating a signed URL and letting VirusTotal to check it.

        Args:
            request (Request):
                The FastAPI request object.
            bucket (str):
                The name of the bucket.
            blob_name (str):
                The name of the blob.

        Returns:
            bool:
                Whether the blob is malicious or not. True if it is malicious, False if it is not.
        """
        from gcp import CloudFunction # to avoid circular imports
        cloud_function: CloudFunction = request.app.state.obj_map[CloudFunction]
        signed_url = await cloud_function.invoke_instance(
            url=C.CREATE_SIGNED_URL_FUNCTION,
            json={
                "bucket_name": bucket,
                "object_name": blob_name,
                "expiry": 3600, # 1 hr
            },
        )
        return await self.check_link(
            url=signed_url["signed_url"],
            col=None,
            cache_result=False,
        )

    async def check_link(self, url: str, col: Collection | None, cache_result: bool | None = True) -> bool:
        """Checks if the link is malicious or not.

        Args:
            url (str): 
                The URL to check.
            col (Collection): 
                The MongoDB collection to insert the URL into for caching.
            cache_result (bool | None, optional):
                Whether to cache the result or not. Defaults to True.

        Returns:
            bool:
                Whether the URL is malicious or not. True if it is malicious, False if it is not.
        """
        if cache_result and col is None:
            raise ValueError("col cannot be None if cache_result is True.")

        try:
            url_id = vt.url_id(url)
            url_check = await self.__vt_client.get_object_async(f"/urls/{url_id}")
            diff_in_days = (time.time() - useful.datetime_to_unix_time(url_check.last_analysis_date)) // 86400

            if diff_in_days > 30:
                if C.DEBUG_MODE:
                    print("URL found on VirusTotal, but is older than 30 days.")
                raise vt.error.APIError

            analysis_stats = url_check.last_analysis_stats
        except vt.error.APIError:
            if C.DEBUG_MODE:
                print("Not Found")

            url_scan = await self.__vt_client.scan_url_async(url, wait_for_completion=True)
            analysis_stats = url_scan.stats

        # False Positives 
        if analysis_stats["suspicious"] > 1 or analysis_stats["malicious"] > 1:
            if cache_result:
                await col.update_one(
                    filter={"identifier": url},
                    update={
                        "$set": {
                            "identifier": url,
                            "malicious": True,
                        },
                    },
                    upsert=True,
                )
            return True

        if cache_result:
            await col.update_one(
                filter={"identifier": url},
                update={
                    "$set": {
                        "identifier": url,
                        "malicious": False,
                    },
                },
                upsert=True,
            )
        return False

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: Type[BaseException] | None, exc: BaseException | None, traceback: types.TracebackType | None) -> None:
        await self.close()

    async def close(self) -> None:
        await self.__vt_client.close_async()

__all__ = [
    "VtAnalysis",
]