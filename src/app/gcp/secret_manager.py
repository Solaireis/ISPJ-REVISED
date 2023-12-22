# import third-party libraries
import six
import orjson
import aiofiles
from google_crc32c import Checksum as g_crc32c
import google.api_core.exceptions as GoogleErrors
from google.cloud import secretmanager

# import local Python libraries
from utils import constants as C
from .gcp_rest import GcpRestApi
from utils.functions.useful import do_request

# import Python's standard libraries
import base64
import pathlib
from typing import Self

def crc32c(data: bytes | str) -> int:
    """Calculates the CRC32C checksum of the provided data

    Args:
        data (bytes | str):
            The bytes of the data which the checksum should be calculated.
            If the data is in string format, it will be encoded to bytes.

    Returns:
        int:
            The CRC32C checksum of the data.
    """
    return int(g_crc32c(initial_value=six.ensure_binary(data, encoding="utf-8")).hexdigest(), 16)

SECRET_MANAGER = secretmanager.SecretManagerServiceClient
class SecretManager(GcpRestApi):
    """Creates a Secret Manager client that can be used to retrieve secrets from GCP."""
    def __init__(self, secret_manager_json: dict | str | None = None, use_base_client: bool | None = True) -> None:
        """Initialize the SecretManager object.

        Args:
            secret_manager_json (dict | str | None):
                The JSON of the secret manager service account.
                If None, the JSON will be read from the file.
            use_base_client (bool | None):
                If true, the GCP's secret manager client will be created.
                Usually, this is not needed, unless you want to upload or access secrets to GCP synchronously.
        """
        if secret_manager_json is None:
            secret_manager_json = self.get_secret_sm_path().read_text()
        if isinstance(secret_manager_json, str):
            secret_manager_json = orjson.loads(secret_manager_json)

        super().__init__(
            credentials=secret_manager_json,
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        if use_base_client:
            self.__sm_client = secretmanager.SecretManagerServiceClient.from_service_account_info(
                info=secret_manager_json,
            )
        else:
            self.__sm_client = None

    @staticmethod
    def get_secret_sm_path() -> pathlib.Path:
        """Get the path to the secret manager service account JSON file.

        Returns:
            pathlib.Path: 
                The path to the secret manager service account JSON file.
        """
        if C.DEBUG_MODE:
            return pathlib.Path(__file__).parent.resolve().joinpath("gcp-sm.json")
        return pathlib.Path("/gcp-sm/secret").resolve()

    @classmethod
    async def init(cls, use_base_client: bool | None = False) -> Self:
        """Initialize the SecretManager object.

        Args:
            use_base_client (bool):
                If true, the GCP's secret manager client will be created.
                Usually, this is not needed, unless you want to upload or access secrets to GCP synchronously.

        Returns:
            SecretManager: 
                The SecretManager object.
        """
        secret_manager_path = cls.get_secret_sm_path()
        async with aiofiles.open(secret_manager_path, "r") as f:
            secret_manager_json = await f.read()

        return cls(
            secret_manager_json=secret_manager_json,
            use_base_client=use_base_client,
        )

    def get_secret_payload(self, 
        secret_id: str, 
        version_id: str | None = "latest", 
        decode_secret: bool | None = True,
    ) -> str | bytes:
        """Get the secret payload from Google Cloud Secret Manager API.

        Args:
            secret_id (str): 
                The ID of the secret.
            version_id (str): 
                The version ID of the secret.
            decode_secret (bool): 
                If true, decode the returned secret bytes payload to string type. (Default: True)

        Returns:
            str | bytes: 
                the secret payload
        """
        if not C.DEBUG_MODE:
            secret_path = pathlib.Path(f"/{secret_id}/secret").resolve()
            if decode_secret:
                return secret_path.read_text()
            return secret_path.read_bytes()

        # construct the resource name of the secret version
        secret_name = SECRET_MANAGER.secret_version_path(
            project=C.GCP_PROJECT_ID, 
            secret=secret_id, 
            secret_version=version_id,
        )

        # get the secret version
        try:
            response = self.__sm_client.access_secret_version(request={"name": secret_name})
        except (GoogleErrors.NotFound) as e:
            raise Exception(
                f"Secret {secret_id} (version {version_id}) not found!\n{e}",
            )

        # return the secret payload
        secret = response.payload.data
        return secret.decode("utf-8") if decode_secret else secret

    async def get_secret_payload_async(self, 
        secret_id: str, 
        version_id: str | None = "latest", 
        decode_secret: bool | None = True
    ) -> str | bytes:
        """Get the secret payload from Google Cloud Secret Manager API asynchronously.

        Args:
            secret_id (str): 
                The ID of the secret.
            version_id (str): 
                The version ID of the secret.
            decode_secret (bool): 
                If true, decode the returned secret bytes payload to string type. (Default: True)

        Returns:
            str | bytes: 
                the secret payload
        """
        if not C.DEBUG_MODE:
            secret_path = pathlib.Path(f"/{secret_id}/secret").resolve()
            mode = "r" if decode_secret else "rb"
            async with aiofiles.open(secret_path, mode=mode) as f:
                return await f.read()

        # construct the resource name of the secret version
        secret_name = SECRET_MANAGER.secret_version_path(
            project=C.GCP_PROJECT_ID, 
            secret=secret_id, 
            secret_version=version_id,
        )

        # get the secret version
        headers = await self.get_authorised_headers()
        response, secret_json = await do_request(
            url=f"https://secretmanager.googleapis.com/v1/{secret_name}:access",
            method="GET",
            get_json=True,
            get_response=True,
            check_status=False,
            request_kwargs={
                "headers": headers,
            }
        )
        if response.status_code == 404:
            raise Exception(
                f"Secret {secret_id} (version {version_id}) not found!",
            )
        elif response.status_code != 200:
            raise Exception(
                f"Response status {response.status_code}! Error while getting secret {secret_id} (version {version_id})...",
            )

        # return the secret payload
        secret = secret_json["payload"]["data"]
        secret = base64.b64decode(secret)
        return secret.decode("utf-8") if decode_secret else secret

    def upload_secret_payload(self, 
        secret_id: str, 
        secret_payload: str | bytes, 
        destroy_old_ver: bool | None = False, 
        optimise: bool | None = False
    ) -> None:
        """Upload a new secret payload to Google Cloud Secret Manager API.

        Args:
            secret_id (str): 
                The ID of the secret.
            secret_payload (str|bytes): 
                The secret payload to be uploaded.
            destroy_old_ver (bool):
                If true, destroy all the old versions of the secret. (Default: False)
            optimise (bool):
                If true, optimise the deletion of all old versions of the secret by 
                breaking out of the loop once an old version has been found to be deleted. (Default: False)
                Set to true if the secret's old versions has been consistently deleted.

        Returns:
            None
        """
        if self.__sm_client is None:
            raise Exception(
                "SecretManager object needs to be initialised with use_base_client=True!",
            )

        # construct the resource name of the secret version
        secret_path = SECRET_MANAGER.secret_path(
            project=C.GCP_PROJECT_ID,
            secret=secret_id,
        )

        # upload the secret payload to GCP
        if isinstance(secret_payload, str):
            secret_payload = secret_payload.encode("utf-8")
        response = self.__sm_client.add_secret_version(
            parent=secret_path,
            payload={
                "data": secret_payload,
                "data_crc32c": crc32c(secret_payload),
            }
        )

        if not destroy_old_ver:
            return response

        # get the latest secret version
        latest_ver = int(response.name.split("/")[-1])
        for version in range(latest_ver - 1, 0, -1):
            secret_ver_path = SECRET_MANAGER.secret_version_path(
                project=C.GCP_PROJECT_ID,
                secret=secret_id,
                secret_version=version,
            )
            try:
                self.__sm_client.destroy_secret_version(request={"name": secret_ver_path})
            except (GoogleErrors.FailedPrecondition):
                # key is already destroyed
                if optimise:
                    break # assuming that all the previous has been destroyed

        return response

__all__ = [
    "SecretManager",
    "crc32c",
]