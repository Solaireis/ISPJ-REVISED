# import third-party libraries
from fastapi.exceptions import HTTPException
from google.cloud import kms
from google.cloud.kms_v1 import KeyManagementServiceClient

# import local Python libraries
from utils import constants as C
from .gcp_rest import GcpRestApi
from utils.functions.useful import do_request
from .secret_manager import (
    SecretManager, 
    crc32c,
)

# import Python's standard libraries
import base64
import asyncio
import secrets
import warnings
from typing import Self

class GcpKms(GcpRestApi):
    """Creates an authenticated Cloud KMS client that can be used for secure cryptographic operations.

    Docs: https://cloud.google.com/kms/docs/reference/rest
    """
    def __init__(self, credentials: str | dict | None = None) -> None:
        if credentials is None:
            credentials = SecretManager().get_secret_payload(secret_id="kms")

        super().__init__(
            credentials=credentials,
            scopes=["https://www.googleapis.com/auth/cloudkms"]
        )
        self._key_ring_id = "dev" if C.DEBUG_MODE else "mirai"

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
            GcpKms:
                The initialised class.
        """
        if secret_manager is None:
            if async_mode:
                secret_manager = await SecretManager.init()
            else:
                secret_manager = SecretManager()

        if async_mode:
            credentials = await secret_manager.get_secret_payload_async("kms")
        else:
            credentials = secret_manager.get_secret_payload("kms")
        return cls(
            credentials=credentials,
        )

    async def __generate_random_bytes(self, location_name: str, n_bytes: int) -> dict:
        """Generate a random byte string of length n_bytes that is cryptographically secure using GCP KMS RNG Cloud HSM.

        Args:
            location_name (str):
                The location name.
            n_bytes (int):
                The number of bytes to generate.

        Returns:
            dict:
                The random bytes response from GCP KMS API.
        """
        headers = await self.get_authorised_headers()
        response = await do_request(
            url=f"https://cloudkms.googleapis.com/v1/{location_name}:generateRandomBytes",
            method="POST",
            get_json=True,
            request_kwargs={
                "headers": headers,
                "json": {
                    "lengthBytes": n_bytes,
                    "protectionLevel": kms.ProtectionLevel.HSM,
                },
            }
        )
        return response

    async def get_random_bytes(self, 
        n_bytes: int, 
        generate_from_hsm: bool | None = False, 
        return_hex: bool | None = False) -> bytes | str:
        """Generate a random byte/hex string of length n_bytes that is cryptographically secure.

        Args:
            n_bytes (int): 
                The number of bytes to generate.
            generate_from_hsm (bool, optional):
                If True, the random bytes will be generated from GCP KMS's Cloud HSM. (Default: False)
            return_hex (bool, optional):
                If True, the random bytes will be returned as a hex string. (Default: False)

        Returns:
            bytes | str:
                The random bytes or random hex string.
        """
        if n_bytes < 1:
            raise ValueError("n_bytes must be greater than 0!")

        # Since GCP KMS RNG Cloud HSM's minimum length is 8 bytes, 
        # fallback to secrets library if n_bytes is less than 8
        if generate_from_hsm and n_bytes < 8:
            warnings.warn(
                message="GCP KMS does not accept n_bytes less than 8, falling back to secrets library...",
                category=RuntimeWarning
            )
            generate_from_hsm = False

        if not generate_from_hsm:
            if return_hex:
                return secrets.token_hex(n_bytes)
            else:
                return secrets.token_bytes(n_bytes)

        # Construct the location name
        location_name = KeyManagementServiceClient.common_location_path(
            project=C.GCP_PROJECT_ID, 
            location=C.GCP_PROJECT_LOCATION
        )

        # Check if the number of bytes exceeds GCP KMS RNG Cloud HSM limit
        max_bytes = 1024
        if n_bytes > max_bytes:
            # if exceeded, make multiple API calls to generate the random bytes
            num_of_max_bytes = n_bytes // max_bytes
            tasks = [self.__generate_random_bytes(location_name, n_bytes=max_bytes) for _ in range(num_of_max_bytes)]

            remainder = n_bytes % max_bytes
            if remainder > 0:
                tasks.append(self.__generate_random_bytes(location_name, n_bytes=remainder))

            tasks_completed = await asyncio.gather(*tasks)
            bytes_arr = []
            for task in tasks_completed:
                data = base64.b64decode(task["data"])
                if task["dataCrc32c"] != str(crc32c(data)):
                    raise HTTPException(
                        status_code=500, 
                        detail="An error has occurred while generating random bytes!"
                    )
                else:
                    bytes_arr.append(data)

            random_bytes = b"".join(bytes_arr)
        else:
            # Call the Google Cloud Platform API to generate a random byte string.
            random_bytes_response = await self.__generate_random_bytes(location_name, n_bytes=n_bytes)
            random_bytes = base64.b64decode(random_bytes_response["data"])
            if random_bytes_response["dataCrc32c"] != str(crc32c(random_bytes)):
                raise HTTPException(
                    status_code=500, 
                    detail="An error has occurred while generating random bytes!"
                )

        return random_bytes if not return_hex else random_bytes.hex()

class GcpAesGcm(GcpKms):
    """Creates an authenticated GCP KMS client that uses AES-256-GCM for cryptographic operations."""
    async def symmetric_encrypt(self, plaintext: str | bytes, key_id: str, key_ring_id: str | None = None) -> bytes:
        """Using AES-256-GCM to encrypt the provided plaintext via GCP KMS API.

        Args:
            plaintext (str|bytes): 
                the plaintext to encrypt
            key_id (str): 
                the key ID/name of the key
            key_ring_id (str): 
                the key ring ID (Defaults to key_ring_id attribute of the object)

        Returns:
            ciphertext (bytes): the ciphertext in bytes format
        """
        if key_ring_id is None:
            key_ring_id = self._key_ring_id

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        # Compute the plaintext's CRC32C checksum before sending it to Google Cloud KMS API
        plaintext_crc32c = crc32c(plaintext)

        # Construct the key version name
        key_version_name = KeyManagementServiceClient.crypto_key_path(
            project=C.GCP_PROJECT_ID, 
            location=C.GCP_PROJECT_LOCATION, 
            key_ring=key_ring_id, 
            crypto_key=key_id
        )

        # Construct and send the request to Google Cloud KMS API to encrypt the plaintext
        headers = await self.get_authorised_headers()
        response = await do_request(
            url=f"https://cloudkms.googleapis.com/v1/{key_version_name}:encrypt",
            method="POST",
            get_json=True,
            request_kwargs={
                "headers": headers,
                "json": {
                    "plaintext": base64.b64encode(plaintext).decode("utf-8"), 
                    "plaintextCrc32c": plaintext_crc32c
                }
            }
        )

        ciphertext = base64.b64decode(response["ciphertext"])
        # Perform some integrity checks on the encrypted data that Google Cloud KMS API returned
        # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
        if not response["verifiedPlaintextCrc32c"]:
            # request sent to Google Cloud KMS API was corrupted in-transit
            raise HTTPException(
                detail="Plaintext CRC32C checksum did not match during the encryption process.",
                status_code=400,
            )
        if response["ciphertextCrc32c"] != str(crc32c(ciphertext)):
            # response received from Google Cloud KMS API was corrupted in-transit
            raise HTTPException(
                detail="Ciphertext CRC32C checksum did not match during the encryption process.",
                status_code=400,
            )

        return ciphertext

    async def symmetric_decrypt(self, 
        ciphertext: bytes, 
        key_id: str, 
        key_ring_id: str | None = None, 
        decode: bool | None = True) -> str | bytes:
        """Using AES-256-GCM to decrypt the provided ciphertext via GCP KMS API.

        Args:
            ciphertext (bytes): 
                the ciphertext to decrypt
            key_id (str): 
                the key ID/name of the key
            key_ring_id (str): 
                the key ring ID (Defaults to key_ring_id attribute of the object)
            decode (bool): 
                whether to decode the decrypted plaintext to string (Defaults to True)

        Returns:
            plaintext (str): the plaintext

        Raises:
            HTTPException:
                if the ciphertext couldn't be decrypted or had failed integrity checks
        """
        if isinstance(ciphertext, bytearray):
            ciphertext = bytes(ciphertext)

        if not isinstance(ciphertext, bytes):
            raise TypeError(f"The ciphertext, {ciphertext} is in \"{type(ciphertext)}\" format. Please pass in a bytes type variable.")

        if key_ring_id is None:
            key_ring_id = self._key_ring_id

        # Construct the key version name
        key_version_name = KeyManagementServiceClient.crypto_key_path(
            project=C.GCP_PROJECT_ID, 
            location=C.GCP_PROJECT_LOCATION, 
            key_ring=key_ring_id, 
            crypto_key=key_id
        )

        # compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
        ciphertext_crc32c = crc32c(ciphertext)

        # construct and send the request to Google Cloud KMS API to decrypt the ciphertext
        headers = await self.get_authorised_headers()
        response, json_res = await do_request(
            url=f"https://cloudkms.googleapis.com/v1/{key_version_name}:decrypt",
            method="POST",
            get_json=True,
            check_status=False,
            get_response=True,
            request_kwargs={
                "headers": headers,
                "json": {
                    "ciphertext": base64.b64encode(ciphertext).decode("utf-8"), 
                    "ciphertextCrc32c": ciphertext_crc32c,
                }
            }
        )
        if response.status_code != 200:
            # Usually happens when the ciphertext is not valid
            # e.g. Ciphertext was encrypted using 
            # a different key that's no longer in use
            raise HTTPException(
                status_code=response.status_code, 
                detail="An error has occurred while decrypting the ciphertext!"
            )

        # Perform a integrity check on the decrypted data that Google Cloud KMS API returned
        # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
        plaintext = base64.b64decode(json_res["plaintext"])
        if json_res["plaintextCrc32c"] != str(crc32c(plaintext)):
            # response received from Google Cloud KMS API was corrupted in-transit
            raise HTTPException(
                detail="Plaintext CRC32C checksum did not match during the encryption process.",
                status_code=400,
            )

        return plaintext.decode("utf-8") if decode else plaintext

__all__ = [
    "GcpKms",
    "GcpAesGcm",
]