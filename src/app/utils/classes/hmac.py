# import third-party libraries
import orjson
from itsdangerous import (
    URLSafeTimedSerializer, 
    BadSignature, 
    SignatureExpired,
)

# import local Python libraries
from utils import constants as C
from gcp.secret_manager import SecretManager

# import Python's standard libraries
import hashlib
from typing import Any, Callable

class URLSafeSerialiserHMAC:
    """URL-safe serialiser (HMAC) using the itsdangerous module which 
    generally produces a shorter string length than if it were to use JWT.

    Note that the secret key must be passed in upon construction of this class and is not 
    dynamically loaded from Google Cloud Platform Secret Manager API.
    """
    def __init__(self, 
        secret_key: str | bytes,
        salt: str | bytes | None = "mirai".encode("utf-8"),
        digest_method: str = "sha512",
        max_age: int | None = 3600 * 24 * 7 # 7 days
    ) -> None:
        """Constructor for the URLSafeSerialiserHMAC class.

        Attributes:
            secret_key (str | bytes):
                Secret key that will be used to sign the data.
            salt (str | bytes, optional):
                Salt to be used to sign the data. Defaults to "cultured-downloader" that is utf-8 encoded.
            digest_method (str, optional):
                Digest method to be used to sign the data. Defaults to "sha512".
            max_age (int, optional):
                Maximum age of the signed data in seconds. Defaults to 7 days.
                Warning: If set to None, the signed data will never expire.
        """
        digest_method = digest_method.lower()
        if digest_method != "sha1":
            digest_method = self.__get_digest_method_function(digest_method)
            signer_kwargs = {
                "digest_method": staticmethod(digest_method)
            }
        else:
            # Since the itsdangerous module uses 
            # sha1 as the digest method by default,
            # we do not need to pass in the digest_method 
            # argument in the signer_kwargs dictionary.
            signer_kwargs = None

        self.signer = URLSafeTimedSerializer(
            secret_key=secret_key, 
            salt=salt,
            serializer=orjson,
            signer_kwargs=signer_kwargs
        )
        self.max_age = max_age

    def __get_digest_method_function(self, digest_method: str) -> Callable:
        """Get the digest method function from the hashlib module.

        Args:
            digest_method (str):
                digest method name.

        Returns:
            Callable: 
                digest method's hashlib function.
        """
        if digest_method == "sha1":
            return hashlib.sha1
        elif digest_method == "sha256":
            return hashlib.sha256
        elif digest_method == "sha384":
            return hashlib.sha384
        elif digest_method == "sha512":
            return hashlib.sha512
        else:
            raise ValueError(f"Only sha1, sh256, sha384, and sha512 are supported but not {digest_method}!")

    def sign(self, data: dict) -> str:
        """Sign the data with the secret key."""
        return self.signer.dumps(data).decode("utf-8")

    def get(self, token: str, default: Any | None = None) -> dict | Any | None:
        """Get the data payload from the token.

        Args:
            token (str):
                Signed token.
            default (Any, optional):
                Default value to return if the token is invalid. Defaults to None.

        Returns:
            dict | Any | None:
                The data payload if the token is valid. Otherwise, return the default value.
        """
        if token is None:
            return default

        try:
            return self.signer.loads(token, max_age=self.max_age)
        except (BadSignature, SignatureExpired):
            return default

__secret_manager = SecretManager()
__secret_key = bytes.fromhex(
    __secret_manager.get_secret_payload("session-secret-key"),
)
__salt = bytes.fromhex(
    __secret_manager.get_secret_payload("session-salt"),
)
def get_hmac_signer(max_age: int) -> URLSafeSerialiserHMAC:
    """Get the URLSafeSerialiserHMAC object.

    Args:
        max_age (int):
            Maximum age of the signed data in seconds.

    Returns:
        URLSafeSerialiserHMAC: 
            URLSafeSerialiserHMAC object.
    """
    return URLSafeSerialiserHMAC(
        secret_key=__secret_key,
        salt=__salt,
        digest_method="sha256",
        max_age=max_age,
    )

__all__ = [
    "get_hmac_signer",
]