# import third-party libraries
from fastapi.exceptions import HTTPException

# import local Python libraries
from .gcp_rest import GcpRestApi
from utils import constants as C
from utils.functions.useful import do_request
from .secret_manager import SecretManager

# import Python's standard libraries
import base64
import hashlib
from typing import Self

# Scrypt hash parameters and constants
SCRYPT_HASH_CPU_MEM_COST = 1 << 12
SCRYPT_HASH_BLOCK_SIZE = 8
SCRYPT_HASH_PARALLELIZATION = 1
SCRYPT_MAX_MEMORY = 1024 * 1024 * 32 # 32 MiB of memory
SCRYPT_HASH_KEY_LENGTH = 32
SCRYPT_HASH_SALT = bytes([
    0x30, 0x76, 0x2a, 0xd2, 0x3f, 0x7b, 0xa1, 0x9b,
    0xf8, 0xe3, 0x42, 0xfc, 0xa1, 0xa7, 0x8d, 0x06,
    0xe6, 0x6b, 0xe4, 0xdb, 0xb8, 0x4f, 0x81, 0x53,
    0xc5, 0x03, 0xc8, 0xdb, 0xbd, 0xde, 0xa5, 0x20,
])

class RecaptchaEnterprise(GcpRestApi):
    """Creates an authenticated GCP reCAPTCHA Enterprise client.

    Docs: https://cloud.google.com/recaptcha-enterprise/docs/reference/rest
    """
    @staticmethod
    def canonicalize_username(username: str) -> str:
        """Canonicalize the username.

        E.g. "username@example.com" => "username"

        Args:
            username (str): 
                The username to canonicalize.

        Returns:
            str: 
                The canonicalized username.
        """
        if "@" in username:
            username = username.rsplit(sep="@", maxsplit=1)[0]
        return username.strip().lower().replace(".", "")

    @staticmethod
    def process_credentials(self, username: str, password: str) -> tuple[str, str]:
        """Process the user's credentials to be sent to the reCAPTCHA Enterprise API for password leak verification.

        Args:
            username (str):
                The username to check. (Email addresses will be canonicalized)
            password (str):
                The password to check.

        Returns:
            tuple[str, str]:
                A tuple containing the canonicalized username and the Base64 encoded hash.
        """
        canonicalized_username = RecaptchaEnterprise.canonicalize_username(username)

        # Compute the salt and convert the credentials to bytes by encoding them
        salt = canonicalized_username.encode("utf-8") + SCRYPT_HASH_SALT
        credentials = (canonicalized_username + password).encode("utf-8")

        # Compute the hash using Scrypt
        _hash = hashlib.scrypt(
            password=credentials,
            salt=salt,
            n=SCRYPT_HASH_CPU_MEM_COST,
            r=SCRYPT_HASH_BLOCK_SIZE,
            p=SCRYPT_HASH_PARALLELIZATION,
            maxmem=SCRYPT_MAX_MEMORY,
            dklen=SCRYPT_HASH_KEY_LENGTH,
        )
        return canonicalized_username, base64.b64encode(_hash).decode("utf-8")

    async def check_credentials(self, username: str, password: str) -> bool:
        """Check if the credentials have been breached.

        Args:
            username (str):
                The username to check. (Email addresses will be canonicalized)
            password (str):
                The password to check.

        Returns:
            bool:
                True if the credentials have been breached, False otherwise.
        """
        canonicalized_username, encoded_hash = RecaptchaEnterprise.process_credentials(self, username, password)

        headers = await self.get_authorised_headers()
        json_res = await do_request(
            url=f"https://recaptchaenterprise.googleapis.com/v1beta1/projects/{C.GCP_PROJECT_ID}/assessments",
            method="POST",
            get_json=True,
            request_kwargs={
                "headers": headers,
                "json": {
                    "password_leak_verification": {
                        "canonicalized_username": canonicalized_username,
                        "hashed_user_credentials": encoded_hash,
                    }
                },
            }
        )

        return json_res["passwordLeakVerification"]["credentialsLeaked"]

    async def verify_assessment(self, site_key: str, token: str, action: str | None = None, min_threshold: float = 0.75) -> bool:
        """Creates an assessment in Google Cloud reCAPTCHA API and 
        verifies it based on the given minimum threshold.

        Args:
            site_key (str):
                The site key to use for the assessment.
            token (str):
                The token to use for the assessment.
            action (str | None, optional):
                The action to validate against for the assessment. Defaults to None.
            min_threshold (float, optional):
                The minimum threshold to use for the assessment. Defaults to 0.75.

        Returns:
            bool:
                True if the assessment was successful, False otherwise.
        """
        if token is None or token.strip() == "":
            return False

        event = {
            "site_key": site_key,
            "token": token,
        }
        if action is not None:
            event["expected_action"] = action

        # send to Google reCAPTCHA API
        headers = await self.get_authorised_headers()
        response = await do_request(
            url=f"https://recaptchaenterprise.googleapis.com/v1/projects/{C.GCP_PROJECT_ID}/assessments",
            method="POST",
            get_json=True,
            request_kwargs={
                "headers": headers,
                "json": {
                    "event": event,
                },
            },
        )
        token_properties = response.get("tokenProperties", {})

        # check if the response is valid
        if not token_properties.get("valid", False):
            if C.DEBUG_MODE:
                print("invalid due to", token_properties.get("invalidReason", "unknown reason"))
            raise HTTPException(
                status_code=400,
                detail="The reCAPTCHA token is invalid.",
            )

        # check if the expected action was executed
        if action is not None and token_properties.get("action") != action:
            if C.DEBUG_MODE:
                print("invalid due to action mismatch")
            raise HTTPException(
                status_code=400,
                detail="The reCAPTCHA token is invalid.",
            )

        risk_analysis = response.get("riskAnalysis", {})
        return (min_threshold <= risk_analysis.get("score", 0.0))

    @classmethod
    async def init(cls, secret_manager: SecretManager | None = None, async_mode: bool | None = True) -> Self:
        """Initialize the reCAPTCHA Enterprise API client.

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
                The initialized reCAPTCHA Enterprise API client.
        """
        if secret_manager is None:
            if async_mode:
                secret_manager = await SecretManager.init()
            else:
                secret_manager = SecretManager()

        if async_mode:
            credentials = await secret_manager.get_secret_payload_async("recaptcha-enterprise")
        else:
            credentials = secret_manager.get_secret_payload("recaptcha-enterprise")
        return cls(
            credentials=credentials, 
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

__all__ = [
    "RecaptchaEnterprise",
]