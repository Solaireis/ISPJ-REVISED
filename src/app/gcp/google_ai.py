# import local Python libraries
from .secret_manager import SecretManager
from .gcp_rest import GcpRestApi

class GoogleAI(GcpRestApi):
    """Google AI object to access any AI related APIs."""
    def __init__(self, scopes: list[str], credentials: dict | str | None = None) -> None:
        if credentials is None:
            credentials = SecretManager().get_secret_payload("gcp-ai")

        super().__init__(
            credentials=credentials,
            scopes=scopes,
        )

    @staticmethod
    async def get_credentials_async(secret_name: str | None = "gcp-ai", secret_manager: SecretManager | None = None, async_mode: bool | None = True) -> str:
        """Get the credentials of a GCP service account from Secret Manager.

        Args:
            secret_name (str):
                The name of the secret.
                Defaults to "gcp-ai".
            secret_manager (SecretManager | None):
                The SecretManager class to use.
                Defaults to None and will create a new instance.
            async_mode (bool | None):
                Whether to use async mode or not.
                Defaults to None and will use async mode.
                Use it if the function is blocking any async I/O. 
                Otherwise, leave it as False to improve performance.

        Returns:
            str:
                The credentials of the service account.
        """
        if secret_manager is None:
            if async_mode:
                secret_manager = await SecretManager.init()
            else:
                secret_manager = SecretManager()

        if async_mode:
            return await secret_manager.get_secret_payload_async(secret_name)
        else:
            return secret_manager.get_secret_payload(secret_name)