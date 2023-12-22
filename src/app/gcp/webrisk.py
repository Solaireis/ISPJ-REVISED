# import local Python libraries
from .secret_manager import SecretManager
from .gcp_rest import GcpRestApi
from utils.functions.useful import do_request

# import Python"s standard libraries
from typing import Self

class WebRisk(GcpRestApi):
    """Creates a Web Risk client that can be used to retrieve threats from GCP.

    docs: https://cloud.google.com/web-risk/docs/lookup-api
    """
    # Searches if a URI Exists in the threat list
    async def search_uri(self, url:str):
        # Initialize request argument(s)
        headers = await self.get_authorised_headers()
        response = await do_request(
            url=f"https://webrisk.googleapis.com/v1/uris:search?uri={url}&threatTypes=MALWARE&threatTypes=UNWANTED_SOFTWARE&threatTypes=SOCIAL_ENGINEERING",
            method="GET",
            request_kwargs={
                "headers": headers,
            },
            get_json=True,
        )

        # According to the documentation, if the URL is not found, 
        # the response will be an empty JSON object of {}.
        # This means that the URL provided isn't on any threat lists.
        return bool(response)

    @classmethod
    async def init(cls, secret_manager: SecretManager | None = None, async_mode: bool | None = True):
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
            WebRisk:
                The initialised class.
        """
        if secret_manager is None:
            if async_mode:
                secret_manager = await SecretManager.init()
            else:
                secret_manager = SecretManager()

        if async_mode:
            credentials = await secret_manager.get_secret_payload_async("web-risk")
        else:
            credentials = secret_manager.get_secret_payload("web-risk")
        return cls(
            credentials=credentials,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

__all__ = [
    "WebRisk",
]