# import local Python libraries
from .google_ai import GoogleAI
from .secret_manager import SecretManager
from utils.functions.useful import do_request

# import Python's standard libraries
from typing import Self

class GoogleNLP(GoogleAI):
    """Google Natural Language Processing object to access the NLP API.

    Docs: https://cloud.google.com/natural-language/docs/reference/rest
    """
    base_url = "https://language.googleapis.com"
    def __init__(self, credentials: dict | str | None = None) -> None:
        super().__init__(
            credentials=credentials,
            scopes=["https://www.googleapis.com/auth/cloud-language"]
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
            GoogleNLP:
                The initialised class.
        """
        credentials = await cls.get_credentials_async(
            secret_manager=secret_manager,
            async_mode=async_mode,
        )
        return cls(
            credentials=credentials,
        )

    async def analyse_entities(self, body: str) -> dict:
        """Analyse entities in a document.

        Args:
            body (str): 
                The body of the document.

        Returns:
            dict: The response from the NLP API.
        """
        if body is None or len(body) <= 5:
            return {}

        headers = await self.get_authorised_headers()
        return await do_request(
            method="POST",
            url=f"{self.base_url}/v1/documents:analyzeEntities",
            request_kwargs={
                "json": {
                    "document": {
                        "content": body,
                        "type": "PLAIN_TEXT",
                        "language": "en",
                    },
                    "encodingType": "UTF8",
                },
                "headers": headers,
                "timeout": 15,
            },
            get_json=True,
        )

__all__ = [
    "GoogleNLP",
]