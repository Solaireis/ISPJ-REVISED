# import third-party libraries
import orjson
from authlib.jose import JsonWebToken

# import local Python libraries
from utils.functions.useful import do_request

# import Python's standard libraries
import time
import asyncio

class GcpRestApi:
    def __init__(self, credentials: dict | str, scopes: list[str]) -> None:
        """Initialise the GCP API object with the service account credentials.

        Args:
            credentials (dict | str):
                A loaded JSON dict object containing the service account credentials.
                If a string is passed, it is will be loaded as a JSON dict object automatically.
            scopes (list[str]):
                A list of scopes to request access to.
        """
        if not isinstance(credentials, dict):
            credentials = orjson.loads(credentials)

        self._credentials = credentials
        self.__auth_url = "https://oauth2.googleapis.com/token"
        self.__algo = "RS256"
        self.__signer = JsonWebToken(
            algorithms=[self.__algo],
        )

        self.__at_lock = asyncio.Lock()
        self.__id_lock = asyncio.Lock()
        self.__scopes = scopes
        self.__access_tokens = {}
        self.__id_tokens = {}

    def create_signed_jwt(self) -> bytes:
        """Creates a signed JWT for authenticating with the Google Cloud API.

        References:
            - https://developers.google.com/identity/protocols/oauth2/service-account#httprest
            - https://www.jhanley.com/blog/google-cloud-creating-oauth-access-tokens-for-rest-api-calls/
        """
        scopes = " ".join(self.__scopes)
        header = {
            "kid": self._credentials["private_key_id"],
            "alg": self.__algo,
            "typ": "JWT",
        }

        issued = int(time.time())
        expiry = issued + 3600
        payload = {
            "iss": self._credentials["client_email"], # Issuer claim
            "aud": self.__auth_url,                    # Audience claim
            "iat": issued,                             # Issued At claim
            "exp": expiry,                             # Expire time
            "scope": scopes,                           # Scope Permissions
        }

        signed_jwt = self.__signer.encode(
            header=header, 
            payload=payload, 
            key=self._credentials["private_key"],
        )
        return signed_jwt

    async def refresh_token(self, use_refresh_token: bool | None = False) -> str:
        """Refresh the access token and return it."""
        if use_refresh_token:
            access_token_key = "refresh_token"
        else:
            access_token_key = "jwt"

        async with self.__at_lock:
            access_token_data = self.__access_tokens.get(access_token_key)
            if access_token_data is None or access_token_data["expiry"] < int(time.time()):
                refresh_token_data = {}
                if use_refresh_token:
                    refresh_token_data = {
                        "grant_type": "refresh_token",
                        "client_id": self._credentials["client_id"],
                        "client_secret": self._credentials["client_secret"],
                        "refresh_token": self._credentials["refresh_token"],
                    }
                else:
                    refresh_token_data = {
                        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                        "assertion": self.create_signed_jwt().decode("utf-8"),
                    }

                response = await do_request(
                    url=self.__auth_url,
                    method="POST",
                    get_json=True,
                    request_kwargs={
                        "json": refresh_token_data,
                    },
                )
                self.__access_tokens[access_token_key] = {
                    "token": response["access_token"],
                    "expiry": int(time.time()) + response["expires_in"] - 60, # minus 60 seconds for extra leeway
                }

        return self.__access_tokens[access_token_key]["token"]

    async def get_authorised_headers(self, use_id_token: bool | None = False, **kwargs) -> dict[str, str]:
        """Get the headers required for the request to the Google Cloud API.

        Args:
            use_id_token (bool | None):
                Whether to use an ID token instead of an access token. (Default: False)
                Will only work if the service account has the "Service Account OpenID Connect Identity Token Creator" role assigned to it.

        Returns:
            dict[str, str]:
                The headers required for the request to the Google Cloud API.
        """
        if use_id_token:
            token = await self.get_id_token(**kwargs)
        else:
            token = await self.refresh_token(**kwargs)

        return {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {token}",
        }

    async def get_id_token(self, audience: str) -> str:
        """Get a identity token for the service account.
        Requires the "Service Account OpenID Connect Identity Token Creator" role to be assigned to the service account.

        References:
            - https://googleapis.dev/python/google-auth/latest/reference/google.auth.transport._aiohttp_requests.html

        Args:
            audience (str):
                The audience for the ID token.
                Usually the URL of the API you are trying to access.

        Returns:
            str: 
                The ID token.
        """
        async with self.__id_lock:
            audience_id_token = self.__id_tokens.get(audience)
            if audience_id_token is None or audience_id_token["expiry"] < int(time.time()):
                sa_to_impersonate = self._credentials["client_email"]
                headers = await self.get_authorised_headers()
                response = await do_request(
                    url=f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa_to_impersonate}:generateIdToken",
                    method="POST",
                    get_json=True,
                    request_kwargs={
                        "headers": headers,
                        "json": {
                            "audience": audience,
                        },
                    },
                )
                self.__id_tokens[audience] = {
                    "token": response["token"],
                    "expiry": int(time.time()) + 3600 - 60, # minus 60 seconds for extra leeway
                }

        return self.__id_tokens[audience]["token"]