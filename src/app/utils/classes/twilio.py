# import local Python libraries
from utils import constants as C
from utils.functions.useful import do_request
from gcp.secret_manager import SecretManager

# import Python's standard libraries
import base64
import asyncio
from typing import Self

class TwilioAPI:
    """TwilioAPI object to send SMS."""
    def __init__(self, account_sid: str, auth_token: str):
        self.__account_sid = account_sid
        self.__auth_token = auth_token

    def get_basic_http_auth(self) -> str:
        """Get the basic HTTP auth token for Twilio API requests.

        Returns:
            str: The basic HTTP auth token.
        """
        formatted_str = f"{self.__account_sid}:{self.__auth_token}"
        return base64.b64encode(formatted_str.encode("utf-8")).decode("utf-8")

    async def send_sms(self, to: str, body: str) -> None:
        """Send an SMS message to a phone number.

        Args:
            to (str):
                The phone number to send the message to.
            body (str):
                The body of the message.

        Returns:
            None
        """
        await do_request(
            url=f"https://api.twilio.com/2010-04-01/Accounts/{self.__account_sid}/Messages.json",
            method="POST",
            request_kwargs={
                "headers": {
                    "Authorization": f"Basic {self.get_basic_http_auth()}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                "data": {
                    "To": to,
                    "From": "+18307305828",
                    "Body": body,
                },
            },
        )

    @classmethod
    async def init(cls, secret_manager: SecretManager | None = None, async_mode: bool | None = True) -> Self:
        """Initialize the TwilioAPI object.

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
            TwilioAPI: The TwilioAPI object.
        """
        if secret_manager is None:
            if async_mode:
                secret_manager = await SecretManager.init()
            else:
                secret_manager = SecretManager()

        if async_mode:
            acc_sid, auth_token = await asyncio.gather(*[
                secret_manager.get_secret_payload_async(C.TWILIO_SID),
                secret_manager.get_secret_payload_async(C.TWILIO_AUTH_TOKEN),
            ])
        else:
            acc_sid = secret_manager.get_secret_payload(C.TWILIO_SID)
            auth_token = secret_manager.get_secret_payload(C.TWILIO_AUTH_TOKEN)
        return cls(
            account_sid=acc_sid,
            auth_token=auth_token,
        )

__all__ = [
    "TwilioAPI",
]