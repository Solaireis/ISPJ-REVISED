# import local Python libraries
from .gcp_rest import GcpRestApi
import utils.constants as C
from utils.functions.useful import do_request
from .secret_manager import SecretManager

# import Python's standard libraries
from typing import Self

class CloudFunction(GcpRestApi):
    """Creates an authenticated GCP Cloud Function client.

    Docs: 
        - https://cloud.google.com/run/docs/reference/rest
        - https://cloud.google.com/functions/docs/reference/rest
    """
    async def invoke_instance(self, url: str, timeout: int | None = 30, **kwargs) -> dict | None:
        """Invoke a Cloud Run instance (Cloud Function Gen 2)

        Args:
            url (str):
                The url of the Cloud Run to invoke.
            timeout (int | None):
                The timeout in seconds. Defaults to 30s.
            **kwargs:
                The data to send to the Cloud Run using httpx.post.

        Returns:
            dict | None:
                The JSON response from the Cloud Run.
        """
        headers = await self.get_authorised_headers(use_id_token=True, audience=url)
        request_kwargs = {
            "headers": headers,
            "timeout": timeout,
        }
        request_kwargs.update(kwargs)

        response = await do_request(
            method="POST",
            url=url,
            get_json=True,
            request_kwargs=request_kwargs,
        )
        return response

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
            CloudFunction:
                The initialised class.
        """
        if secret_manager is None:
            if async_mode:
                secret_manager = await SecretManager.init()
            else:
                secret_manager = SecretManager()

        if async_mode:
            credentials = await secret_manager.get_secret_payload_async("cloud-function")
        else:
            credentials = secret_manager.get_secret_payload("cloud-function")
        return cls(
            credentials=credentials,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

class EmailCloudFunction(CloudFunction):
    async def send_email(
        self, 
        to: str, 
        subject: str, 
        body: str, 
        name: str | None = None, 
        mirai_email: str | None = C.NOREPLY_EMAIL_ADDRESS,
        format_email: bool | None = True,
    ) -> None:
        """Send an email using a Cloud Function.

        Args:
            to (str):
                The email address to send the email to.
            subject (str):
                The subject of the email.
            body (str):
                The body of the email.
            name (str | None):
                The name of the person to send the email to.
                Defaults to None.
            mirai_email (str | None):
                The email address to send the email from.
                Defaults to "noreply@miraisocial.live".
            format_email (bool | None):
                Whether to format the email or not to include the Mirai logo, etc.

        Returns:
            None
        """
        if format_email:
            subject = f"[Mirai] {subject}"
            msg = f"""<p>Hello{f' {name}' if (name is not None) else ''},</p>
            {body}
            <p>
                Sincerely,<br>
                <strong>Mirai Team</strong>
            </p>
            <img src="https://storage.googleapis.com/mirai-public/common/Logo.png" alt="Mirai Logo" style="border-radius: 5px; width: min(250px, 40%);">
            """

        await self.invoke_instance(
            url=C.SEND_EMAIL_URL_FUNCTION,
            json={
                "mirai_email": mirai_email,
                "email_recipient": to,
                "email_subject": subject,
                "email_body": msg,
            },
        )

__all__ = [
    "CloudFunction",
    "EmailCloudFunction",
]