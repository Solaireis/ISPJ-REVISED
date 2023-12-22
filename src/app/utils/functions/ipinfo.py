# import third-party libraries
import ipinfo

# import local Python libraries
from gcp.secret_manager import SecretManager

async def get_ipinfo_handler(
    secret_manager: SecretManager | None = None, 
    async_mode: bool | None = True,
) -> ipinfo.handler_async.AsyncHandler:
    """Get the ipinfo handler.

    Args:
        secret_manager (SecretManager, optional): 
            The secret manager.
            Defaults to None and a new SecretManager object will be initialised.
        async_mode (bool | None):
                Whether to use async mode or not.
                Defaults to None and will use async mode.
                Use it if the function is blocking any async I/O. 
                Otherwise, leave it as False to improve performance.

    Returns:
        ipinfo.handler_async.AsyncHandler: 
            The ipinfo async handler.
    """
    if secret_manager is None:
        if async_mode:
            secret_manager = await SecretManager.init()
        else:
            secret_manager = SecretManager()

    if async_mode:
        ipinfo_token = await secret_manager.get_secret_payload_async("ipinfo-token")
    else:
        ipinfo_token = secret_manager.get_secret_payload("ipinfo-token")
    return ipinfo.getHandlerAsync(
        access_token=ipinfo_token,
    )

__all__ = [
    "get_ipinfo_handler",
]