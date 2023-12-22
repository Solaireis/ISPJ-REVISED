# import third-party libraries
import orjson
from google.cloud import tasks_v2

# import local Python libraries
from utils import constants as C
from .gcp_rest import GcpRestApi
from utils.functions.useful import do_request
from .secret_manager import SecretManager

# import Python's standard libraries
import base64
import logging
from typing import Self

class CloudTasks(GcpRestApi):
    METHODS_MAP = {
        "POST": tasks_v2.HttpMethod.POST,
        "GET": tasks_v2.HttpMethod.GET,
        "HEAD": tasks_v2.HttpMethod.HEAD,
        "PUT": tasks_v2.HttpMethod.PUT,
        "DELETE": tasks_v2.HttpMethod.DELETE,
        "PATCH": tasks_v2.HttpMethod.PATCH,
        "OPTIONS": tasks_v2.HttpMethod.OPTIONS,
    }

    @classmethod
    async def init(cls, secret_manager: SecretManager | None = None, async_mode: bool | None = None) -> Self:
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
            CloudTasks:
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

    @staticmethod
    def get_queue_url(queue_name: str, project: str | None = C.GCP_PROJECT_ID, location: str | None = "asia-southeast1") -> str:
        """Get the URL of a Cloud Task queue.

        Args:
            queue_name (str):
                The name of the queue.
            project (str, optional):
                The project ID of the queue. 
                Defaults to the project ID of the current GCP project.
            location (str, optional):
                The location of the queue.
                Defaults to "asia-southeast1".

        Returns:
            str:
                The URL of the queue.
        """
        parent = tasks_v2.CloudTasksClient.queue_path(
            project=project,
            location=location,
            queue=queue_name,
        )
        return f"https://cloudtasks.googleapis.com/v2/{parent}/tasks"

    async def create_http_task(self, url: str, method: str, queue_name: str, payload: dict | list | str | bytes, location: str | None = "asia-southeast1") -> dict:
        """Create a HTTP trigger Cloud Task.

        Args:
            url (str):
                The URL to send the payload to.
            queue_name (str):
                The name of the queue to create the task in.
            payload (dict | list | str | bytes):
                The payload to send to the task.
            location (str | None):
                The location of the queue to create the task in.
                Defaults to "asia-southeast1".

        Returns:
            dict:
                The created task JSON response information.
        """
        queue_url = self.get_queue_url(queue_name=queue_name, location=location)

        if isinstance(payload, dict | list):
            payload = orjson.dumps(payload)
        elif isinstance(payload, str):
            payload = payload.encode("utf-8")
        payload = base64.b64encode(payload).decode("utf-8")

        http_method = None
        method = method.upper()
        if method in self.METHODS_MAP:
            http_method = self.METHODS_MAP[method]
        else:
            raise ValueError(f"Invalid HTTP method: {method}")

        task = {
            "http_request": {
                "http_method": http_method,
                "url": url,
                "oidc_token": {
                    "service_account_email": self._credentials["client_email"],
                    "audience": url,
                },
                "body": payload,
            },
        }

        headers = await self.get_authorised_headers()
        response = await do_request(
            url=queue_url,
            method="POST",
            request_kwargs={
                "headers": headers,
                "json": {
                    "task": task,
                },
            },
            get_json=True,
        )
        logging.info(f"Created task {response['name']}")
        return response

    async def find_task(self, task_name: str, get_full_details: bool | None = False) -> dict | None:
        """Find a task in a queue.

        Args:
            task_name (str):
                The name of the task. (e.g. projects/ispj-mirai/locations/asia-southeast1/queues/export-user/tasks/61200249992053979411)
            get_full_details (bool | None):
                Whether to get the full details of the task. 
                You should only get the full details of the task if you need to get the payload of the task.
                Defaults to False (only get the basic details).

        Returns:
            dict | None:
                The task JSON response information if the task is found, else None (when the task is not found or has been completed/deleted)
        """
        url = f"https://cloudtasks.googleapis.com/v2/{task_name}"
        headers = await self.get_authorised_headers()
        response, json_response = await do_request(
            url=url,
            method="GET",
            request_kwargs={
                "headers": headers,
                "params": {
                    "responseView": "FULL" if get_full_details else "BASIC",
                }
            },
            get_response=True,
            check_status=False,
            get_json=True,
        )
        return json_response if response.status_code == 200 else None

__all__ = [
    "CloudTasks",
]