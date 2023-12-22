# import third-party libraries
import bson
import httpx
from fastapi import Request
from fastapi.exceptions import HTTPException
from pymongo.database import Database

# import local Python libraries
from gcp import SecretManager
from utils import constants as C
from utils.functions.useful import (
    url_for, 
    do_request,
)

# import Python's standard libraries
import asyncio
from datetime import (
    datetime, 
    timedelta,
)
from typing import Self

class StripeSubscription():
    @classmethod
    async def init(cls, secret_manager: SecretManager | None = None, async_mode: bool | None = True) -> Self:
        obj = StripeSubscription()
        if secret_manager is None:
            if async_mode:
                secret_manager = await SecretManager.init()
            else:
                secret_manager = SecretManager()

        secrets = ("stripe-secret-key", "mirai-plus-key")
        if async_mode:
            obj.api_key, obj.mirai_plus = await asyncio.gather(*[
                secret_manager.get_secret_payload_async(
                    secret_id=secret_id,
                ) for secret_id in secrets
            ])
        else:
            obj.api_key, obj.mirai_plus = [
                secret_manager.get_secret_payload(
                    secret_id=secret_id,
                ) for secret_id in secrets
            ]
        return obj

    async def create_new_session(self, request: Request, user_id: str | bson.ObjectId, email: str, old_session_id: str | None = None) -> dict | None:
        coroutines = [
            do_request(
                url="https://api.stripe.com/v1/checkout/sessions",
                method="POST",
                get_json=True,
                request_kwargs={
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "auth": (self.api_key, ""),
                    "data": f"""
                    success_url={url_for(request, 'payment_complete', external=True)}&
                    cancel_url={url_for(request, 'mirai_plus', external=True)}&
                    line_items[0][price]={self.mirai_plus}&
                    line_items[0][quantity]=1&
                    mode=subscription&
                    metadata[created_by]={str(user_id)}&
                    metadata[cancelled]={False}&
                    customer_email={email}"""
                },
            ),
        ]

        if old_session_id:
            coroutines.append(
                do_request(
                    url=f"https://api.stripe.com/v1/checkout/sessions/{old_session_id}/expire",
                    method="POST",
                    request_kwargs={"auth": (self.api_key, "")},
                ),
            )

        checkout_session = await asyncio.gather(*coroutines, return_exceptions=True)
        checkout_session = checkout_session[0]

        if isinstance(checkout_session, dict):
            return checkout_session
        return None

    async def get_subscription(self, user_id: str | bson.ObjectId, checkout_session_id: str) -> str | None:
        try:
            checkout_session = await do_request(
                url=f"https://api.stripe.com/v1/checkout/sessions/{checkout_session_id}",
                method="GET",
                get_json=True,
                request_kwargs={"auth": (self.api_key, "")},
            )
        except HTTPException:
            return None

        payment_success = (checkout_session["payment_status"] == "paid")
        correct_user = (checkout_session["metadata"]["created_by"] == str(user_id))

        if payment_success and correct_user:
            return checkout_session["subscription"]
        return None

    async def cancel_subscription(self, subscription_id: str) -> None | datetime:
        try:
            subscription = await do_request(
                url=f"https://api.stripe.com/v1/subscriptions/{subscription_id}",
                method="POST",
                get_json=True,
                request_kwargs={
                    "auth": (self.api_key, ""),
                    "data": "pause_collection[behavior]=mark_uncollectible&metadata[cancelled]=true"
                },
            )
        except HTTPException:
            return None

        return datetime.utcfromtimestamp(subscription["current_period_end"])

    async def resume_subscription(self, subscription_id: str) -> bool:
        try:
            await do_request(
                url=f"https://api.stripe.com/v1/subscriptions/{subscription_id}",
                method="POST",
                get_json=True,
                request_kwargs={
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "auth": (self.api_key, ""),
                    "data": "pause_collection=&metadata[cancelled]=false",
                },
            )
        except HTTPException:
            return False
        return True

    async def update_subscription_metadata(self, subscription_id, **kwargs) -> None:
        await do_request(
            url=f"https://api.stripe.com/v1/subscriptions/{subscription_id}",
            method="POST",
            get_json=True,
            request_kwargs={
                "auth": (self.api_key, ""),
                "data": "&".join(f"metadata[{key}]={value}" for key, value in kwargs.items())
            }
        )

    async def remove_late_subscriptions(self, db: Database | None):
        params = {
            "query": """
                status:"incomplete" 
                OR status:"past_due" 
                OR metadata["cancelled"]:"true" """,
            "limit": 10,
        }
        data = {"has_more": True}

        while data["has_more"]:
            async with httpx.AsyncClient(http2=True) as client:
                response:httpx.Response = await client.get(
                    url='https://api.stripe.com/v1/subscriptions/search',
                    params=params,
                    auth=(self.api_key, ""),
                )
                response.raise_for_status()
                data = response.json()

                await asyncio.gather(*[
                    self.check_for_expiry(db, client, subscription["items"]["data"][0], self.api_key)
                    for subscription in data["data"]
                ], return_exceptions=True)
                params["page"] = data["next_page"]

        current_time = datetime.utcnow()
        previous_month = current_time.replace(day=1) - timedelta(days=1)
        user_col = db[C.USER_COLLECTION]
        payment_col = db[C.PAYMENT_COLLECTION]

        _filter = {"end_date": {
            "$lte": current_time,
            "$gte": previous_month,
        }}

        async for payment in payment_col.find(_filter):
            await asyncio.gather(
                user_col.update_one(
                    filter={"_id": payment["user_id"]},
                    update={"mirai_plus": False},
                ),
                client.delete(
                    url=f"https://api.stripe.com/v1/subscriptions/{payment['subscription']}",
                    auth=(self.api_key, ""),
                ),
                return_exceptions=True
            )

        return data

    async def check_for_expiry(self, db:Database, client: httpx.AsyncClient, subscription: dict, verify=True):
        # Check every 20 days, but also check to make sure there's no new subscription in the repeated 10 days
        user_col = db[C.USER_COLLECTION]
        payment_col = db[C.PAYMENT_COLLECTION]

        subscription_id = subscription["subscription"]
        user_id = bson.ObjectId(subscription["metadata"]["created_by"])

        current_time = datetime.utcnow()
        previous_month = current_time.replace(day=1) - timedelta(days=1)

        if verify:
            response = await payment_col.find_one(
                filter={
                    "user_id": user_id,
                    "end_date": {
                        "$lte": current_time,
                        "$gte": previous_month,
                    },
                },
                projection={"_id": True},
            )
            if not response:
                return

        await asyncio.gather(
            user_col.update_one(
                filter={"_id": user_id},
                update={"mirai_plus": False},
            ),
            client.delete(
                url=f"https://api.stripe.com/v1/subscriptions/{subscription_id}",
                auth=(self.api_key, ""),
            ),
            return_exceptions=True
        )