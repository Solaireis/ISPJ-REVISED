# import local Python libraries
from .base import MiraiBaseException

class UserBannedException(MiraiBaseException):
    def __init__(self, username: str, reason: str, expiry: str ,time: str , done_by : str | None = "Never") -> None:
        self.username = username
        self.reason = reason
        self.expiry = expiry
        self.time = time
        self.done_by = done_by

    def __str__(self) -> str:
        return f"User '{self.username}' is banned for '{self.reason}' until {self.expiry}."