from .base import MiraiBaseException

class UserInactiveException(MiraiBaseException):
    def __init__(self, username: str, reason: str, expiry: str , time: str , done_by: str | None = "Never") -> None:
        self.username = username
        self.reason = reason
        self.expiry = expiry
        self.time = time
        self.done_by = done_by

    def __str__(self) -> str:
        return f"Admin '{self.username}' is inactive for '{self.reason}' until {self.expiry}."