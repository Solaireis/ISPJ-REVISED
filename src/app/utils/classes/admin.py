# import local Python libraries
from .common import Common

class Admin(Common):
    def __init__(self, doc: dict):
        super().__init__(doc)
        self.inactive: bool = doc["inactive"]["status"]