
class Locks:
    def __init__(self, doc: dict):
        self.id = doc["user_id"]
        self.username = doc["username"]
        self.reason = doc["reason"]
        self.done_by = doc["done_by"]
        self.done_at = doc["done_at"]
        self.lock_type = doc["lock_type"]