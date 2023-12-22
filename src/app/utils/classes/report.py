class Report:
    def __init__(self, doc: dict):
        self.id = doc["_id"]
        self.title = doc["title"]
        self.affected = doc["affected"]
        self.reasons = doc["reasons"]
        self.created_at = doc["created_at"]
        self.status = doc["status"]
        self.reported_user_id = doc["reported_user_id"]
        self.reported_username = doc["reported_username"]
        self.reported_by = doc["reported_by"]
        self.report_by_id = doc["report_by_id"]