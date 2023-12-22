# import Python's standard libraries
import enum

class SearchType(enum.Enum):
    USER = "people"
    POST = "post"
    COMMENT = "comment"