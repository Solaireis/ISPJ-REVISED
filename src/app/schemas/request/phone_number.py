# import third-party libraries
import phonenumbers
from pydantic import BaseModel, validator

class Phone(BaseModel):
    phone_num: str

    @validator("phone_num")
    def phone_validation(cls, value: str):
        try:
            phone_obj = phonenumbers.parse(value)
        except (phonenumbers.phonenumberutil.NumberParseException):
            raise ValueError("Invalid phone number")

        if not phonenumbers.is_valid_number(phone_obj):
            raise ValueError("Invalid phone number")
        return value