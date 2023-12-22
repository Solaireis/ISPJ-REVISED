# import third-party libraries
from pydantic import Field

# import local Python libraries
from .recaptcha_token import RecaptchaToken

class ForgotPasswordProcess(RecaptchaToken):
    token: str = Field(
        min_length=20,
        title="Password Reset Token",
        description="The signed password reset token sent to the user's email address.",
        example="CiQArDhoGy5rlUC73Cfu4RYVo1ht7RLQKp96931yijSox7slJ_4SjgEA2u-xvFLQk_F6hRssNTy5pqVZJRo1alxGEkRkTQ_7oAxGoHDPScnPlmMGgbZSMCBz6PkVvBBjjKuWJfqyWtPJmST1lK-aJmVctkeLbchCOKoEoZcCwBSKnC3OZinUwgPqEwzsmMmOlrG_Y15GGvR24gibzTZCdo3MpBeRTAbn2LliYArF0yPyhNiAdM_y",
    )
    password: str = Field(
        min_length=8,
        max_length=64,
        title="User Password",
        description="The password entered by the user to hash using Argon2 before saving it into the database.",
        example="P@ssw0rd!",
    )