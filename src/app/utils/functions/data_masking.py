# import third-party libraries
from fastapi import (
    Request,
    WebSocket,
)

# import local Python libraries
from gcp import (
    GoogleNLP,
)
from .useful import (
    check_if_str_is_url,
)
import utils.constants as C

# import Python's standard libraries
import re
import warnings

LUHN_ODD_LOOKUP = (0, 2, 4, 6, 8, 1, 3, 5, 7, 9)
def validate_card_number(card_number: str) -> bool:
    """Validate a credit card number using the 
    Luhn's algorithm, aka the modulus 10 or mod 10 algorithm.

    Args:
        card_number (str): 
            The credit card number to validate.

    Returns:
        bool:
            True if the card number is valid, False otherwise.
    """
    card_number = card_number.replace(" ", "").replace("-", "")
    if all(char == "0" for char in card_number):
        return False

    try:
        evens = sum(int(c) for c in card_number[-1::-2])
        odds = sum(LUHN_ODD_LOOKUP[int(c)] for c in card_number[-2::-2])
        return ((evens + odds) % 10 == 0)
    except (ValueError):
        return False

ST_CHECKSUMS = {
    0: "J",
    1: "Z",
    2: "I",
    3: "H",
    4: "G",
    5: "F",
    6: "E",
    7: "D",
    8: "C",
    9: "B",
    10: "A"
}
FG_CHECKSUMS = {
    0: "X",
    1: "W",
    2: "U",
    3: "T",
    4: "R",
    5: "Q",
    6: "P",
    7: "N",
    8: "M",
    9: "L",
    10: "K"
}
M_CHECKSUMS = {
    0: "K",
    1: "L",
    2: "J",
    3: "N",
    4: "P",
    5: "Q",
    6: "R",
    7: "T",
    8: "U",
    9: "W", 
    10: "X",
}
WEIGHTS = (2, 7, 6, 5, 4, 3, 2)
def validate_nric(nric: str) -> bool:
    """Validates a Singapore NRIC.
    Thanks to https://github.com/samliew/singapore-nric for the main logic.

    Args:
        nric (str):
            The NRIC to validate.

    Returns:
        bool:
            True if the NRIC is valid, False otherwise.
    """
    nric = nric.upper().strip()
    if len(nric) != 9:
        return False

    first_char = nric[0]
    if first_char not in ("S", "T", "F", "G", "M"):
        return False

    last_char = nric[-1]
    weight = sum(int(nric[idx]) * WEIGHTS[idx-1] for idx in range(1, 8))

    # get offsets and add to weight
    if first_char in ("T", "G"):
        weight += 4
    elif first_char == "M":
        weight += 3

    idx = weight % 11
    if first_char in ("S", "T"):
        checksums = ST_CHECKSUMS
    elif first_char in ("F", "G"):
        checksums = FG_CHECKSUMS
    else: # first_char == "M"
        idx = 10 - idx # rotate the index
        checksums = M_CHECKSUMS

    checksum_last_char = checksums.get(idx)
    return (checksum_last_char is not None and last_char == checksum_last_char)

SENSITIVE_DATA_REGEX: tuple[re.Pattern] = (
    C.SG_STR_ADDR_REGEX,
    C.SSN_REGEX,
)
async def call_ai_api_and_analyse_text(request: Request | WebSocket, text: str) -> list[str]:
    """Calls the Google NLP API to analyse the text.

    Args:
        request (Request | WebSocket):
            The request or websocket object.
        text (str):
            The text to analyse.

    Returns:
        list[str]:
            The list of sensitive information found in the text.
    """
    text_without_url = (t for t in text.split() if not check_if_str_is_url(t))
    text = " ".join(text_without_url)

    sensitive_str = []
    cloud_nlp: GoogleNLP = request.app.state.obj_map[GoogleNLP]
    json_response = await cloud_nlp.analyse_entities(text)
    for entity in json_response.get("entities", []):
        if entity["type"] in ("ADDRESS", "PHONE_NUMBER",):
            sensitive_str.append(entity["name"])

    # mask any VALID sensitive information
    sensitive_str.extend(
        card_number.strip()
        for card_number in C.CREDIT_CARD_REGEX.findall(text)
        if validate_card_number(card_number)
    )
    sensitive_str.extend(
        nric
        for nric in C.NRIC_REGEX.findall(text)
        if validate_nric(nric)
    )

    for regex in SENSITIVE_DATA_REGEX:
        sensitive_str.extend(regex.findall(text))
    return sensitive_str

MASKED_INFO_STR =  "*****"
async def mask_sensitive_info(request: Request | WebSocket, text: str | None) -> str:
    """Masks any sensitive information in a string.

    Args:
        request (Request | WebSocket):
            The request or websocket object.
        text (str | None):
            The text to mask. If None, you will get a RuntimeWarning.

    Returns:
        str: 
            The masked text.

    Raises:
        TypeError:
            If the text is not a string or NoneType.
    """
    if isinstance(text, str):
        text = text.strip()
    elif text is not None:
        raise TypeError("text must be a string or NoneType!")

    if text is None or not text:
        warnings.warn(
            "No text provided to mask sensitive information.",
            RuntimeWarning,
        )
        return text

    if check_if_str_is_url(text):
        return text

    for sensitive_str in await call_ai_api_and_analyse_text(request, text):
        text = text.replace(sensitive_str, MASKED_INFO_STR, 1)
    return text