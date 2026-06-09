from fastapi import HTTPException
from datetime import datetime, timezone
from defines import GW_KEY_ENCODING, PAIRS_FOR_POST_LLM,\
    PAIRS_FOR_REDACT, ID_CASE_FLAG, ID_TOKEN_OPTS, RAISE_ERROR_TOKEN
from difflib import SequenceMatcher
import hashlib
import re


def hasher(data: str):
    return hashlib.sha256(data.encode(GW_KEY_ENCODING)).hexdigest()


async def validate_api_key(api_key: str, mongo_db_client, check_if_admin: bool = False):
    # Hashing and finding the key in the database
    now_key_hash = hasher(api_key)
    key_record = await mongo_db_client.api_keys.find_one(
        {
            "key_hash": now_key_hash,
            "active": True
        }
    )

    # If the key is not stored, raising 401 error.
    if not key_record:
        raise HTTPException(
            status_code=401,
            detail="The API key is invalid"
        )

    # By an input flag, checking if the key belongs to an admin, if it's not - raising 401 error.
    if check_if_admin:
        key_client_role = key_record.get("admin", "client")
        if key_client_role != "admin":
            raise HTTPException(
                status_code=401,
                detail="Current action is accessible for admins only."
            )

async def write_to_log(mon_db, api_key_id: str | None, model: str | None, request_hash: str,
                       response_hash: str | None, detected_threats: list[str], latency_ms: int, status: str):
    await mon_db.audit_logs.insert_one(
        {
            "timestamp": datetime.now(timezone.utc),
            "api_key_id": api_key_id,
            "model": model,
            "request_hash": request_hash,
            "response_hash": response_hash,
            "detected_threats": detected_threats,
            "latency_ms": latency_ms,
            "status": status
        }
    )


def validate_israeli_id(id_number):
    id_number = str(id_number).zfill(9)
    total = 0
    for i, digit in enumerate(id_number):
        num = int(digit) * (1 if i % 2 == 0 else 2)
        if num > 9:
            num = num // 10 + num % 10
        total += num

    # Values corresponding to indices of the options' list for id tokens:
    # ID_TOKEN_OPTS = ['[ID]', '[PHONE]', '[INVALID_ID]']
    if total % 10 == 0:
        return 0
    elif id_number[:2] in ['02', '03', '04', '08', '09']:
        # Consider it as an Israeli home phone number (for example: 035054157)
        return 1
    else:
        return 2


def handle_pii_occurances(inc_message: str, post_llm_mode: bool = False):
    pii_handle_list = PAIRS_FOR_POST_LLM if post_llm_mode else PAIRS_FOR_REDACT
    out_message = inc_message
    for pii_pattern, pii_rep_token in pii_handle_list:
        if pii_rep_token == ID_CASE_FLAG:
            # For the pattern of id, we decide the redacting token based on the validity of the id itself
            def id_replace(match):
                id_number = match.group(0)
                is_id_valid = validate_israeli_id(id_number)
                return ID_TOKEN_OPTS[is_id_valid]

            out_message = re.sub(pii_pattern, id_replace, out_message)
        else:
            out_message = re.sub(pii_pattern, pii_rep_token, out_message)
            if pii_rep_token == RAISE_ERROR_TOKEN and RAISE_ERROR_TOKEN in out_message:
                return None

    return out_message


def is_the_response_echoing(orig_msg: str, now_resp: str, echo_ratio: float = 0.8):
    quote_flag = orig_msg in now_resp
    similarity_msg_resp = SequenceMatcher(None, orig_msg, now_resp).ratio()
    return (similarity_msg_resp > echo_ratio) or quote_flag

