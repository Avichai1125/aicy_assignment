from defines import mongo_db_client, redis_client, openai_client, BACKEND_URL,\
    GW_OPENAI_MODEL, GW_OPENAI_MAX_TOKENS, GW_SYSTEM_RULE_DESC, GW_MODEL_NAME, ReqStatus
from llm_configuration.secure_llm import SecureLLM
from utils import validate_api_key, handle_pii_occurances, hasher, write_to_log
from datetime import datetime
from fastapi import Header, Query, FastAPI, HTTPException
from pydantic import BaseModel
import requests
import time
import json

app = FastAPI()
gw_secure_llm = SecureLLM(llm_client=openai_client,
                          system_rule=GW_SYSTEM_RULE_DESC,
                          llm_model=GW_OPENAI_MODEL,
                          max_tokens=GW_OPENAI_MAX_TOKENS)


class MessageRequest(BaseModel):
    user_id: str
    message: str


@app.post("/v1/chat")
async def gateway_message(payload: MessageRequest, x_api_key: str = Header(...)):
    start_time = time.perf_counter()
    threats = []
    # Checking api-key validity and then handling the message itself
    try:
        await validate_api_key(x_api_key, mongo_db_client)
        approved, reason, threats = await gw_secure_llm.invoke(payload.message)
        if not approved:
            raise HTTPException(
                status_code=400,
                detail={
                    "approved": False,
                    "reason": reason
                })

    except Exception as e:
        latency_ms = int(
            (time.perf_counter() - start_time) * 1000
        )

        log_req_status = ReqStatus.BLOCKED if isinstance(e, HTTPException) else ReqStatus.ERROR

        await write_to_log(
            mon_db=mongo_db_client,
            api_key_id=x_api_key,
            model=GW_MODEL_NAME,
            request_hash=hasher(payload.message),
            response_hash=None,
            detected_threats=threats,
            latency_ms=latency_ms,
            status=log_req_status
        )

        if log_req_status == ReqStatus.ERROR:
            raise HTTPException(
                status_code=500,
                detail={
                    "approved": False,
                    "reason": f"An unexpected error: {str(e)}"
                })
        else:
            raise e

    latency_ms = int(
        (time.perf_counter() - start_time) * 1000
    )

    backend_response = requests.post(
        BACKEND_URL,
        json=payload.model_dump(),
        timeout=10
    )

    await write_to_log(
        mon_db = mongo_db_client,
        api_key_id=x_api_key,
        model=GW_MODEL_NAME,
        request_hash=hasher(payload.message),
        response_hash=hasher(backend_response.text),
        detected_threats=threats,
        latency_ms=latency_ms,
        status=ReqStatus.ALLOWED
    )

    return {
        "approved": True,
        "backend_status": backend_response.status_code
    }


@app.get("/v1/audit")
async def get_audit_logs(since: datetime, limit: int = Query(default=100, ge=1, le=500), api_key: str = Header(...)):
    # Validating api_key in order to block requests from non admin users.
    try:
        await validate_api_key(api_key, mongo_db_client, check_if_admin=True)
    except Exception as e:
        raise e

    logs = await mongo_db_client.audit_logs.find(
        {"timestamp": {"$gte": since}}
    ).sort(
        "timestamp", -1
    ).limit(limit).to_list(length=limit)

    return {
        "count": len(logs),
        "entries": logs
    }


@app.get("/healthz")
async def readiness():
    mongo_ok = False
    redis_ok = False
    provider_ok = False

    try:
        await mongo_db_client.command("ping")
        mongo_ok = True
    except Exception:
        pass

    try:
        await redis_client.ping()
        redis_ok = True
    except Exception:
        pass

    try:
        openai_client.models.list()
        provider_ok = True
    except Exception:
        pass

    ready = mongo_ok and redis_ok and provider_ok

    return {
        "ready": ready,
        "dependencies": {
            "mongodb": mongo_ok,
            "redis": redis_ok,
            "openai": provider_ok
        }
    }
