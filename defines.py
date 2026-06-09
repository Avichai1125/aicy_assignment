from motor.motor_asyncio import AsyncIOMotorClient
from openai import OpenAI
import redis.asyncio as redis
import os

### Setting up env variables.

# Mongo db conn setup
mongo_db_url = os.environ["MONGO_URL"]
mongo_client = AsyncIOMotorClient(mongo_db_url)
mongo_db_client = mongo_client["api_gateway"]

# Redis client setup
redis_url = os.environ["REDIS_URL"]
redis_client = redis.from_url(
    redis_url,
    decode_responses=True
)

# OpenAI client setup
openai_client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"]
)

BACKEND_URL = os.environ["BACKEND_URL"]

### Gateway messages format variables
GW_API_KEY_HEADER = 'x-api-key:'
GW_KEY_ENCODING = "utf-8"
GW_MODEL_NAME = "SecureLLM"
GW_OPENAI_MODEL = "gpt-5"
GW_OPENAI_MAX_TOKENS = 300
GW_SYSTEM_RULE_PATH = "llm_configuration/secure_llm_rules.txt"
with open(GW_SYSTEM_RULE_PATH, "r", encoding="utf-8") as f:
    GW_SYSTEM_RULE_DESC = f.read()


class ReqStatus:
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    ERROR = "error"

### Values for redacting processes

# Regex values for redacting of gateway messages before insertion to LLM analysis.
EMAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
ISRAELI_PHONE_REGEX = r'(?<!\w)(?:\+972[- ]?|0)(?:5\d[- ]?\d{3}[- ]?\d{4}|[23489][- ]?\d{7})(?!\w)'
INTL_PHONE_REGEX = r'\b\+?[1-9]\d{1,14}\b'
ISRAELI_ID_REGEX = r'\b\d{9}\b'
REDACT_REGEX_LIST = [EMAIL_REGEX, ISRAELI_ID_REGEX, ISRAELI_PHONE_REGEX, INTL_PHONE_REGEX]

# Regex values for redacting personal information from LLM responses.
AWS_ACCESS_KEY_REGEX = r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'
JWT_FORMAT_REGEX = r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b'
SK_KEY_REGEX = r'\bsk-[A-Za-z0-9_-]{16,}\b'
POST_LLM_REGEX_LIST = [AWS_ACCESS_KEY_REGEX, JWT_FORMAT_REGEX, SK_KEY_REGEX]

# Variables for defining redacting tokens.
ID_CASE_FLAG = 'ID_CASE'
RAISE_ERROR_TOKEN = '[ERR]'
ID_TOKEN_OPTS = ['[ID]', '[PHONE]', '[INVALID_ID]']
REDACT_TOKENS = ['[EMAIL]', ID_CASE_FLAG, '[PHONE]', '[PHONE]', '[PHONE]']
PAIRS_FOR_REDACT = list(zip(REDACT_REGEX_LIST, REDACT_TOKENS))
PAIRS_FOR_POST_LLM = [(plr, RAISE_ERROR_TOKEN) for plr in POST_LLM_REGEX_LIST]
