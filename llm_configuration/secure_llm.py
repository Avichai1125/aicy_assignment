from utils import handle_pii_occurances, is_the_response_echoing
from fastapi import HTTPException
import json

SYSTEM_EXTR_THREAT = "system_prompt_and_context_extraction"
INDIRECT_INJ_THREAT = "indirect_injection"

class SecureLLM:
    def __init__(self, llm_client, system_rule: str, llm_model: str, max_tokens: int):
        self.llm_client = llm_client
        self.system_rule = system_rule
        self.llm_model = llm_model
        self.max_tokens = max_tokens
        self.is_llm_approved = True
        self.response = ''
        self.threats = []

    def input_setup(self, inc_message: str):
        system_part = {"role": "system", "content": [{"type": "input_text", "text": self.system_rule}]}
        user_part = {"role": "user", "content": [{"type": "input_text", "text": inc_message}]}
        full_input = [system_part, user_part]
        return full_input

    async def invoke(self, inc_message: str):
        # The full SecureLLM process: Preparing the incoming message,
        # receiving the response from the LLM and validating the response's content.
        try:
            llm_fit_message = self.prepare_message_to_llm(inc_message)
            raw_response = self.llm_client.responses.create(
                model=self.llm_model,
                max_tokens=self.max_tokens,
                input=self.input_setup(llm_fit_message)
            )
            raw_response = json.loads(raw_response)
            self.is_llm_approved, self.response, self.threats = raw_response["approved"],\
                raw_response["reason"], raw_response["threats"]
            self.post_llm_response_validations(inc_message)
            return self.is_llm_approved, self.response, self.threats
        except Exception as e:
            raise e

    @staticmethod
    def prepare_message_to_llm(inc_message: str):
        # Before inserting the message in the LLM, we must:
        # - check if the message has content
        # - redact personal information from the message
        if len(inc_message.strip()) == 0:
            raise HTTPException(
                status_code=400,
                detail={
                    "approved": False,
                    "reason": "The incoming message is empty."
                })

        out_message = handle_pii_occurances(inc_message)
        return out_message

    def post_llm_response_validations(self, inc_message: str):
        # After receiving the response from the LLM, we must:
        # - check if the response contains personal information
        # - check if the response doesn't echo malicious injections
        # (if there is) from the original message.
        if handle_pii_occurances(self.response, post_llm_mode=True) is None:
            raise HTTPException(
                status_code=400,
                detail={
                    "approved": False,
                    "reason": "The SecureLLM response contains personal information and thus denied."
                })

        if INDIRECT_INJ_THREAT in self.threats or SYSTEM_EXTR_THREAT in self.threats:
            if is_the_response_echoing(inc_message, self.response):
                raise HTTPException(
                    status_code=400,
                    detail={
                        "approved": False,
                        "reason": "The response echoes malicious injection from the original request."
                    })


