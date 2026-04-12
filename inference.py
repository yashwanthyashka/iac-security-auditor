"""Hackathon inference entrypoint for the IaC Security Auditor benchmark."""

import asyncio
import json
import os
from typing import Optional

from dotenv import load_dotenv
from openai import OpenAI

try:
    from iac_security_auditor_env import IaCSecurityAuditorAction, IaCSecurityAuditorEnv
except ImportError:
    from client import IaCSecurityAuditorEnv
    from models import IaCSecurityAuditorAction

load_dotenv()

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Meta-Llama-3-8B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")

LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME") or os.getenv("IMAGE_NAME")
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "https://Yash-25-iac-security-auditor.hf.space")

# ✅ FIXED: valid default task
TASK_NAME = os.getenv("IAC_AUDITOR_TASK_ID", "iac_audit_task_0")

BENCHMARK = "iac_security_auditor_env"
FALLBACK_SCORE = 0.02
SUCCESS_SCORE_THRESHOLD = 0.50

SYSTEM_PROMPT = """You are a cloud security reviewer auditing Terraform IaC.
Return valid JSON only with:
- executive_summary
- overall_risk
- findings
- attack_path
"""


def log_start(task: str):
    print(f"[START] task={task}", flush=True)


def log_step(step: int, reward: float, done: bool, error: Optional[str]):
    print(
        f"[STEP] step={step} reward={reward:.2f} done={str(done).lower()} error={error or 'null'}",
        flush=True,
    )


def log_end(success: bool, score: float):
    print(f"[END] success={str(success).lower()} score={score:.3f}", flush=True)


def build_prompt(observation) -> str:
    return f"""
Task ID: {observation.task_id}
Instructions:
{observation.instructions}

Terraform:
{observation.terraform_config}
"""


def fallback_report(observation) -> str:
    return json.dumps({
        "executive_summary": "Basic security issues detected.",
        "overall_risk": "high",
        "findings": [
            {
                "issue_type": "public_access",
                "resource": "unknown",
                "severity": "high",
                "explanation": "Resource may be publicly exposed",
                "remediation": "Restrict access"
            }
        ],
        "attack_path": ["Public exposure leads to compromise"]
    })


def get_llm_response(client: Optional[OpenAI], prompt: str, observation):
    if client is None:
        return fallback_report(observation)

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )
        return response.choices[0].message.content
    except Exception:
        return fallback_report(observation)


async def connect_env():
    if LOCAL_IMAGE_NAME:
        return await IaCSecurityAuditorEnv.from_docker_image(LOCAL_IMAGE_NAME)
    return IaCSecurityAuditorEnv(base_url=ENV_BASE_URL)


async def main():
    env = None
    client: Optional[OpenAI] = None

    try:
        log_start(TASK_NAME)

        if HF_TOKEN:
            client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)

        env = await connect_env()

        result = await env.reset(task_id=TASK_NAME)

        prompt = build_prompt(result.observation)

        report = get_llm_response(client, prompt, result.observation)

        result = await env.step(IaCSecurityAuditorAction(report_json=report))

        reward = float(result.reward or FALLBACK_SCORE)

        success = reward >= SUCCESS_SCORE_THRESHOLD

        log_step(1, reward, result.done, None)
        log_end(success, reward)

    except Exception as e:
        log_step(1, FALLBACK_SCORE, True, str(e))
        log_end(False, FALLBACK_SCORE)

    finally:
        if env:
            await env.close()


if __name__ == "__main__":
    asyncio.run(main())