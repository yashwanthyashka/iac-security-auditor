"""Hackathon inference entrypoint for the IaC Security Auditor benchmark."""

import asyncio
import json
import os
from typing import Optional

from openai import OpenAI
from dotenv import load_dotenv

try:
    from iac_security_auditor_env import IaCSecurityAuditorAction, IaCSecurityAuditorEnv
except ImportError:
    from client import IaCSecurityAuditorEnv
    from models import IaCSecurityAuditorAction

load_dotenv()

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "openai/gpt-4.1-mini")
HF_TOKEN = os.getenv("HF_TOKEN")
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME") or os.getenv("IMAGE_NAME")
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://127.0.0.1:8000")
TASK_NAME = os.getenv("IAC_AUDITOR_TASK_ID", "random")
BENCHMARK = "iac_security_auditor_env"
SUCCESS_SCORE_THRESHOLD = 0.50

SYSTEM_PROMPT = """You are a cloud security reviewer auditing Terraform IaC.
Return valid JSON only. Follow the provided output schema exactly.
Be precise about issue_type, resource, severity, explanation, remediation, and attack_path.
"""


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={str(done).lower()} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: list[float]) -> None:
    rewards_str = ",".join(f"{reward:.2f}" for reward in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


def build_prompt(observation) -> str:
    return (
        f"Task ID: {observation.task_id}\n"
        f"Title: {observation.title}\n"
        f"Difficulty: {observation.difficulty}\n"
        f"Instructions:\n{observation.instructions}\n\n"
        f"Terraform configuration:\n{observation.terraform_config}\n\n"
        f"Required output schema:\n{observation.expected_output_schema}\n"
    )


def get_report_json(client: OpenAI, prompt: str) -> str:
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
        response_format={"type": "json_object"},
    )
    content = response.choices[0].message.content or "{}"
    json.loads(content)
    return content


async def _connect_env():
    if LOCAL_IMAGE_NAME:
        return await IaCSecurityAuditorEnv.from_docker_image(LOCAL_IMAGE_NAME)
    return IaCSecurityAuditorEnv(base_url=ENV_BASE_URL)


async def main() -> None:
    if not HF_TOKEN:
        raise ValueError("HF_TOKEN environment variable is required")

    client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)
    env = await _connect_env()

    rewards: list[float] = []
    steps_taken = 0
    score = 0.02
    success = False

    log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)

    try:
        result = await env.reset()
        prompt = build_prompt(result.observation)
        report_json = get_report_json(client, prompt)

        result = await env.step(IaCSecurityAuditorAction(report_json=report_json))
        reward = float(result.reward or 0.02)
        rewards.append(reward)
        steps_taken = 1
        score = reward
        success = reward >= SUCCESS_SCORE_THRESHOLD
        log_step(step=1, action="submit_audit_report", reward=reward, done=result.done, error=None)
    except Exception as exc:
        log_step(
            step=max(1, steps_taken or 1),
            action="submit_audit_report",
            reward=0.02,
            done=True,
            error=str(exc),
        )
        score = 0.02
        success = False
    finally:
        try:
            await env.close()
        finally:
            log_end(success=success, steps=steps_taken, score=score, rewards=rewards or [score])


if __name__ == "__main__":
    asyncio.run(main())
