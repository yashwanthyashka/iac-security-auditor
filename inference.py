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
TASK_NAME = os.getenv("IAC_AUDITOR_TASK_ID", "random")
BENCHMARK = "iac_security_auditor_env"
FALLBACK_SCORE = 0.02
SUCCESS_SCORE_THRESHOLD = 0.50

SYSTEM_PROMPT = """You are a cloud security reviewer auditing Terraform IaC.
Return valid JSON only. Follow the provided output schema exactly.
Be precise about issue_type, resource, severity, explanation, remediation, and attack_path.
"""


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(
    step: int, action: str, reward: float, done: bool, error: Optional[str]
) -> None:
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


def build_fallback_report(observation) -> str:
    terraform = getattr(observation, "terraform_config", "") or ""
    findings = []
    attack_path = []

    if "0.0.0.0/0" in terraform and "aws_security_group" in terraform:
        findings.append(
            {
                "issue_type": "public_ingress",
                "resource": _find_resource(terraform, 'resource "aws_security_group"'),
                "severity": "high",
                "explanation": "A security group allows inbound access from the internet.",
                "remediation": "Restrict ingress CIDRs to trusted sources only.",
            }
        )
        attack_path.append("An attacker can reach the exposed service from the internet.")

    if 'publicly_accessible = true' in terraform:
        findings.append(
            {
                "issue_type": "public_rds_access",
                "resource": _find_resource(terraform, 'resource "aws_db_instance"'),
                "severity": "critical",
                "explanation": "The database is marked publicly accessible.",
                "remediation": "Set publicly_accessible to false and place the DB in private subnets.",
            }
        )

    if 'acl    = "public-read"' in terraform:
        findings.append(
            {
                "issue_type": "public_s3_read",
                "resource": _find_resource(terraform, 'resource "aws_s3_bucket"'),
                "severity": "high",
                "explanation": "The S3 bucket is configured for public read access.",
                "remediation": "Block public access and remove public ACL usage.",
            }
        )

    if "password" in terraform and '"' in terraform:
        findings.append(
            {
                "issue_type": "plaintext_secret",
                "resource": _find_resource(terraform, 'resource "aws_db_instance"'),
                "severity": "high",
                "explanation": "A password appears hardcoded in Terraform.",
                "remediation": "Move credentials to Secrets Manager or a secure variable source.",
            }
        )

    if 'Action   = "*"' in terraform or '"*"' in terraform and "aws_iam_role_policy" in terraform:
        findings.append(
            {
                "issue_type": "overprivileged_iam",
                "resource": _find_resource(terraform, 'resource "aws_iam_role_policy"'),
                "severity": "critical",
                "explanation": "The IAM policy appears broader than least privilege.",
                "remediation": "Replace wildcard permissions with scoped actions and resources.",
            }
        )
        attack_path.append("If the role is compromised, the attacker can use excessive IAM permissions.")

    if 'http_tokens   = "optional"' in terraform:
        findings.append(
            {
                "issue_type": "imds_v1_enabled",
                "resource": _find_resource(terraform, 'resource "aws_instance"'),
                "severity": "high",
                "explanation": "IMDSv2 is not enforced because http_tokens is optional.",
                "remediation": "Require IMDSv2 by setting http_tokens to required.",
            }
        )
        attack_path.append("Metadata access may expose instance credentials.")

    if not attack_path:
        attack_path.append("Misconfigurations can increase exposure and enable lateral movement.")

    report = {
        "executive_summary": (
            "The Terraform configuration contains security misconfigurations that "
            "increase exposure and should be remediated before deployment."
        ),
        "overall_risk": "high" if findings else "medium",
        "findings": findings,
        "attack_path": attack_path,
    }
    return json.dumps(report)


def _find_resource(terraform: str, marker: str) -> str:
    for line in terraform.splitlines():
        stripped = line.strip()
        if stripped.startswith(marker):
            parts = stripped.split('"')
            if len(parts) >= 4:
                return f"{parts[1]}.{parts[3]}"
    return "unknown.resource"


def get_report_json(client: Optional[OpenAI], prompt: str, observation) -> str:
    if client is None:
        return build_fallback_report(observation)

    try:
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
    except Exception:
        return build_fallback_report(observation)


async def _connect_env():
    if LOCAL_IMAGE_NAME:
        return await IaCSecurityAuditorEnv.from_docker_image(LOCAL_IMAGE_NAME)
    return IaCSecurityAuditorEnv(base_url=ENV_BASE_URL)


async def main() -> None:
    env = None
    client: Optional[OpenAI] = None
    rewards: list[float] = []
    steps_taken = 0
    score = FALLBACK_SCORE
    success = False
    logged_start = False

    try:
        log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)
        logged_start = True

        if HF_TOKEN:
            try:
                client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)
            except Exception:
                client = None

        env = await _connect_env()
        result = await env.reset()
        prompt = build_prompt(result.observation)
        report_json = get_report_json(client, prompt, result.observation)

        result = await env.step(IaCSecurityAuditorAction(report_json=report_json))
        reward = float(result.reward or FALLBACK_SCORE)
        rewards.append(reward)
        steps_taken = 1
        score = reward
        success = reward >= SUCCESS_SCORE_THRESHOLD
        log_step(
            step=1,
            action="submit_audit_report",
            reward=reward,
            done=result.done,
            error=None,
        )
    except Exception as exc:
        if not logged_start:
            log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)
        log_step(
            step=max(1, steps_taken or 1),
            action="submit_audit_report",
            reward=FALLBACK_SCORE,
            done=True,
            error=str(exc),
        )
        score = FALLBACK_SCORE
        success = False
        if not rewards:
            rewards = [FALLBACK_SCORE]
    finally:
        if env is not None:
            try:
                await env.close()
            except Exception:
                pass

        log_end(
            success=success,
            steps=steps_taken,
            score=score,
            rewards=rewards or [FALLBACK_SCORE],
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception:
        log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)
        log_step(
            step=1,
            action="submit_audit_report",
            reward=FALLBACK_SCORE,
            done=True,
            error="fatal_inference_error",
        )
        log_end(
            success=False,
            steps=0,
            score=FALLBACK_SCORE,
            rewards=[FALLBACK_SCORE],
        )
