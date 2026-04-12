"""Server-side environment implementation for Terraform security auditing."""

from __future__ import annotations

import os
from random import Random
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import EnvironmentMetadata, State

try:
    from ..benchmark_data import TASK_INDEX, TASKS, AuditTask
    from ..grader import grade_submission
    from ..models import IaCSecurityAuditorAction, IaCSecurityAuditorObservation
except ImportError:
    from benchmark_data import TASK_INDEX, TASKS, AuditTask
    from grader import grade_submission
    from models import IaCSecurityAuditorAction, IaCSecurityAuditorObservation


OUTPUT_SCHEMA = """
Return a JSON object with this shape:
{
  "executive_summary": "short summary",
  "overall_risk": "low|medium|high|critical",
  "findings": [
    {
      "issue_type": "one of: public_ingress, public_rds_access, public_s3_read, missing_encryption, plaintext_secret, overprivileged_iam, imds_v1_enabled",
      "resource": "terraform resource address",
      "severity": "low|medium|high|critical",
      "explanation": "why this is risky",
      "remediation": "how to fix it"
    }
  ],
  "attack_path": ["step 1", "step 2", "step 3"]
}
""".strip()


class IaCSecurityAuditorEnvironment(
    Environment[IaCSecurityAuditorAction, IaCSecurityAuditorObservation, State]
):
    """One-step benchmark where the agent audits a Terraform configuration."""

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self):
        super().__init__()
        self._rng = Random()
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._current_task: AuditTask | None = None

    def _select_task(self, seed: int | None = None) -> AuditTask:
        requested = os.getenv("IAC_AUDITOR_TASK_ID", "").strip()
        if requested and requested in TASK_INDEX:
            return TASK_INDEX[requested]
        if seed is not None:
            return TASKS[seed % len(TASKS)]
        return self._rng.choice(list(TASKS))

    def _build_observation(
        self,
        task: AuditTask,
        submission_feedback: str = "",
        strict_score: float = 0.02,
        reward: float | None = None,
        done: bool = False,
    ) -> IaCSecurityAuditorObservation:
        instructions = (
            "Audit the Terraform configuration for security issues. Identify each "
            "misconfiguration, assign a severity, propose a remediation, and for "
            "hard tasks explain how multiple issues chain into an attack path."
        )
        return IaCSecurityAuditorObservation(
            task_id=task.task_id,
            title=task.title,
            difficulty=task.difficulty,
            instructions=instructions,
            terraform_config=task.terraform_config,
            expected_output_schema=OUTPUT_SCHEMA,
            submission_feedback=submission_feedback,
            strict_score=strict_score,
            done=done,
            reward=reward,
            metadata={
                "allowed_issue_types": list(task.allowed_issue_types),
                "task_requires_attack_path": bool(task.attack_path_keywords),
            },
        )

    def reset(
        self,
        seed: int | None = None,
        episode_id: str | None = None,
        **kwargs,
    ) -> IaCSecurityAuditorObservation:
        self._current_task = self._select_task(seed=seed)
        self._state = State(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
            **{"task_id": self._current_task.task_id, "completed": False},
        )
        return self._build_observation(task=self._current_task)

    def step(
        self,
        action: IaCSecurityAuditorAction,
        timeout_s: float | None = None,
        **kwargs,
    ) -> IaCSecurityAuditorObservation:
        if self._current_task is None:
            self.reset()

        assert self._current_task is not None
        self._state.step_count += 1

        grade = grade_submission(self._current_task, action.report_json)
        self._state = State(
            episode_id=self._state.episode_id,
            step_count=self._state.step_count,
            **{"task_id": self._current_task.task_id, "completed": True},
        )
        return self._build_observation(
            task=self._current_task,
            submission_feedback=grade.feedback,
            strict_score=grade.strict_score,
            reward=grade.strict_score,
            done=True,
        )

    @property
    def state(self) -> State:
        return self._state

    def get_metadata(self) -> EnvironmentMetadata:
        return EnvironmentMetadata(
            name="IaCSecurityAuditorEnvironment",
            description=(
                "OpenEnv benchmark where agents audit Terraform IaC for "
                "misconfigurations, severity, remediation, and attack chains."
            ),
            version="0.1.0",
            author="Codex for Meta OpenEnv hackathon",
        )
