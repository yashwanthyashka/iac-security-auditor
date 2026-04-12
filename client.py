"""Client for the IaC Security Auditor environment."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

try:
    from .models import IaCSecurityAuditorAction, IaCSecurityAuditorObservation
except ImportError:
    from models import IaCSecurityAuditorAction, IaCSecurityAuditorObservation


class IaCSecurityAuditorEnv(
    EnvClient[IaCSecurityAuditorAction, IaCSecurityAuditorObservation, State]
):
    """Typed OpenEnv client for the Terraform auditing benchmark."""

    def _step_payload(self, action: IaCSecurityAuditorAction) -> Dict:
        return {"report_json": action.report_json}

    def _parse_result(self, payload: Dict) -> StepResult[IaCSecurityAuditorObservation]:
        obs_data = payload.get("observation", {})
        observation = IaCSecurityAuditorObservation(
            task_id=obs_data.get("task_id", ""),
            title=obs_data.get("title", ""),
            difficulty=obs_data.get("difficulty", ""),
            instructions=obs_data.get("instructions", ""),
            terraform_config=obs_data.get("terraform_config", ""),
            expected_output_schema=obs_data.get("expected_output_schema", ""),
            submission_feedback=obs_data.get("submission_feedback", ""),
            strict_score=obs_data.get("strict_score", 0.02),
            done=payload.get("done", False),
            reward=payload.get("reward"),
            metadata=obs_data.get("metadata", {}),
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
            **{
                "task_id": payload.get("task_id"),
                "completed": payload.get("completed", False),
            },
        )
