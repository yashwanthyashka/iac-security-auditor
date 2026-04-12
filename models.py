"""Pydantic models for the IaC Security Auditor environment."""

from openenv.core.env_server.types import Action, Observation
from pydantic import Field


class IaCSecurityAuditorAction(Action):
    """Agent submission containing a JSON report."""

    report_json: str = Field(
        ...,
        description=(
            "JSON string with keys findings, attack_path, executive_summary, and "
            "overall_risk."
        ),
    )


class IaCSecurityAuditorObservation(Observation):
    """Observation describing the current Terraform audit task and result."""

    task_id: str = Field(..., description="Stable identifier for the current task")
    title: str = Field(..., description="Human-readable task title")
    difficulty: str = Field(..., description="Task difficulty label")
    instructions: str = Field(..., description="Instructions for the agent")
    terraform_config: str = Field(..., description="Terraform configuration to audit")
    expected_output_schema: str = Field(
        ..., description="JSON schema guidance for the agent output"
    )
    submission_feedback: str = Field(
        default="",
        description="Grader feedback after an audit submission",
    )
    strict_score: float = Field(
        default=0.02,
        description="Task score mapped strictly inside the open interval (0, 1)",
    )
