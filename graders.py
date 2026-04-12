"""Static grader registry for hackathon validator discovery."""

from __future__ import annotations

from typing import Any


def _strict_open_interval(reward: float) -> float:
    bounded = max(0.0, min(1.0, float(reward)))
    return 0.02 + (bounded * 0.96)


def _grade_for_index(state: dict[str, Any], reward: float, expected_index: int) -> float:
    task_id = state.get("task_id")
    if isinstance(task_id, str):
        valid = task_id.endswith(("easy_s3_public", "medium_rds_exposure", "medium_ec2_role", "hard_imds_chain")[expected_index])
    else:
        valid = False
    return _strict_open_interval(reward if valid else 0.0)


def grade_task_0(state: dict[str, Any], reward: float) -> float:
    return _grade_for_index(state, reward, 0)


def grade_task_1(state: dict[str, Any], reward: float) -> float:
    return _grade_for_index(state, reward, 1)


def grade_task_2(state: dict[str, Any], reward: float) -> float:
    return _grade_for_index(state, reward, 2)


def grade_task_3(state: dict[str, Any], reward: float) -> float:
    return _grade_for_index(state, reward, 3)


GRADERS = {
    "iac_audit_task_0": grade_task_0,
    "iac_audit_task_1": grade_task_1,
    "iac_audit_task_2": grade_task_2,
    "iac_audit_task_3": grade_task_3,
}

TASK_GRADER_PAIRS = [
    ("iac_audit_task_0", grade_task_0),
    ("iac_audit_task_1", grade_task_1),
    ("iac_audit_task_2", grade_task_2),
    ("iac_audit_task_3", grade_task_3),
]

__all__ = [
    "grade_task_0",
    "grade_task_1",
    "grade_task_2",
    "grade_task_3",
    "GRADERS",
    "TASK_GRADER_PAIRS",
]
