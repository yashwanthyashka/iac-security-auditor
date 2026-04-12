def _strict_open_interval(reward: float) -> float:
    bounded = max(0.0, min(1.0, float(reward)))
    return 0.02 + (bounded * 0.96)


def grade_task_0(state: dict, reward: float) -> float:
    return _strict_open_interval(
        reward if str(state.get("task_id", "")) == "easy_s3_public" else 0.0
    )


def grade_task_1(state: dict, reward: float) -> float:
    return _strict_open_interval(
        reward if str(state.get("task_id", "")) == "medium_rds_exposure" else 0.0
    )


def grade_task_2(state: dict, reward: float) -> float:
    return _strict_open_interval(
        reward if str(state.get("task_id", "")) == "medium_ec2_role" else 0.0
    )


def grade_task_3(state: dict, reward: float) -> float:
    return _strict_open_interval(
        reward if str(state.get("task_id", "")) == "hard_imds_chain" else 0.0
    )


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
