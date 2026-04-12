"""Static task registry for hackathon validator discovery."""

from importlib.util import find_spec

PACKAGE_GRADER_MODULE = "iac_security_auditor_env.graders"
LOCAL_GRADER_MODULE = "graders"


def _is_module_available(module_name: str) -> bool:
    try:
        return find_spec(module_name) is not None
    except ModuleNotFoundError:
        return False


GRADER_MODULE = (
    PACKAGE_GRADER_MODULE
    if _is_module_available(PACKAGE_GRADER_MODULE)
    else LOCAL_GRADER_MODULE
)


TASKS = [
    {
        "id": "iac_audit_task_0",
        "task_id": "easy_s3_public",
        "name": "audit-public-s3",
        "difficulty": "easy",
        "description": "Audit a Terraform configuration with a public S3 bucket and missing encryption.",
        "max_steps": 1,
        "reset_params": {"seed": 0},
        "action_schema": {
            "report_json": "JSON string containing executive_summary, overall_risk, findings, attack_path"
        },
        "grader": f"{GRADER_MODULE}:grade_task_0",
        "graders": [
            f"{PACKAGE_GRADER_MODULE}:grade_task_0",
            f"{LOCAL_GRADER_MODULE}:grade_task_0",
        ],
        "reward_range": [0.0, 1.0],
    },
    {
        "id": "iac_audit_task_1",
        "task_id": "medium_rds_exposure",
        "name": "audit-public-rds",
        "difficulty": "medium",
        "description": "Audit a Terraform configuration with public database exposure and a hardcoded password.",
        "max_steps": 1,
        "reset_params": {"seed": 1},
        "action_schema": {
            "report_json": "JSON string containing executive_summary, overall_risk, findings, attack_path"
        },
        "grader": f"{GRADER_MODULE}:grade_task_1",
        "graders": [
            f"{PACKAGE_GRADER_MODULE}:grade_task_1",
            f"{LOCAL_GRADER_MODULE}:grade_task_1",
        ],
        "reward_range": [0.0, 1.0],
    },
    {
        "id": "iac_audit_task_2",
        "task_id": "medium_ec2_role",
        "name": "audit-bastion-iam",
        "difficulty": "medium",
        "description": "Audit a Terraform configuration with internet-exposed SSH and an overprivileged IAM policy.",
        "max_steps": 1,
        "reset_params": {"seed": 2},
        "action_schema": {
            "report_json": "JSON string containing executive_summary, overall_risk, findings, attack_path"
        },
        "grader": f"{GRADER_MODULE}:grade_task_2",
        "graders": [
            f"{PACKAGE_GRADER_MODULE}:grade_task_2",
            f"{LOCAL_GRADER_MODULE}:grade_task_2",
        ],
        "reward_range": [0.0, 1.0],
    },
    {
        "id": "iac_audit_task_3",
        "task_id": "hard_imds_chain",
        "name": "audit-attack-chain",
        "difficulty": "hard",
        "description": "Audit a Terraform configuration where internet exposure, metadata access, and IAM permissions form an attack chain.",
        "max_steps": 1,
        "reset_params": {"seed": 3},
        "action_schema": {
            "report_json": "JSON string containing executive_summary, overall_risk, findings, attack_path"
        },
        "grader": f"{GRADER_MODULE}:grade_task_3",
        "graders": [
            f"{PACKAGE_GRADER_MODULE}:grade_task_3",
            f"{LOCAL_GRADER_MODULE}:grade_task_3",
        ],
        "reward_range": [0.0, 1.0],
    },
]

TASK_ID_TO_INDEX = {
    "easy_s3_public": 0,
    "medium_rds_exposure": 1,
    "medium_ec2_role": 2,
    "hard_imds_chain": 3,
}

TASK_GRADER_PAIRS = [
    ("iac_audit_task_0", f"{GRADER_MODULE}:grade_task_0"),
    ("iac_audit_task_1", f"{GRADER_MODULE}:grade_task_1"),
    ("iac_audit_task_2", f"{GRADER_MODULE}:grade_task_2"),
    ("iac_audit_task_3", f"{GRADER_MODULE}:grade_task_3"),
]

__all__ = ["TASKS", "TASK_ID_TO_INDEX", "TASK_GRADER_PAIRS"]
