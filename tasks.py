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
        "grader": "graders:grade_task_0",
        "graders": ["graders:grade_task_0"],
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
        "grader": "graders:grade_task_1",
        "graders": ["graders:grade_task_1"],
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
        "grader": "graders:grade_task_2",
        "graders": ["graders:grade_task_2"],
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
        "grader": "graders:grade_task_3",
        "graders": ["graders:grade_task_3"],
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
    ("iac_audit_task_0", "graders:grade_task_0"),
    ("iac_audit_task_1", "graders:grade_task_1"),
    ("iac_audit_task_2", "graders:grade_task_2"),
    ("iac_audit_task_3", "graders:grade_task_3"),
]

__all__ = ["TASKS", "TASK_ID_TO_INDEX", "TASK_GRADER_PAIRS"]
