"""Static task registry for validator discovery."""

def _grader_spec(function_name: str) -> dict:
    return {
        "type": "function",
        "module": "graders",
        "function": function_name,
    }


TASKS = [
    {
        "id": "iac_audit_task_0",
        "name": "audit-public-s3",
        "description": "Identify public S3 bucket exposure.",
        "difficulty": "easy",
        "max_steps": 1,
        "grader": _grader_spec("grade_task_0"),
    },
    {
        "id": "iac_audit_task_1",
        "name": "audit-public-rds",
        "description": "Identify public database exposure.",
        "difficulty": "medium",
        "max_steps": 1,
        "grader": _grader_spec("grade_task_1"),
    },
    {
        "id": "iac_audit_task_2",
        "name": "audit-bastion-iam",
        "description": "Identify IAM misconfiguration.",
        "difficulty": "medium",
        "max_steps": 1,
        "grader": _grader_spec("grade_task_2"),
    },
    {
        "id": "iac_audit_task_3",
        "name": "audit-attack-chain",
        "description": "Identify multi-step attack chain.",
        "difficulty": "hard",
        "max_steps": 1,
        "grader": _grader_spec("grade_task_3"),
    },
]


# ✅ THIS IS THE MISSING PIECE
TASK_GRADER_PAIRS = [
    ("iac_audit_task_0", "graders:grade_task_0"),
    ("iac_audit_task_1", "graders:grade_task_1"),
    ("iac_audit_task_2", "graders:grade_task_2"),
    ("iac_audit_task_3", "graders:grade_task_3"),
]


__all__ = ["TASKS", "TASK_GRADER_PAIRS"]



















# """Static task registry for validator discovery."""

# def _grader_spec(function_name: str) -> dict:
#     return {
#         "type": "function",
#         "module": "graders",
#         "function": function_name,
#     }


# TASKS = [
#     {
#         "id": "iac_audit_task_0",
#         "name": "audit-public-s3",
#         "description": "Identify public S3 bucket exposure.",
#         "difficulty": "easy",
#         "max_steps": 1,
#         "grader": _grader_spec("grade_task_0"),
#     },
#     {
#         "id": "iac_audit_task_1",
#         "name": "audit-public-rds",
#         "description": "Identify public database exposure and hardcoded password.",
#         "difficulty": "medium",
#         "max_steps": 1,
#         "grader": _grader_spec("grade_task_1"),
#     },
#     {
#         "id": "iac_audit_task_2",
#         "name": "audit-bastion-iam",
#         "description": "Identify open SSH and overprivileged IAM.",
#         "difficulty": "medium",
#         "max_steps": 1,
#         "grader": _grader_spec("grade_task_2"),
#     },
#     {
#         "id": "iac_audit_task_3",
#         "name": "audit-attack-chain",
#         "description": "Identify full attack chain across services.",
#         "difficulty": "hard",
#         "max_steps": 1,
#         "grader": _grader_spec("grade_task_3"),
#     },
# ]

# __all__ = ["TASKS"]