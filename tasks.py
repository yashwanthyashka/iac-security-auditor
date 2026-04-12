"""Static task registry for hackathon validator discovery."""

from benchmark_data import TASKS as BENCHMARK_TASKS


TASKS = [
    {
        "id": "iac_audit_task_0",
        "task_id": BENCHMARK_TASKS[0].task_id,
        "name": "audit-public-s3",
        "difficulty": BENCHMARK_TASKS[0].difficulty,
        "description": BENCHMARK_TASKS[0].title,
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
        "task_id": BENCHMARK_TASKS[1].task_id,
        "name": "audit-public-rds",
        "difficulty": BENCHMARK_TASKS[1].difficulty,
        "description": BENCHMARK_TASKS[1].title,
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
        "task_id": BENCHMARK_TASKS[2].task_id,
        "name": "audit-bastion-iam",
        "difficulty": BENCHMARK_TASKS[2].difficulty,
        "description": BENCHMARK_TASKS[2].title,
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
        "task_id": BENCHMARK_TASKS[3].task_id,
        "name": "audit-attack-chain",
        "difficulty": BENCHMARK_TASKS[3].difficulty,
        "description": BENCHMARK_TASKS[3].title,
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

TASK_ID_TO_INDEX = {task["task_id"]: idx for idx, task in enumerate(TASKS)}

TASK_GRADER_PAIRS = [(task["id"], task["grader"]) for task in TASKS]

__all__ = ["TASKS", "TASK_ID_TO_INDEX", "TASK_GRADER_PAIRS"]
