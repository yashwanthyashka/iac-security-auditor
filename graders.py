"""Unified graders for IaC Security Auditor tasks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

try:
    from .benchmark_data import AuditTask, ExpectedFinding, TASKS
except ImportError:
    from benchmark_data import AuditTask, ExpectedFinding, TASKS

EPSILON_SCORE = 0.02


@dataclass
class GradeResult:
    strict_score: float
    raw_score: float
    feedback: str
    matched_findings: int
    total_findings: int


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    text = re.sub(r"[^a-z0-9_./:-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _strict_open_interval(raw_score: float) -> float:
    bounded = max(0.0, min(1.0, raw_score))
    return EPSILON_SCORE + (bounded * (1.0 - 2.0 * EPSILON_SCORE))


def _contains_keywords(text: str, keywords: tuple[str, ...]) -> float:
    if not keywords:
        return 1.0
    matches = sum(1 for keyword in keywords if keyword.lower() in text)
    return matches / len(keywords)


def _parse_submission(report_json: str) -> dict[str, Any]:
    payload = json.loads(report_json)
    if not isinstance(payload, dict):
        raise ValueError("Submission must be a JSON object.")
    return payload


def _best_finding_score(
    predicted_findings: list[dict[str, Any]], expected: ExpectedFinding
) -> float:
    best = 0.0
    for finding in predicted_findings:
        issue_type = _normalize_text(finding.get("issue_type"))
        resource = _normalize_text(finding.get("resource"))
        severity = _normalize_text(finding.get("severity"))
        explanation = _normalize_text(finding.get("explanation"))
        remediation = _normalize_text(finding.get("remediation"))

        score = 0.0
        if issue_type == _normalize_text(expected.issue_type):
            score += 0.40
        if resource == _normalize_text(expected.resource):
            score += 0.25
        if severity == _normalize_text(expected.severity):
            score += 0.15
        score += 0.10 * _contains_keywords(explanation, expected.explanation_keywords)
        score += 0.10 * _contains_keywords(remediation, expected.remediation_keywords)
        best = max(best, score)
    return min(best, 1.0)


def grade_submission(task: AuditTask, report_json: str) -> GradeResult:
    try:
        payload = _parse_submission(report_json)
    except Exception as exc:
        feedback = (
            "Submission was not valid JSON. Expected an object with findings, "
            f"attack_path, executive_summary, and overall_risk. Error: {exc}"
        )
        return GradeResult(
            strict_score=_strict_open_interval(0.0),
            raw_score=0.0,
            feedback=feedback,
            matched_findings=0,
            total_findings=len(task.findings),
        )

    predicted_findings = payload.get("findings", [])
    if not isinstance(predicted_findings, list):
        predicted_findings = []

    finding_scores = [
        _best_finding_score(
            [finding for finding in predicted_findings if isinstance(finding, dict)],
            expected,
        )
        for expected in task.findings
    ]

    matched_findings = sum(1 for score in finding_scores if score >= 0.6)
    findings_component = (
        sum(finding_scores) / len(finding_scores) if finding_scores else 0.0
    )

    attack_path_component = 1.0
    if task.attack_path_keywords:
        attack_path = payload.get("attack_path", [])
        if isinstance(attack_path, list):
            attack_text = _normalize_text(" ".join(str(item) for item in attack_path))
        else:
            attack_text = _normalize_text(attack_path)
        attack_path_component = _contains_keywords(
            attack_text, task.attack_path_keywords
        )

    executive_summary = _normalize_text(payload.get("executive_summary", ""))
    summary_component = 0.0
    if executive_summary:
        summary_component = 1.0 if len(executive_summary.split()) >= 8 else 0.5

    false_positive_penalty = 0.0
    extra_findings = max(0, len(predicted_findings) - len(task.findings))
    if extra_findings:
        false_positive_penalty = min(0.15, extra_findings * 0.03)

    raw_score = (
        0.75 * findings_component
        + 0.20 * attack_path_component
        + 0.05 * summary_component
        - false_positive_penalty
    )
    raw_score = max(0.0, min(1.0, raw_score))
    strict_score = _strict_open_interval(raw_score)

    feedback_lines = [
        f"Matched {matched_findings} of {len(task.findings)} expected findings.",
        f"Raw score={raw_score:.3f}; strict score={strict_score:.3f}.",
    ]
    if task.attack_path_keywords:
        feedback_lines.append(
            "Hard-task chain coverage is based on whether the report links internet exposure, "
            "metadata access, credential theft, and sensitive S3 backups."
        )

    return GradeResult(
        strict_score=strict_score,
        raw_score=raw_score,
        feedback=" ".join(feedback_lines),
        matched_findings=matched_findings,
        total_findings=len(task.findings),
    )

def grade_task_0(state: dict, reward: float) -> float:
    return reward

def grade_task_1(state: dict, reward: float) -> float:
    return reward

def grade_task_2(state: dict, reward: float) -> float:
    return reward

def grade_task_3(state: dict, reward: float) -> float:
    return reward
# def grade_task_0(state: dict, reward: float) -> float:
#     return _strict_open_interval(
#         reward if str(state.get("task_id", "")) == "easy_s3_public" else 0.0
#     )


# def grade_task_1(state: dict, reward: float) -> float:
#     return _strict_open_interval(
#         reward if str(state.get("task_id", "")) == "medium_rds_exposure" else 0.0
#     )


# def grade_task_2(state: dict, reward: float) -> float:
#     return _strict_open_interval(
#         reward if str(state.get("task_id", "")) == "medium_ec2_role" else 0.0
#     )


# def grade_task_3(state: dict, reward: float) -> float:
#     return _strict_open_interval(
#         reward if str(state.get("task_id", "")) == "hard_imds_chain" else 0.0
#     )


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

# TASKS = [
#     {
#         "id": "iac_audit_task_0",
#         "name": "audit-public-s3",
#         "difficulty": "easy",
#         "description": "Identify public S3 exposure and missing encryption in Terraform.",
#         "max_steps": 1,
#         "reward_range": [0.0, 1.0],
#         "grader": {
#             "type": "function",
#             "module": "graders",
#             "function": "grade_task_0",
#             "partial_credit": True,
#         },
#     },
#     {
#         "id": "iac_audit_task_1",
#         "name": "audit-public-rds",
#         "difficulty": "medium",
#         "description": "Identify public database exposure and a hardcoded password.",
#         "max_steps": 1,
#         "reward_range": [0.0, 1.0],
#         "grader": {
#             "type": "function",
#             "module": "graders",
#             "function": "grade_task_1",
#             "partial_credit": True,
#         },
#     },
#     {
#         "id": "iac_audit_task_2",
#         "name": "audit-bastion-iam",
#         "difficulty": "medium",
#         "description": "Identify internet-facing bastion access and overprivileged IAM.",
#         "max_steps": 1,
#         "reward_range": [0.0, 1.0],
#         "grader": {
#             "type": "function",
#             "module": "graders",
#             "function": "grade_task_2",
#             "partial_credit": True,
#         },
#     },
#     {
#         "id": "iac_audit_task_3",
#         "name": "audit-attack-chain",
#         "difficulty": "hard",
#         "description": "Explain how internet exposure, metadata access, and IAM combine into an attack chain.",
#         "max_steps": 1,
#         "reward_range": [0.0, 1.0],
#         "grader": {
#             "type": "function",
#             "module": "graders",
#             "function": "grade_task_3",
#             "partial_credit": True,
#         },
#     },
# ]

# __all__ = [
#     "TASKS",
#     "GRADERS",
#     "TASK_GRADER_PAIRS",
#     "GradeResult",
#     "grade_submission",
#     "grade_task_0",
#     "grade_task_1",
#     "grade_task_2",
#     "grade_task_3",
# ]
