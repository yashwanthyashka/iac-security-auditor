---
title: IaC Security Auditor
emoji: "🛡️"
colorFrom: red
colorTo: yellow
sdk: docker
app_port: 8000
pinned: false
short_description: OpenEnv agent env for Terraform security audit
---

# IaC Security Auditor OpenEnv Environment

An OpenEnv-compatible benchmark where an agent audits Terraform Infrastructure-as-Code for security vulnerabilities.

## What the agent must do

- Identify Terraform misconfigurations.
- Classify severity.
- Propose remediations.
- For hard tasks, explain how multiple issues chain into an attack path.

## Benchmark design

The environment is single-step by design:

1. `reset()` returns one Terraform task.
2. The agent submits one JSON report in `step()`.
3. A deterministic grader scores the submission.

Built-in tasks cover:

- Public S3 buckets
- Publicly reachable RDS instances
- Hardcoded secrets
- Overprivileged IAM policies
- IMDSv1 exposure
- Multi-step attack chains

## Strict scoring rule

Phase-2 rejects exact `0.0` and `1.0` task scores. This project prevents that by mapping raw grader output into the open interval `(0, 1)`:

`strict_score = 0.02 + raw_score * 0.96`

That guarantees every returned task score is greater than `0` and less than `1`, even for completely wrong or perfect submissions.

## Expected submission format

The agent should submit a JSON object containing:

- `executive_summary`
- `overall_risk`
- `findings`
- `attack_path`

Each finding should include:

- `issue_type`
- `resource`
- `severity`
- `explanation`
- `remediation`

## Local development

Install dependencies:

```bash
pip install -e .
```

Environment variables can be stored in a root `.env` file. The provided `inference.py` loads that file automatically.

Run validation:

```bash
openenv validate
```

Run the server:

```bash
python -m uvicorn server.app:app --host 0.0.0.0 --port 8000
```

## Hugging Face notes

- This Space uses `sdk: docker`.
- The root `Dockerfile` launches the OpenEnv HTTP app on port `8000`.
- Add `API_BASE_URL` and `MODEL_NAME` as Space Variables.
- Add `HF_TOKEN` as a Space Secret.
