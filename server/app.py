"""FastAPI app for the IaC Security Auditor OpenEnv environment."""

import os
import subprocess
try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:  # pragma: no cover
    raise ImportError(
        "openenv is required for the web interface. Install dependencies first."
    ) from e

from fastapi.responses import RedirectResponse

try:
    from ..models import IaCSecurityAuditorAction, IaCSecurityAuditorObservation
    from ..graders import TASKS as DECLARED_TASKS
    from .iac_security_auditor_env_environment import IaCSecurityAuditorEnvironment
except ImportError:
    from models import IaCSecurityAuditorAction, IaCSecurityAuditorObservation
    from graders import TASKS as DECLARED_TASKS
    from server.iac_security_auditor_env_environment import IaCSecurityAuditorEnvironment

app = create_app(
    IaCSecurityAuditorEnvironment,
    IaCSecurityAuditorAction,
    IaCSecurityAuditorObservation,
    env_name="iac_security_auditor_env",
    max_concurrent_envs=4,
)

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")

@app.get("/tasks")
def list_tasks():
    return {"tasks": DECLARED_TASKS}

# --- NEW ADDITION: Grader Endpoint required for Phase 2 Validation ---
@app.get("/grader")
async def get_grader():
    results = {}
    
    # We iterate over the 4 internal task_ids defined in your benchmark_data.py
    tasks_to_run = [
        ("easy_s3_public", "iac_audit_task_0"),
        ("medium_rds_exposure", "iac_audit_task_1"),
        ("medium_ec2_role", "iac_audit_task_2"),
        ("hard_imds_chain", "iac_audit_task_3")
    ]
    
    overall = 0.0
    for internal_id, task_key in tasks_to_run:
        # Force the environment to load this specific task using your existing logic
        os.environ["IAC_AUDITOR_TASK_ID"] = internal_id
        
        env = IaCSecurityAuditorEnvironment()
        obs = env.reset()
        
        # Send a valid dummy JSON payload to gracefully trigger the graders.py logic
        dummy_payload = '{"findings": [], "executive_summary": "dummy baseline evaluation", "overall_risk": "low", "attack_path": []}'
        action = IaCSecurityAuditorAction(report_json=dummy_payload)
        obs = env.step(action)
        
        # Fetch the strict score returned by grade_submission (fallback to 0.02)
        score = obs.strict_score if hasattr(obs, 'strict_score') else 0.02
        
        results[task_key] = {
            "score": round(score, 4),
            "done": obs.done,
            "task_id": internal_id
        }
        overall += score
        
    overall_score = overall / len(tasks_to_run) if tasks_to_run else 0.0
    
    return {
        "overall_score": round(overall_score, 4),
        "tasks": results
    }

# --- NEW ADDITION: Baseline Endpoint (Matches the working metarl repo) ---
@app.get("/baseline")
async def run_baseline():
    try:
        result = subprocess.run(
            ["python", "inference.py"],  
            capture_output=True,
            text=True,
            env=os.environ,          
            timeout=120
        )
        return {
            "status": "success" if result.returncode == 0 else "error",
            "output": result.stdout,
            "stderr": result.stderr
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Inference script timed out after 120s"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def main(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    main()