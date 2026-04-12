"""FastAPI app for the IaC Security Auditor OpenEnv environment."""

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:  # pragma: no cover
    raise ImportError(
        "openenv is required for the web interface. Install dependencies first."
    ) from e

try:
    from ..models import IaCSecurityAuditorAction, IaCSecurityAuditorObservation
    from .iac_security_auditor_env_environment import IaCSecurityAuditorEnvironment
except ImportError:
    from models import IaCSecurityAuditorAction, IaCSecurityAuditorObservation
    from server.iac_security_auditor_env_environment import IaCSecurityAuditorEnvironment


app = create_app(
    IaCSecurityAuditorEnvironment,
    IaCSecurityAuditorAction,
    IaCSecurityAuditorObservation,
    env_name="iac_security_auditor_env",
    max_concurrent_envs=4,
)


def main(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
