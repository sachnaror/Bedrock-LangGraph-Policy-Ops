from fastapi import FastAPI

from app.api.routes import router
from app.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description=(
            "Natural-language AI access governance assistant with Bedrock, "
            "LangGraph, ABAC, IAM-style policy checks, OPA, and audit traces."
        ),
    )
    app.include_router(router)
    return app


app = create_app()
