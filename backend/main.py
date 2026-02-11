from fastapi import FastAPI

from backend.api.analyze import router as analyze_router
from backend.api.explain import router as explain_router
from backend.api.history import router as history_router
from backend.persistence.sqlite_store import init_db


def create_app() -> FastAPI:
    app = FastAPI(
        title="Security Analyzer API",
        description=(
            "Heuristic-based analysis for domains, URLs, and IP addresses. "
            "Outputs explainable signals, a 0-100 risk score, confidence, and a verdict."
        ),
        version="1.1.0",
    )

    @app.on_event("startup")
    def _startup() -> None:
        init_db()

    app.include_router(analyze_router, prefix="/api")
    app.include_router(history_router, prefix="/api")
    app.include_router(explain_router, prefix="/api")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
