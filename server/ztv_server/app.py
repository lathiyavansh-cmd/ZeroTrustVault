"""FastAPI application factory."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import select

from . import config
from .audit import init_audit
from .db import SessionLocal, init_db
from .models import Policy
from .pep import build_pdp
from .routers import admin, auth, files, keys, shares
from .security import SessionStore, keys as server_keys
from .storage import storage

log = logging.getLogger("ztv")


def default_policy() -> dict:
    for cand in (Path(config.settings.SEED_FILE).parent / "policy.json", Path(__file__).resolve().parents[2] / "seed" / "policy.json"):
        if cand.exists():
            return json.loads(cand.read_text())
    return {"rules": []}


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    server_keys()  # fail fast if key material is missing
    await init_db()
    app.state.redis = Redis.from_url(config.settings.REDIS_URL, decode_responses=False)
    app.state.store = SessionStore(app.state.redis)
    st = storage()
    await st.ensure_buckets()
    async with SessionLocal() as db:
        row = await db.get(Policy, 1)
        if row is None:
            row = Policy(id=1, document=default_policy())
            db.add(row)
            await db.commit()
        policy = row.document
    app.state.pdp = build_pdp(policy)
    svc = init_audit(SessionLocal, st)
    await svc.log(actor=None, action="server.start", resource="api", decision="INFO", reason=f"mode={config.current_mode()}", details={"pdp": type(app.state.pdp).__name__})
    task = asyncio.create_task(svc.checkpoint_loop())
    log.info("ZeroTrustVault API up (mode=%s, pdp=%s)", config.current_mode(), type(app.state.pdp).__name__)
    try:
        yield
    finally:
        task.cancel()
        await app.state.redis.aclose()


def create_app() -> FastAPI:
    app = FastAPI(title="ZeroTrustVault API", version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None, lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in config.settings.CORS_ORIGINS.split(",") if o.strip()], allow_credentials=True, allow_methods=["*"], allow_headers=["*"], expose_headers=["X-Server-Time", "X-PDP-Time-Ms", "X-PDP-Eval-Ms", "WWW-Authenticate"])

    @app.middleware("http")
    async def server_time(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Server-Time"] = str(int(time.time()))
        resp.headers["Cache-Control"] = resp.headers.get("Cache-Control", "no-store")
        return resp

    @app.exception_handler(HTTPException)
    async def http_exc(request: Request, exc: HTTPException):
        body = exc.detail if isinstance(exc.detail, dict) else {"error": str(exc.detail)}
        return JSONResponse(status_code=exc.status_code, content=body, headers=dict(exc.headers or {}))

    @app.exception_handler(RequestValidationError)
    async def validation_exc(request: Request, exc: RequestValidationError):
        return JSONResponse(status_code=400, content={"error": "bad_request", "detail": json.loads(json.dumps(exc.errors(), default=str))})

    for r in (auth.router, auth.devices_router, keys.router, files.router, files.blob_router, shares.router, admin.router):
        app.include_router(r, prefix="/api")
    return app


app = create_app()
