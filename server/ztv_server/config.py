"""Server configuration (pydantic-settings). Env names match docker-compose.yml x-api-env."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

MODES = ("zerotrustvault", "baseline")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    MODE: str = "zerotrustvault"
    DATABASE_URL: str = "postgresql+asyncpg://ztv:ztv-dev-password@localhost:5433/ztv"
    DATABASE_URL_SYNC: str = "postgresql://ztv:ztv-dev-password@localhost:5433/ztv"
    REDIS_URL: str = "redis://localhost:6379/0"
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: str = "ztv-minio"
    MINIO_SECRET_KEY: str = "ztv-minio-dev-secret"
    MINIO_BUCKET: str = "ztv-ciphertext"
    MINIO_AUDIT_BUCKET: str = "audit-checkpoints"
    PUBLIC_BASE_URL: str = "https://localhost:8443"
    ADMIN_API_KEY: str = "ztv-dev-admin-key-change-me"
    BASELINE_SERVER_KEY: str = "00" * 32
    DB_POOL_SIZE: int = 60
    DB_MAX_OVERFLOW: int = 60
    ALLOW_RUNTIME_MODE_SWITCH: bool = False
    ORG_ROOT_PUB_FILE: str = "/keys/org_root.pub.json"
    SERVER_KEYS_DIR: str = "/keys"
    TLS_DIR: str = "/certs"
    SEED_FILE: str = "/seed/seed.json"
    SEED_OUTPUT_DIR: str = "/seed/generated"
    SEED_API_URL: str = "https://api:8000"
    OPA_URL: str | None = None
    WEBAUTHN_RP_ID: str = "localhost"
    WEBAUTHN_ORIGINS: str = "https://localhost:8443,http://localhost:5173"
    CORS_ORIGINS: str = "http://localhost:5173,https://localhost:5173"
    ACCESS_TOKEN_SECONDS: int = 300
    REFRESH_TOKEN_SECONDS: int = 8 * 3600
    BASELINE_TOKEN_SECONDS: int = 30 * 24 * 3600
    BLOB_URL_SECONDS: int = 60
    STEP_UP_SECONDS: int = 300
    LOGIN_MAX_FAILURES: int = 5
    LOGIN_LOCK_SECONDS: int = 900
    LOGIN_RATE_PER_MINUTE: int = 30
    REQUIRE_MTLS: bool = True
    LISTEN_PORT: int = 8000

    @property
    def org_root_pk(self) -> bytes:
        from ztv_crypto.encoding import b64u_decode

        return b64u_decode(json.loads(Path(self.ORG_ROOT_PUB_FILE).read_text())["pk"])

    @property
    def baseline_key(self) -> bytes:
        """Static server-side key for baseline mode: 64 hex chars, else SHA-256 of the configured string."""
        import hashlib

        v = str(self.BASELINE_SERVER_KEY).strip()
        try:
            k = bytes.fromhex(v)
            if len(k) == 32:
                return k
        except ValueError:
            pass
        return hashlib.sha256(v.encode()).digest()


settings = Settings()

# Runtime-switchable mode (guarded by ALLOW_RUNTIME_MODE_SWITCH at the endpoint).
_mode_lock = threading.Lock()
_mode = {"value": settings.MODE if settings.MODE in MODES else "zerotrustvault"}


def current_mode() -> str:
    return _mode["value"]


def set_mode(mode: str) -> str:
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode}")
    with _mode_lock:
        _mode["value"] = mode
    return mode


def is_baseline() -> bool:
    return current_mode() == "baseline"
