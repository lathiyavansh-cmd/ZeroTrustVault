"""Shared plumbing for the ZeroTrustVault attack-simulation lab.

Config from the environment (with localhost fallbacks so the lab also runs
outside docker), seed credential/state loaders, a self-sufficient `make_client`
(falls back to the admin API to create users/files), mode switching, TLS-aware
HTTP / MinIO / Postgres factories, the plaintext marker, and the `Result`
record used by every attack and by the runner.

Written entirely against docs/CONTRACT.md and the headless-client interface
(`ztv_crypto.headless_client.ZTVClient`).  The backend + headless client are built
by another agent and may not yet be importable/reachable, so every dependency is
imported lazily and attacks degrade to a recorded ERROR row instead of crashing.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

MARKER = "ZTV-PLAINTEXT-MARKER"
MODES = ("baseline", "zerotrustvault")

DEFAULT_PASSWORDS = {
    "admin": "Admin-Pass-123", "alice": "Alice-Pass-123", "bob": "Bob-Pass-123",
    "carol": "Carol-Pass-123", "dan": "Dan-Pass-123",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _first_existing(*paths: str) -> Optional[str]:
    for p in paths:
        if p and Path(p).exists():
            return p
    return None


@dataclass
class Config:
    api_url: str
    direct_url: str
    ca_cert: Optional[str]
    client_cert: Optional[tuple]
    pin_spki_b64: Optional[str]
    minio_endpoint: str
    minio_access: str
    minio_secret: str
    minio_bucket: str
    minio_audit_bucket: str
    pg_dsn: str
    admin_key: str
    baseline_server_key: str
    seed_dir: str
    org_root_pk_b64u: Optional[str]
    key_passphrase: Optional[str]
    edge_cert: Optional[str] = None


def load_config() -> Config:
    root = _repo_root()
    certs = [str(root / "infra" / "certs"), "/certs"]
    ca = _first_existing(*(f"{c}/internal-ca.crt" for c in certs))
    edge = _first_existing(*(f"{c}/public.crt" for c in certs))
    crt = _first_existing(*(f"{c}/nginx-client.crt" for c in certs))
    key = _first_existing(*(f"{c}/nginx-client.key" for c in certs))
    client_cert = (crt, key) if crt and key else None
    seed_dir = os.environ.get("ZTV_SEED_DIR") or _first_existing(str(root / "seed"), "/seed") or str(root / "seed")

    org_pk = os.environ.get("ZTV_ORG_ROOT_PK")
    if not org_pk:
        pub = _first_existing("/keys/org_root.pub.json", str(root / "infra" / "keys" / "org_root.pub.json"))
        if pub:
            try:
                org_pk = json.loads(Path(pub).read_text()).get("pk")
            except (OSError, ValueError):
                org_pk = None

    return Config(
        api_url=os.environ.get("ZTV_API_URL", "https://localhost:8443"),
        direct_url=os.environ.get("ZTV_API_DIRECT_URL", "https://localhost:8000"),
        ca_cert=ca,
        edge_cert=edge,
        client_cert=client_cert,
        pin_spki_b64=os.environ.get("ZTV_PIN_SPKI"),
        minio_endpoint=os.environ.get("ZTV_MINIO_ENDPOINT", "localhost:9000"),
        minio_access=os.environ.get("MINIO_ACCESS_KEY", "ztv-minio"),
        minio_secret=os.environ.get("MINIO_SECRET_KEY", "ztv-minio-dev-secret"),
        minio_bucket=os.environ.get("MINIO_BUCKET", "ztv-ciphertext"),
        minio_audit_bucket=os.environ.get("MINIO_AUDIT_BUCKET", "audit-checkpoints"),
        pg_dsn=os.environ.get("ZTV_PG_DSN", "postgresql://ztv:ztv-dev-password@localhost:5433/ztv"),
        admin_key=os.environ.get("ADMIN_API_KEY", "ztv-dev-admin-key-change-me"),
        baseline_server_key=os.environ.get("BASELINE_SERVER_KEY", "0" * 64),
        seed_dir=seed_dir,
        org_root_pk_b64u=org_pk,
        key_passphrase=os.environ.get("ZTV_KEY_PASSPHRASE"),
    )


CFG = load_config()

# --------------------------------------------------------------------------- #
# Seed material                                                               #
# --------------------------------------------------------------------------- #
def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def load_credentials(cfg: Config = CFG) -> dict:
    return _load_json(Path(cfg.seed_dir) / "generated" / "credentials.json")


def load_state(cfg: Config = CFG) -> dict:
    return _load_json(Path(cfg.seed_dir) / "generated" / "state.json")


def creds_for(username: str, cfg: Config = CFG) -> dict:
    c = load_credentials(cfg).get(username, {})
    pw = c.get("password") or DEFAULT_PASSWORDS.get(username, "")
    return {"password": pw, "totp_secret": c.get("totp_secret"),
            "passphrase": cfg.key_passphrase or c.get("passphrase") or pw}


def find_file(name: str, cfg: Config = CFG) -> Optional[dict]:
    return load_state(cfg).get("files", {}).get(name)


# --------------------------------------------------------------------------- #
# Lazy imports / low-level factories                                          #
# --------------------------------------------------------------------------- #
class ClientUnavailable(RuntimeError):
    pass


def import_client():
    try:
        from ztv_crypto.headless_client import ZTVClient, IntegrityError, AccessDenied, StepUpRequired  # type: ignore
    except Exception as e:  # pragma: no cover
        raise ClientUnavailable(f"ztv_crypto.headless_client not importable yet: {e}") from e
    return ZTVClient, IntegrityError, AccessDenied, StepUpRequired


def exc_types():
    """(IntegrityError, AccessDenied, StepUpRequired) — safe to call anywhere."""
    _, ie, ad, su = import_client()
    return ie, ad, su


def _verify_arg(cfg: Config, direct: bool = False):
    """Trust anchor: the nginx edge presents the self-signed public.crt (SPKI-pinned by real
    clients); the direct mTLS port presents a cert from the internal CA."""
    if direct:
        return cfg.ca_cert if cfg.ca_cert else False
    return cfg.edge_cert if cfg.edge_cert else (cfg.ca_cert if cfg.ca_cert else False)


def new_device_key():
    from ztv_crypto import DeviceKey  # type: ignore
    return DeviceKey.generate()


def raw_http(cfg: Config = CFG, *, direct: bool = False):
    import httpx
    kw: dict[str, Any] = {"verify": _verify_arg(cfg, direct), "timeout": 20.0}
    base = cfg.direct_url if direct else cfg.api_url
    if direct and cfg.client_cert:
        kw["cert"] = cfg.client_cert
    return httpx.Client(base_url=base, **kw)


def minio_client(cfg: Config = CFG):
    from minio import Minio
    ep = cfg.minio_endpoint.replace("https://", "").replace("http://", "")
    secure = cfg.minio_endpoint.startswith("https")
    return Minio(ep, access_key=cfg.minio_access, secret_key=cfg.minio_secret, secure=secure)


def pg_connect(cfg: Config = CFG):
    import psycopg
    return psycopg.connect(cfg.pg_dsn, autocommit=False)


# --------------------------------------------------------------------------- #
# Mode control                                                                #
# --------------------------------------------------------------------------- #
def get_mode(cfg: Config = CFG) -> Optional[str]:
    try:
        with raw_http(cfg) as h:
            r = h.get("/api/mode")
            if r.status_code == 200:
                return r.json().get("mode")
            r = h.get("/api/health")
            if r.status_code == 200:
                return r.json().get("mode")
    except Exception:
        pass
    return None


def set_mode(mode: str, cfg: Config = CFG) -> bool:
    assert mode in MODES, f"unknown mode {mode}"
    try:
        with raw_http(cfg) as h:
            r = h.post("/api/admin/mode", json={"mode": mode}, headers={"X-Admin-Key": cfg.admin_key})
            return r.status_code == 200
    except Exception:
        return False


def wait_for_health(cfg: Config = CFG, timeout: float = 60.0) -> bool:
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with raw_http(cfg) as h:
                if h.get("/api/health").status_code == 200:
                    return True
        except Exception:
            pass
        time.sleep(1.5)
    return False


# --------------------------------------------------------------------------- #
# Clients / provisioning (self-sufficient)                                    #
# --------------------------------------------------------------------------- #
def make_client(username: str, *, cfg: Config = CFG, load_keys: bool = False, new_device: bool = True,
                posture: str = "registered", direct: bool = False, password: Optional[str] = None,
                totp_secret: Optional[str] = "auto"):
    """Return a logged-in ZTVClient for `username`.

    Reads seed credentials; TOTP is auto-handled in ztv mode.  `new_device`
    forces a fresh device key (the default; each lab client is its own device).
    If the user cannot log in, we create them through the admin API so the lab is
    self-sufficient.  `load_keys` enrols + waits for the offline CA if no key blob
    exists yet.  Pass `totp_secret=None` to deliberately attempt a login with no
    second factor (used by a2_stolen_creds against the ZTV MFA gate).
    """
    ZTVClient, _, _, _ = import_client()
    cr = creds_for(username, cfg)
    pw = password or cr["password"]
    totp = cr["totp_secret"] if totp_secret == "auto" else totp_secret
    base = cfg.direct_url if direct else cfg.api_url
    client_cert = cfg.client_cert if direct else None
    dev = new_device_key() if new_device else None
    client = ZTVClient(base, verify=_verify_arg(cfg, direct), client_cert=client_cert,
                       pin_spki_b64=cfg.pin_spki_b64, device_key=dev, posture=posture,
                       org_root_pk_b64u=cfg.org_root_pk_b64u)
    try:
        client.login(username, pw, totp_secret=totp)
    except Exception:
        _admin_ensure_user(cfg, username, pw)
        client.login(username, pw, totp_secret=totp)
    if load_keys:
        try:
            client.load_keys(cr["passphrase"])
        except Exception:
            try:
                client.enroll_keys(cr["passphrase"])
                client.wait_for_cert(timeout=60)
            except Exception:
                pass
    return client


def _admin_ensure_user(cfg: Config, username: str, password: str) -> None:
    try:
        with raw_http(cfg) as h:
            h.post("/api/admin/users",
                   json={"username": username, "password": password, "role": "analyst",
                         "department": "research", "clearance": 2},
                   headers={"X-Admin-Key": cfg.admin_key})
    except Exception:
        pass


_TARGET_CACHE: dict = {}


def ensure_target_file(cfg: Config = CFG, *, name: str = "q3-results.pdf",
                       classification: str = "CONFIDENTIAL", fresh: bool = False) -> dict:
    """Provision a confidential file owned by alice (and, in zerotrustvault mode, a signed grant
    for bob) for the CURRENT mode.  Provisioned once per mode per process so every attack in a
    run shares the same target; `fresh=True` forces a new one.  Seeded files are deliberately not
    reused: earlier runs may have rotated/revoked/exhausted them, which would make an attack
    'blocked' for the wrong reason."""
    mode = get_mode(cfg) or "zerotrustvault"
    if not fresh and mode in _TARGET_CACHE:
        return _TARGET_CACHE[mode]
    owner = make_client("alice", cfg=cfg, load_keys=(mode != "baseline"))
    payload = (MARKER + "\nconfidential research results - do not disclose\n").encode() * 2000  # ~110 KiB
    fid = owner.upload(name, payload, classification=classification)
    rec = {"file_id": fid, "owner_username": "alice", "name": name, "provisioned": True, "mode": mode,
           "size": len(payload), "grant_id": None}
    if mode != "baseline":
        try:
            rec["grant_id"] = owner.share(fid, "bob", rights=("view", "download"), expires_in_days=7,
                                          max_downloads=100000, posture="any")
        except Exception as e:  # noqa: BLE001 - attacks that need bob will surface this
            rec["share_error"] = f"{type(e).__name__}: {e}"
    _TARGET_CACHE[mode] = rec
    return rec


# --------------------------------------------------------------------------- #
# Result record                                                               #
# --------------------------------------------------------------------------- #
@dataclass
class Result:
    attack: str
    mode: str
    expected: str = ""            # "SUCCEEDS" (baseline) or "BLOCKED" (ztv)
    succeeded: bool = False       # did the attack actually breach?
    blocked_by: str = ""          # the control that stopped it (ztv rows)
    detail: str = ""
    evidence: dict = field(default_factory=dict)
    error: Optional[str] = None

    def __post_init__(self):
        if not self.expected:
            self.expected = "SUCCEEDS" if self.mode == "baseline" else "BLOCKED"

    @property
    def expected_success(self) -> bool:
        return self.mode == "baseline"

    @property
    def status(self) -> str:
        if self.error is not None:
            return "ERROR"
        return "SUCCEEDED" if self.succeeded else "BLOCKED"

    @property
    def as_expected(self) -> Optional[bool]:
        if self.error is not None:
            return None
        return self.succeeded == self.expected_success

    def as_dict(self) -> dict:
        return {"attack": self.attack, "mode": self.mode, "expected": self.expected,
                "succeeded": self.succeeded, "status": self.status, "as_expected": self.as_expected,
                "blocked_by": self.blocked_by, "detail": self.detail,
                "evidence": self.evidence, "error": self.error}


def succeeded(attack: str, mode: str, detail: str, **ev) -> Result:
    return Result(attack, mode, succeeded=True, detail=detail, evidence=ev)


def blocked(attack: str, mode: str, by: str, detail: str, **ev) -> Result:
    return Result(attack, mode, succeeded=False, blocked_by=by, detail=detail, evidence=ev)


def errored(attack: str, mode: str, exc: Exception) -> Result:
    return Result(attack, mode, succeeded=False, detail=f"{type(exc).__name__}: {exc}", error=str(exc))


def assert_expected(result: Result) -> bool:
    """Assert helper: True when the observed outcome matches the mode's expectation."""
    if result.as_expected is None:
        raise AssertionError(f"{result.attack}[{result.mode}] errored: {result.error}")
    if not result.as_expected:
        raise AssertionError(
            f"{result.attack}[{result.mode}] expected {result.expected} but "
            f"{'SUCCEEDED' if result.succeeded else 'was BLOCKED'}: {result.detail}")
    return True
