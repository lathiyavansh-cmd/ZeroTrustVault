"""Entry point: uvicorn with TLS and REQUIRED client certificates (mTLS from nginx / tools)."""
from __future__ import annotations

import ssl
from pathlib import Path

import uvicorn

from .config import settings


def main() -> None:
    tls = Path(settings.TLS_DIR)
    kwargs: dict = {}
    if (tls / "api.crt").exists():
        kwargs.update(ssl_certfile=str(tls / "api.crt"), ssl_keyfile=str(tls / "api.key"))
        if settings.REQUIRE_MTLS:
            kwargs.update(ssl_ca_certs=str(tls / "internal-ca.crt"), ssl_cert_reqs=ssl.CERT_REQUIRED)
    uvicorn.run("ztv_server.app:app", host="0.0.0.0", port=settings.LISTEN_PORT, proxy_headers=True, forwarded_allow_ips="*", log_level="info", **kwargs)


if __name__ == "__main__":
    main()
