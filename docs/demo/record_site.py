"""Record a real walkthrough of the running ZeroTrustVault site (no slides, no voice).

Drives the client at http://127.0.0.1:5173 (Vite dev server proxying to the live API) in Microsoft Edge
through Playwright with video recording, performing the complete flow as a user would, and writes
`captions.json` with the timestamp of each explanatory caption for `compose_captions.py` to burn in.

    python docs/demo/record_site.py --base http://127.0.0.1:5173 --out docs/demo/build/record
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import pyotp
from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
CREDS = json.loads((ROOT / "seed" / "generated" / "credentials.json").read_text())
DEMO_FILE = ROOT / "docs" / "demo" / "build" / "q3-results-demo.txt"


class Recorder:
    def __init__(self, page: Page):
        self.page = page
        self.t0 = time.perf_counter()
        self.caps: list[dict] = []

    def cap(self, text: str, hold: float = 0.0) -> None:
        self.caps.append({"t": round(time.perf_counter() - self.t0, 2), "text": text})
        self.page.wait_for_timeout(int(max(hold, 2.0) * 1000))

    def pause(self, s: float) -> None:
        self.page.wait_for_timeout(int(s * 1000))

    def type_in(self, label: str, text: str, delay: int = 70) -> None:
        box = self.page.get_by_label(label)
        box.click()
        box.type(text, delay=delay)

    def totp(self, user: str) -> None:
        secret = CREDS[user]["totp_secret"]
        remaining = 30 - int(time.time()) % 30
        if remaining < 8:
            self.pause(remaining + 0.5)
        code = pyotp.TOTP(secret).now()
        self.page.get_by_label("digit 1").click()
        self.page.keyboard.type(code, delay=140)

    def nav(self, name: str) -> None:
        self.page.get_by_role("link", name=name, exact=True).click()
        self.pause(1.2)

    def scroll(self, px: int, steps: int = 6) -> None:
        for _ in range(steps):
            self.page.mouse.wheel(0, px / steps)
            self.pause(0.12)


def run(base: str, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        ctx = browser.new_context(viewport={"width": 1280, "height": 720}, color_scheme="dark",
                                  record_video_dir=str(out_dir), record_video_size={"width": 1280, "height": 720})
        page = ctx.new_page()
        R = Recorder(page)
        page.goto(f"{base}/login")
        page.wait_for_load_state("networkidle")
        R.cap("ZeroTrustVault — a zero-trust secure file-sharing system. Every file is encrypted on the client; every request is re-verified.", 5.5)

        # ---- login ----
        R.cap("Sign in: Argon2id-hashed password plus a second factor. The browser presents its non-extractable ECDSA P-256 device key.")
        R.type_in("Username", "alice")
        R.type_in("Password", CREDS["alice"]["password"])
        R.pause(0.8)
        page.get_by_role("button", name="Continue").click()
        page.get_by_label("digit 1").wait_for()
        R.cap("Second factor: a TOTP code (or a WebAuthn passkey). The server then issues a 5-minute access token bound to this device via DPoP.", 5.5)
        R.totp("alice")
        page.wait_for_url("**/enrol", timeout=20000)
        R.pause(1.5)

        # ---- enrol / keys ----
        R.cap("Enrolment: X25519 + Ed25519 keys were generated in this browser and sealed under an Argon2id passphrase. Only the sealed blob is stored server-side.", 5.5)
        R.cap("The certificate was issued by the OFFLINE organisation CA after an administrator confirmed this key fingerprint out-of-band, and is verified against the pinned root.", 5.5)
        R.scroll(380)
        R.pause(1.0)
        R.cap("Unlocking derives the key-encryption key locally (Argon2id, 64 MiB) and imports the private keys as non-extractable Web Crypto keys for this session only.")
        R.type_in("Key passphrase", CREDS["alice"].get("key_passphrase", CREDS["alice"]["password"]))
        page.get_by_role("button", name="Unlock keys").click()
        page.get_by_text("Keys unlocked for this session").first.wait_for(timeout=30000)
        R.pause(1.5)
        R.scroll(-600)
        R.cap("The posture strip shows the live security state: mode, device key, keys unlocked, certificate, pinned org root, session risk and the token countdown.", 5.5)

        # ---- files: upload ----
        R.nav("Files")
        R.cap("Files: uploads are encrypted in the browser before any byte leaves it — fresh AES-256 key, 4 MiB GCM chunks, SHA-256 Merkle tree, Ed25519-signed manifest.", 5.5)
        page.locator("#cls").select_option("CONFIDENTIAL")
        R.pause(0.8)
        R.cap("Uploading a 3.4 MB confidential report: each chunk is sent with its own DPoP proof; the manifest signature and Merkle root are shown on finalize.")
        page.locator("input[type=file]").first.set_input_files(str(DEMO_FILE))
        page.get_by_text("finalized", exact=False).first.wait_for(timeout=90000)
        R.pause(2.5)
        R.cap("Finalized: the server verified the manifest signature against Alice's certificate and stored only ciphertext chunks, wrapped keys and the signed manifest.", 5.5)

        # ---- files: view / integrity ----
        row = page.get_by_role("row").filter(has_text="q3-results-demo.txt").first
        row.scroll_into_view_if_needed()
        R.pause(0.8)
        R.cap("Viewing the file: a Web Worker fetches 60-second ciphertext URLs, verifies the signed Merkle root and decrypts chunk by chunk. Any tag failure aborts.")
        row.get_by_role("button", name="View").click()
        page.get_by_text("INTEGRITY OK").first.wait_for(timeout=60000)
        R.pause(2.5)
        R.cap("Integrity verdict: manifest signature OK, Merkle root OK, all chunks authenticated. The decrypted preview exists only in this tab.", 5.5)
        page.keyboard.press("Escape")
        R.pause(0.8)
        R.scroll(-800)
        R.pause(1.0)

        # ---- share ----
        row = page.get_by_role("row").filter(has_text="q3-results-demo.txt").first
        row.scroll_into_view_if_needed()
        R.cap("Sharing: the owner's client fetches the recipient's certificate and verifies it against the pinned org root — a malicious server cannot substitute its own key.")
        row.get_by_role("button", name="Share").click()
        page.get_by_placeholder("username…").type("bob", delay=120)
        R.pause(0.8)
        page.get_by_role("option").filter(has_text="bob").first.click()
        page.get_by_text("CERTIFICATE VERIFIED").first.wait_for(timeout=20000)
        R.pause(2.5)
        R.cap("Bob's certificate verifies. The file key is wrapped for his X25519 key (ECDH → HKDF-SHA256 → AES-KW) and the grant carries rights, expiry, download limit and device posture.", 5.5)
        page.get_by_role("button", name="Sign grant & share").click()
        page.get_by_text("shared with bob").first.wait_for(timeout=20000)
        R.pause(2.0)
        R.cap("The grant is signed with Alice's Ed25519 key. At access time both organisation policy and this grant must permit; revoking it denies the very next request.", 5.5)
        page.keyboard.press("Escape")
        R.pause(0.8)

        # ---- grants page ----
        R.nav("Share / Grants")
        R.cap("Share / Grants: files you own with their active grants, files shared with you, and instant revocation. Hard re-key creates a new version under a new key.", 5.5)
        R.scroll(300)
        R.pause(1.5)

        # ---- dashboard ----
        R.nav("Dashboard")
        R.cap("Dashboard: every decision is logged. Permits, denials, alerts and step-ups update live every 3 seconds.", 5.5)
        R.cap("Audit chain: SHA-256 hash-chained entries with Ed25519-signed checkpoints every 100 entries or 5 minutes. Status INTACT, with the head hash and last checkpoint.", 5.5)
        R.scroll(420)
        R.pause(1.0)
        R.cap("Recent decisions with their rule and reason. Denied requests receive only a generic error; the real reason lives in this tamper-evident log.", 5.5)
        R.cap("Evaluation (make eval): 6/6 attacks blocked; 100% tamper detection over 1,000 corruptions; 100% replay rejection, 0% false rejects; PDP decision p95 0.025 ms.", 5.5)
        R.cap("Load test: 100 concurrent users, 16,468 requests, 0 failures. Tests: 37 pytest (crypto, PDP, DPoP, live e2e) and 18 client cross-implementation vectors, all green.", 5.5)
        R.scroll(-600)
        R.pause(1.0)

        # ---- settings ----
        R.nav("Settings")
        R.cap("Settings: every registered device with its key thumbprint and posture. Revoking a device invalidates its sessions on the next request.", 5.5)
        R.scroll(300)
        R.pause(1.5)

        # ---- admin ----
        page.get_by_role("button", name="Sign out").click()
        page.get_by_label("Username").wait_for(timeout=20000)
        R.cap("Administration: signing in as the admin (same password + TOTP flow).")
        R.type_in("Username", "admin")
        R.type_in("Password", CREDS["admin"]["password"])
        page.get_by_role("button", name="Continue").click()
        page.get_by_label("digit 1").wait_for()
        R.totp("admin")
        page.wait_for_url("**/enrol", timeout=20000)
        R.pause(1.0)
        R.nav("Admin")
        R.cap("Admin: pending certificate requests are confirmed here by reading the fingerprint back over a trusted channel; the offline signer then issues the certificate.", 5.5)
        R.cap("User provisioning returns a one-time TOTP secret and QR for the new account; users carry role, department, clearance and an employment end date.", 5.5)
        R.scroll(520)
        R.pause(1.0)
        R.cap("Policy: hybrid RBAC + ABAC rules — deny-overrides, then first PERMIT, else default DENY. Validated JSON, with a clean seam for Open Policy Agent.", 5.5)
        R.scroll(-900)
        R.pause(1.0)
        page.get_by_role("button", name="Switch mode…").click()
        R.pause(0.8)
        R.cap("One flag switches the whole posture. Baseline mode (password-only, bearer tokens, server-side encryption, plain logs) exists only for the attack lab: baseline fails, ZeroTrustVault blocks.", 5.5)
        page.keyboard.press("Escape")
        R.pause(0.8)
        page.get_by_role("button", name="Sign out").click()
        page.get_by_label("Username").wait_for(timeout=20000)
        R.cap("ZeroTrustVault — github.com/lathiyavansh-cmd/zerotrustvault", 5.5)

        duration = round(time.perf_counter() - R.t0, 2)
        ctx.close()
        browser.close()
    video = next(out_dir.glob("*.webm"))
    (out_dir / "captions.json").write_text(json.dumps({"video": str(video), "duration": duration, "captions": R.caps}, indent=2))
    print(f"recorded {video} ({duration:.1f}s, {len(R.caps)} captions)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:5173")
    ap.add_argument("--out", default=str(ROOT / "docs" / "demo" / "build" / "record"))
    a = ap.parse_args()
    out = Path(a.out)
    for old in out.glob("*.webm"):
        old.unlink()
    run(a.base, out)
