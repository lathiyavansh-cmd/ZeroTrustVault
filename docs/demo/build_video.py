"""Build the narrated demonstration video from real captures, terminal outputs and slides.

    python docs/demo/build_video.py [--voice en-US-AriaNeural] [--out docs/demo/ZeroTrustVault-demo.mp4]

Narration: edge-tts (neural voice, needs internet) with an offline pyttsx3 (Windows SAPI) fallback.
Video: 1280x720, H.264 + AAC, one segment per slide, concatenated with the bundled ffmpeg.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import textwrap
import wave
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "docs" / "demo"
CAP = DEMO / "captures"
BUILD = DEMO / "build"
W, H = 1280, 720
BG = (11, 15, 25)
PANEL = (18, 24, 38)
FG = (232, 236, 245)
MUTED = (150, 160, 180)
ACCENT = (99, 128, 255)
GREEN = (46, 204, 113)
RED = (231, 76, 60)
AMBER = (241, 196, 15)

REPO_URL = "https://github.com/lathiyavansh-cmd/zerotrustvault"


def font(size: int, mono: bool = False, bold: bool = False):
    cands = ["C:/Windows/Fonts/consola.ttf"] if mono else (["C:/Windows/Fonts/segoeuib.ttf"] if bold else ["C:/Windows/Fonts/segoeui.ttf"])
    cands += ["C:/Windows/Fonts/arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]
    for c in cands:
        if Path(c).exists():
            return ImageFont.truetype(c, size)
    return ImageFont.load_default()


def brand(d: ImageDraw.ImageDraw):
    d.rounded_rectangle((40, 28, 76, 64), radius=10, fill=ACCENT)
    d.text((88, 30), "ZeroTrustVault", font=font(26, bold=True), fill=FG)
    d.text((88, 58), "ACME RESEARCH LABS · zero-trust secure file sharing", font=font(13), fill=MUTED)


def footer(d: ImageDraw.ImageDraw, idx: int, total: int):
    d.text((40, H - 34), REPO_URL, font=font(14), fill=MUTED)
    d.text((W - 110, H - 34), f"{idx}/{total}", font=font(14), fill=MUTED)


def slide_text(title: str, bullets: list[str], subtitle: str | None = None, color=ACCENT) -> Image.Image:
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    brand(d)
    d.text((40, 110), title, font=font(44, bold=True), fill=FG)
    y = 170
    if subtitle:
        d.text((40, y), subtitle, font=font(20), fill=color)
        y += 44
    f = font(24)
    for b in bullets:
        for i, line in enumerate(textwrap.wrap(b, 78)):
            d.text((60 if i == 0 else 92, y), ("•  " if i == 0 else "") + line, font=f, fill=FG)
            y += 36
        y += 10
    return im


def slide_image(title: str, image_path: Path, caption: str = "", fit=(1180, 560)) -> Image.Image:
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.text((40, 24), title, font=font(30, bold=True), fill=FG)
    if caption:
        d.text((40, 64), caption, font=font(17), fill=MUTED)
    if image_path.exists():
        shot = Image.open(image_path).convert("RGB")
        shot.thumbnail(fit, Image.LANCZOS)
        if shot.width < fit[0] * 0.8:  # upscale small captures so they fill the frame
            scale = min(fit[0] / shot.width, fit[1] / shot.height)
            shot = shot.resize((int(shot.width * scale), int(shot.height * scale)), Image.LANCZOS)
        x = (W - shot.width) // 2
        y = 100 + (fit[1] - shot.height) // 2
        d.rounded_rectangle((x - 6, y - 6, x + shot.width + 6, y + shot.height + 6), radius=10, fill=PANEL, outline=(40, 50, 70))
        im.paste(shot, (x, y))
    else:
        d.text((40, 300), f"(capture missing: {image_path.name})", font=font(22), fill=RED)
    return im


def slide_mono(title: str, text: str, caption: str = "", size: int = 17) -> Image.Image:
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.text((40, 24), title, font=font(30, bold=True), fill=FG)
    if caption:
        d.text((40, 64), caption, font=font(17), fill=MUTED)
    d.rounded_rectangle((40, 100, W - 40, H - 50), radius=12, fill=(8, 10, 16), outline=(40, 50, 70))
    f = font(size, mono=True)
    y = 112
    for line in text.rstrip().splitlines()[:30]:
        col = FG
        if "PASS" in line and "FAIL" not in line:
            col = GREEN
        elif "FAIL" in line or "ERROR" in line:
            col = RED
        elif line.strip().startswith("|") or line.strip().startswith("┃") or line.strip().startswith("│"):
            col = FG
        d.text((56, y), line[:118], font=f, fill=col)
        y += size + 5
    return im


def slide_table(title: str, rows: list[tuple[str, str, str]], caption: str = "") -> Image.Image:
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.text((40, 24), title, font=font(30, bold=True), fill=FG)
    if caption:
        d.text((40, 64), caption, font=font(17), fill=MUTED)
    y = 120
    hdr = font(18, bold=True)
    d.text((60, y), "METRIC", font=hdr, fill=MUTED); d.text((560, y), "RESULT", font=hdr, fill=MUTED); d.text((980, y), "TARGET", font=hdr, fill=MUTED)
    y += 40
    f = font(21)
    for name, val, tgt in rows:
        d.line((60, y + 36, W - 60, y + 36), fill=(40, 50, 70))
        d.text((60, y), name, font=f, fill=FG)
        d.text((560, y), val, font=f, fill=GREEN)
        d.text((980, y), tgt, font=f, fill=MUTED)
        y += 48
    return im


def slide_attacks(title: str, caption: str) -> Image.Image:
    """Clean table of the six attacks from eval/results/attack_results.json."""
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.text((40, 24), title, font=font(30, bold=True), fill=FG)
    d.text((40, 64), caption, font=font(17), fill=MUTED)
    rows = []
    src = ROOT / "eval" / "results" / "attack_results.json"
    if src.exists():
        data = json.loads(src.read_text())
        data = data if isinstance(data, list) else data.get("results", data.get("rows", []))
        for r in data:
            rows.append((r.get("title") or r["attack"], r.get("baseline", ""), r.get("zerotrustvault", ""), r.get("blocked_by", ""), bool(r.get("pass"))))
    cols = (60, 400, 560, 740, 1170)
    hdr = font(17, bold=True)
    y = 112
    for x, t in zip(cols, ("ATTACK", "BASELINE", "ZEROTRUSTVAULT", "BLOCKED BY", "PASS")):
        d.text((x, y), t, font=hdr, fill=MUTED)
    y += 38
    f = font(20); fs = font(16)
    for name, b, z, by, ok in rows:
        d.line((60, y + 78, W - 60, y + 78), fill=(40, 50, 70))
        d.text((cols[0], y), name[:34], font=f, fill=FG)
        d.text((cols[1], y), b, font=f, fill=RED if b == "SUCCEEDED" else FG)
        d.text((cols[2], y), z, font=f, fill=GREEN if z == "BLOCKED" else RED)
        for i, line in enumerate(textwrap.wrap(by, 44)[:3]):
            d.text((cols[3], y + i * 22), line, font=fs, fill=FG)
        d.text((cols[4], y), "PASS" if ok else "FAIL", font=font(20, bold=True), fill=GREEN if ok else RED)
        y += 86
    d.text((60, y + 6), f"{sum(1 for r in rows if r[4])}/{len(rows)} attacks PASS: baseline SUCCEEDS, ZeroTrustVault BLOCKS", font=font(20, bold=True), fill=GREEN)
    return im


def build_slides() -> list[tuple[Image.Image, str]]:
    """Return (image, narration) pairs."""
    ev = json.loads((CAP / "eval_rows.json").read_text()) if (CAP / "eval_rows.json").exists() else []
    pytest_txt = (CAP / "pytest.txt").read_text() if (CAP / "pytest.txt").exists() else ""
    vitest_txt = (CAP / "vitest.txt").read_text() if (CAP / "vitest.txt").exists() else ""

    S: list[tuple[Image.Image, str]] = []

    S.append((slide_text("ZeroTrustVault", [
        "A secure file-sharing and access-control system for the Applied Cryptography & Network Security design challenge",
        "Two independent planes that fail separately: a zero-trust control plane and a data-centric cryptographic plane",
        "Everything shown here is running locally from one docker compose up, and every claim is demonstrated as baseline fails, ZeroTrustVault blocks",
    ], subtitle="Demonstration: working system, attack lab, evaluation and testing"),
        "Welcome to the demonstration of ZeroTrustVault, a secure file-sharing and access-control system built for the Applied Cryptography and Network Security design challenge. "
        "The system is built on two independent planes that fail separately. A zero-trust control plane authenticates and authorizes every single request. "
        "And a data-centric cryptographic plane encrypts and signs every file on the client before it leaves the device. "
        "In this video I will show the working system, the six attack simulations run in both a conventional baseline mode and ZeroTrustVault mode, the evaluation metrics, and the test suites."))

    S.append((slide_text("The problem", [
        "Conventional file sharing trusts the network perimeter and the server: a stolen password, a replayed request or a compromised database exposes plaintext",
        "Access decisions are made once at login and never re-checked; stored files can be altered without anyone noticing",
        "Goal: never trust the network, verify every request explicitly, least privilege with time-boxed default-deny grants, assume breach, and log everything tamper-evidently",
    ]),
        "The problem we address is that conventional file sharing trusts the network perimeter and the server itself. A stolen password, a replayed request, or a compromised database exposes plaintext. "
        "Access decisions are typically made once at login and never re-checked, and stored files can be altered silently. "
        "ZeroTrustVault enforces five principles throughout: never trust the network, verify every request explicitly, least privilege with time-boxed default-deny grants, assume breach so the server is never trusted for confidentiality, and log everything in a tamper-evident chain."))

    S.append((slide_text("Architecture", [
        "Client zone (React + TypeScript, Web Crypto): the only place plaintext and private keys ever exist; non-extractable device key; streaming decryption in Web Workers",
        "Control plane (NIST SP 800-207): Nginx with TLS 1.3 only, HSTS and certificate pinning; FastAPI gateway as the policy enforcement point; hybrid RBAC + ABAC policy decision point with default deny",
        "Data plane: PostgreSQL 16 for signed manifests, policies, wrapped keys and the audit log; MinIO for ciphertext chunks only; Redis for the DPoP nonce cache and sessions",
        "Offline: the Ed25519 organisation root key, loaded only by a separate signer, never by the API",
    ]),
        "Here is the architecture. The client zone is a React and TypeScript application using the Web Crypto API with non-extractable keys. It is the only place where plaintext and private keys ever exist. "
        "The control plane follows NIST Special Publication 800-207: Nginx terminates TLS 1.3 only, with HSTS and certificate pinning, and talks to the FastAPI gateway over mutual TLS. The gateway is the policy enforcement point, and a hybrid role-based and attribute-based policy decision point evaluates every request with default deny. "
        "The data plane holds only ciphertext, wrapped keys and signed manifests: PostgreSQL, MinIO and Redis. "
        "The organisation root key is Ed25519 and stays offline: it is loaded only by a separate signer process, never by the running API."))

    S.append((slide_text("Cryptographic design", [
        "Level 0: offline Ed25519 organisation root, 2-year cryptoperiod, certifies every user public key after out-of-band fingerprint confirmation",
        "Level 1: per-user X25519 encryption and Ed25519 signing keys, generated in the browser and sealed under KEK = Argon2id(passphrase) with 64 MiB, t=3; only the sealed blob is uploaded",
        "Level 2: a fresh 256-bit AES data key per file version, wrapped per recipient via X25519 ECDH, HKDF-SHA256 and AES-KW",
        "Level 3: 4 MiB chunks under AES-256-GCM with associated data binding file id, version, chunk index and final flag; SHA-256 Merkle root inside an Ed25519-signed manifest",
        "Only NIST and IETF primitives from OpenSSL and Web Crypto. No home-made cryptography. DPoP proof-of-possession on every request.",
    ]),
        "The cryptographic design has four levels. At level zero, the offline organisation root certifies every user's public keys, but only after an administrator confirms the key fingerprint out of band. "
        "At level one, each user has an X25519 encryption key pair and an Ed25519 signing key pair, generated in the browser and sealed under a key-encryption key derived with Argon2id using 64 mebibytes of memory. Only the sealed blob is ever uploaded, so the server never holds a usable private key. "
        "At level two, every file version gets a fresh 256-bit AES data key, wrapped once per recipient using X25519 Diffie-Hellman, HKDF with SHA-256, and AES key wrap. "
        "At level three, files are split into 4 mebibyte chunks, each encrypted with AES-256-GCM. The associated data binds the file id, version, chunk index and a final-chunk flag, so reordering and truncation are detected. A SHA-256 Merkle tree over the ciphertext chunks is signed inside the manifest with the owner's Ed25519 key. "
        "Everything is built only from NIST and IETF standard primitives, and every request carries a DPoP proof of possession signed by the device key."))

    S.append((slide_image("Workflow A: authentication", CAP / "01-login.jpg",
                          "Argon2id password, then a second factor; the device's non-extractable ECDSA P-256 key is bound into every token"),
        "Let us walk through the working system. Logging in starts with a username and an Argon2id-hashed password. The browser also presents the public half of its non-extractable device key, whose thumbprint will be bound into every access token."))

    S.append((slide_image("Workflow A: multi-factor step", CAP / "02-mfa.jpg",
                          "TOTP or a WebAuthn passkey; the server issues a 5-minute DPoP-bound access token"),
        "Password alone is never enough. The second step accepts a time-based one-time code or a WebAuthn passkey. On success the server issues a five-minute access token bound to this device, plus a device-bound refresh token. "
        "In the conventional baseline mode, which the attack lab uses for comparison, login is password-only with a thirty-day bearer token."))

    S.append((slide_image("Enrolment and the offline certificate authority", CAP / "03-enrol-cert.jpg",
                          "Keys generated client-side, sealed and uploaded; the fingerprint is confirmed out-of-band before the offline root signs the certificate"),
        "The enrolment page shows the complete key lifecycle. On the first login from a device the browser generates the X25519 and Ed25519 key pairs, seals the private halves under the Argon2id passphrase, and uploads only the sealed blob. "
        "The public keys go to the organisation certificate authority as a request. The fingerprint is shown as eight groups of four hexadecimal characters, and an administrator must confirm it over a separate channel before the offline signer issues the certificate. "
        "Here the certificate has been issued and the client has verified it against the pinned organisation root."))

    S.append((slide_image("Keys unlocked for the session", CAP / "04-keys-unlocked.jpg",
                          "The posture strip: mode, device key, keys unlocked with Web Crypto, certificate, pinned root, risk and token countdown"),
        "After the passphrase is entered, the key-encryption key is derived locally and the private keys are imported as non-extractable Web Crypto keys for this session only. "
        "The posture strip at the top of every page shows the security state at a glance: the mode, the device key, whether keys are unlocked, the certificate serial, the pinned organisation root, the session risk level, and a countdown on the five-minute token."))

    S.append((slide_image("Workflow B and D: upload, access and integrity", CAP / "05-files-locked.jpg",
                          "Files are encrypted in the browser before upload; every download verifies the signed Merkle root chunk by chunk in a Web Worker"),
        "On the Files page, uploads are encrypted in the browser before any byte leaves it: a fresh data key, 4 mebibyte chunks under AES-256-GCM, the Merkle tree and the signed manifest, with a separate DPoP proof on every chunk upload. "
        "Downloads run in a Web Worker which verifies the manifest signature against the owner's certificate, checks the Merkle root, and decrypts chunk by chunk. Any authentication-tag failure aborts immediately and the client reports an integrity alert to the server. "
        "In the live run the verdict panel reported integrity OK, signature OK, Merkle OK, two of two chunks for a six-mebibyte file."))

    S.append((slide_image("Workflow C: sharing with a verified recipient", CAP / "07-share-cert-verified.jpg",
                          "The recipient's certificate is verified against the pinned org root before the data key is wrapped for them"),
        "Sharing is where a malicious server could try to substitute its own key. To defeat that, the owner's client fetches the recipient's certificate and verifies it against the organisation root pinned at build time. "
        "Only then does it wrap the file's data key for the recipient's X25519 key, and it signs a share grant carrying the rights, an expiry, a maximum download count and a required device posture. Here Bob's certificate verifies, and his fingerprint is displayed."))

    S.append((slide_image("A signed, time-boxed grant", CAP / "08-share-grant-listed.jpg",
                          "Grants carry rights, expiry, download limit and posture; revocation is instant and hard re-key creates a new version"),
        "The grant is now active: view and download rights, expiring in seven days, limited to three downloads, requiring a registered device. "
        "At access time both the organisation policy and this owner grant must permit. Revoking the grant deletes the wrapped key and kills any outstanding ciphertext URL, so the very next request is denied. For a hard revocation the owner rotates the file to a new version under a new data key."))

    S.append((slide_image("Per-request authorization", CAP / "09-dashboard.jpg",
                          "Every decision is evaluated and logged: TLS, token, DPoP, timestamp window, nonce, attributes, PDP, risk and step-up"),
        "Every request is re-verified. The gateway checks the TLS channel, the token signature and five-minute expiry, that the session is still alive, the DPoP proof signature, that the method and URL match, that the timestamp is within sixty seconds, that the nonce has never been seen in Redis, and that the proof key matches the token. "
        "Then it collects subject, device, resource, environment and grant attributes and asks the policy decision point. Elevated risk triggers a step-up second factor; a very high score is denied outright. "
        "The dashboard shows permits, denials and alerts live, and the audit chain status: here it reads intact, with the head hash and the last signed checkpoint."))

    S.append((slide_image("Share and grant management", CAP / "10-grants.jpg", "Owned files with grant counts, files shared with you, and revocation"),
        "The Share and Grants page lists the files you own with their active grants, the files shared with you through someone else's grant, and lets the owner revoke access instantly."))

    S.append((slide_image("Devices and session", CAP / "11-settings.jpg", "Each device holds a non-extractable P-256 key; device loss revokes its sessions"),
        "Settings shows every registered device with its key thumbprint and posture. Revoking a device, for example after it is lost, invalidates its sessions, because every request checks the session in Redis."))

    S.append((slide_image("Administration", CAP / "12-admin.jpg",
                          "Out-of-band fingerprint confirmation, user provisioning with a one-time TOTP secret, the policy editor and the mode switch"),
        "The administrator page handles the out-of-band fingerprint confirmation, creates users with a one-time TOTP provisioning secret, edits the policy JSON with validation, and switches the running mode between baseline and ZeroTrustVault for the attack lab."))

    S.append((slide_image("Policy editor and users", CAP / "13-admin-policy.jpg",
                          "Deny-overrides, then first PERMIT, else default DENY; rules are validated JSON with a clean seam for Open Policy Agent"),
        "The policy itself is a validated JSON document: deny rules for ended employment, high risk, revoked certificates and untrusted devices on secret files, then permit rules for owners and for valid grants with sufficient clearance. The decision point has a clean seam so Open Policy Agent can be dropped in later."))

    S.append((slide_image("One flag switches the whole posture", CAP / "14-mode-switch.jpg",
                          "MODE=baseline disables MFA, DPoP binding, the PDP, signed manifests and the audit hash chain, only for the attack lab"),
        "The runtime mode switch is what makes the before-and-after demonstration possible. Baseline mode disables multi-factor authentication, DPoP binding, the policy decision point, signed manifests and the audit hash chain, reproducing a conventional design. It is only ever used by the attack lab."))

    S.append((slide_text("Tamper-evident audit log", [
        "Each entry chained: h_i = SHA-256(h_{i-1} || entry_i), recording who, what, when, decision and reason, never file content",
        "Every 100 entries or 5 minutes a checkpoint (i, h_i) is signed with the audit Ed25519 key and exported to a separate write-once store",
        "ztv-audit-verify recomputes the chain and pinpoints the exact modified, deleted or truncated entry",
        "Rows written in baseline mode carry no hash and are reported as unchained, exactly the weakness the attack lab exploits",
    ]),
        "Underneath the dashboard is the tamper-evident audit log. Each entry is chained by hashing the previous hash together with the entry, and every one hundred entries or five minutes a signed checkpoint is exported to a separate write-once store. "
        "A verification tool recomputes the whole chain and pinpoints the exact entry that was modified, deleted or truncated."))

    S.append((slide_attacks("Attack-simulation lab: baseline versus ZeroTrustVault",
                            "make attack-demo runs all six attacks in both modes with one config flag and asserts the outcome"),
        "Now the attack lab, which is the heart of the demonstration. A single MODE flag switches the whole system between a conventional baseline and ZeroTrustVault, and each attack is a scripted, repeatable scenario run twice. "
        "Attack one is unauthorized file access by changing a file id: in baseline Carol from finance reads Alice's confidential research file; in ZeroTrustVault she gets a generic 403, and even a leaked storage URL yields only ciphertext. "
        "Attack two uses stolen credentials on a new device: baseline logs straight in; ZeroTrustVault blocks at the second factor, and a stolen token replayed from another machine fails the DPoP key binding. "
        "Attack three is a man in the middle with a rogue certificate authority: baseline traffic is read and altered; ZeroTrustVault refuses the rogue certificate through pinning, and any change fails the authentication tag or signature. "
        "Attack four tampers with stored files: byte flips, chunk swaps and truncation in MinIO are served and trusted in baseline, but refused by the client and logged as alerts in ZeroTrustVault. "
        "Attack five replays a captured request: it succeeds in baseline and returns 401 replayed nonce in ZeroTrustVault. "
        "Attack six is an insider dumping the database and the bucket: baseline reveals plaintext and the log can be edited silently; in ZeroTrustVault the dump is all ciphertext and wrapped keys, and the edited log row is flagged at its exact sequence number. "
        "All six rows pass: baseline succeeded, ZeroTrustVault blocked."))

    S.append((slide_table("Evaluation harness: make eval", [tuple(r) for r in ev] if ev else [("(eval rows not captured)", "", "")],
                          "Measured against the live stack on a clean bring-up"),
        "The evaluation harness measures every target from the challenge. Attack success rate falls from one hundred percent in baseline to zero in ZeroTrustVault. "
        "One thousand randomized bit flips, chunk swaps and truncations were one hundred percent detected. One thousand replayed requests were all rejected with zero false rejections of legitimate requests. "
        "The policy decision itself takes a few hundredths of a millisecond; the full authorization pipeline including attribute collection and the chained audit write is around four milliseconds, and end-to-end access is about eleven milliseconds. "
        "Soft revocation is effective on the very next request, and five hundred random audit edits and deletions were all detected at their exact position."))

    S.append((slide_image("Load test and primitive benchmark", ROOT / "eval" / "results" / "bench_ec_vs_rsa.png",
                          "Locust: 100 concurrent users, 16,468 measurements, 0 failures, PDP decision sub-millisecond; X25519/Ed25519 versus RSA-3072", fit=(900, 540)),
        "Under Locust with one hundred concurrent users driving the full DPoP round trip through the Nginx edge, sixteen thousand measurements completed with zero failures, and the policy decision stayed sub-millisecond. "
        "The primitive benchmark compares the elliptic-curve primitives with the RSA-3072 baseline: key generation is thousands of times faster, signing about thirty times faster, and only RSA verification is comparable. "
        "Client-side protection costs between one and five percent of the upload time on a 100 megabit link across file sizes from one to one hundred twenty-eight megabytes, meeting the five percent target."))

    S.append((slide_mono("Testing", pytest_txt + "\n" + vitest_txt,
                         "pytest: crypto core + server PDP, tokens, DPoP, replay, lockout; vitest: cross-implementation vectors proving TypeScript and Python produce identical bytes", size=17),
        "For testing, the crypto core and the server are covered by pytest, including the policy engine's default-deny, grant, clearance, expiry and step-up cases, token and DPoP verification with replay, and lockout. "
        "A live end-to-end test runs the complete flow against the Docker stack. On the client, vitest runs eighteen cross-implementation vectors generated by the Python core, proving that the TypeScript Web Crypto engine produces byte-identical canonical JSON, associated data, ciphertext, Merkle roots, signatures and certificates. "
        "Static analysis with Bandit and Semgrep and all of these suites run in GitHub Actions on every push."))

    S.append((slide_text("Standards, compliance and limitations", [
        "Mapped to the CISA Zero Trust Maturity Model pillars, DPDP Rules 2025 (encryption, access control, access logs retained a year) and CERT-In 2022 (tamper-evident logs, six-hour reporting evidence); NIST SP 800-57 cryptoperiods",
        "Out of scope by design: malware on an unlocked authorized device, physical attacks, volumetric DDoS, browser side channels, screen photography",
        "Known limitations with mitigations: forgotten passphrase (Shamir escrow of the key blob), metadata visibility (minimisation and size padding), revoked users keeping decrypted copies (watermarked view-only mode), clock skew (60-second window plus server time)",
    ]),
        "The documentation maps every feature to the CISA Zero Trust Maturity Model pillars, to the DPDP Rules 2025 and to the CERT-In 2022 directions, and follows NIST cryptoperiods. "
        "We are explicit about what is out of scope, such as malware on an already-unlocked device, and we document the known limitations with their mitigations."))

    S.append((slide_text("Summary", [
        "Ten modules, six workflows, six attacks, all running from one docker compose up",
        "Baseline fails, ZeroTrustVault blocks: 6 of 6 attacks, 100% tamper and replay detection, sub-millisecond policy decisions, instant revocation, exact audit localisation",
        f"Repository: {REPO_URL}",
        "README covers bring-up, switching MODE, make attack-demo, make eval, make bench and the dashboard",
    ], subtitle="Thank you"),
        "In summary: ten modules, six workflows and six attack simulations, all running locally from a single docker compose command. Every security claim is demonstrated as baseline fails, ZeroTrustVault blocks. "
        "The repository link is shown on screen and in the submission, and the README explains how to bring the stack up, switch modes, and run the attack demo, the evaluation harness and the benchmarks. Thank you."))
    return S


async def tts_edge(text: str, out_mp3: Path, voice: str) -> None:
    import edge_tts

    await edge_tts.Communicate(text, voice, rate="-4%").save(str(out_mp3))


def tts_pyttsx3(text: str, out_wav: Path) -> None:
    import pyttsx3

    e = pyttsx3.init()
    e.setProperty("rate", 170)
    e.save_to_file(text, str(out_wav))
    e.runAndWait()


def to_wav(ffmpeg: str, src: Path, dst: Path) -> None:
    subprocess.run([ffmpeg, "-y", "-loglevel", "error", "-i", str(src), "-ar", "44100", "-ac", "2", str(dst)], check=True)


def wav_seconds(p: Path) -> float:
    with wave.open(str(p)) as w:
        return w.getnframes() / float(w.getframerate())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DEMO / "ZeroTrustVault-demo.mp4"))
    ap.add_argument("--voice", default="en-US-AriaNeural")
    ap.add_argument("--offline-tts", action="store_true")
    a = ap.parse_args(argv)
    import imageio_ffmpeg

    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    BUILD.mkdir(parents=True, exist_ok=True)
    slides = build_slides()
    total = len(slides)
    segs: list[Path] = []
    for i, (im, narration) in enumerate(slides, 1):
        d = ImageDraw.Draw(im)
        footer(d, i, total)
        png = BUILD / f"slide{i:02d}.png"
        im.save(png)
        wav = BUILD / f"narr{i:02d}.wav"
        if not wav.exists():
            ok = False
            if not a.offline_tts:
                try:
                    mp3 = BUILD / f"narr{i:02d}.mp3"
                    asyncio.run(tts_edge(narration, mp3, a.voice))
                    to_wav(ffmpeg, mp3, wav)
                    ok = True
                except Exception as e:  # noqa: BLE001
                    print(f"  edge-tts failed on slide {i} ({e}); using offline voice")
            if not ok:
                raw = BUILD / f"narr{i:02d}.raw.wav"
                tts_pyttsx3(narration, raw)
                to_wav(ffmpeg, raw, wav)
        dur = wav_seconds(wav) + 1.2
        seg = BUILD / f"seg{i:02d}.mp4"
        subprocess.run([ffmpeg, "-y", "-loglevel", "error", "-loop", "1", "-framerate", "24", "-i", str(png), "-i", str(wav),
                        "-filter_complex", "[1:a]apad[a]", "-map", "0:v", "-map", "[a]", "-t", f"{dur:.2f}",
                        "-c:v", "libx264", "-tune", "stillimage", "-preset", "medium", "-crf", "20", "-pix_fmt", "yuv420p",
                        "-c:a", "aac", "-b:a", "160k", "-shortest", str(seg)], check=True)
        segs.append(seg)
        print(f"  slide {i:02d}/{total}  {dur:5.1f}s")
    lst = BUILD / "concat.txt"
    lst.write_text("".join(f"file '{s.as_posix()}'\n" for s in segs))
    out = Path(a.out)
    subprocess.run([ffmpeg, "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(lst), "-c", "copy", "-movflags", "+faststart", str(out)], check=True)
    total_s = sum(wav_seconds(BUILD / f"narr{i:02d}.wav") + 1.2 for i in range(1, total + 1))
    print(f"\nwrote {out}  ({total_s/60:.1f} min, {out.stat().st_size/1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
