# Submission checklist

| Item | What to upload |
|---|---|
| **Phase 1 – Problem Identification** | The problem-identification document(s) you already submitted on Moodle (not part of this repository). |
| **Phase 2 – Demonstration Video** | `docs/demo/ZeroTrustVault-demo.mp4` — narrated walkthrough of the working system (login + MFA, enrolment and the offline CA, client-side encrypted upload, verified sharing, per-request authorization, dashboard, admin), the six-attack lab in baseline vs ZeroTrustVault mode, the evaluation metrics, the load test and benchmark, and the test suites. |
| **GitHub Repository Link** | https://github.com/lathiyavansh-cmd/zerotrustvault (private; evaluators must be added as collaborators, or switch the repository to public under Settings → General → Danger zone → Change visibility). |

## Regenerating the video

```bash
python docs/demo/build_video.py            # neural voice via edge-tts (internet), falls back to the offline Windows voice
python docs/demo/build_video.py --offline-tts
```

Captures live in `docs/demo/captures/` (real screenshots of the running UI plus the captured attack-lab table, evaluation rows and test output). Intermediate slides and audio are written to `docs/demo/build/`.
