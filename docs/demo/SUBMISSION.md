# Submission checklist

| Item | What to upload |
|---|---|
| **Phase 1 – Problem Identification** | The problem-identification document(s) you already submitted on Moodle (not part of this repository). |
| **Phase 2 – Demonstration Video** | `docs/demo/ZeroTrustVault-demo.mp4` — a screen recording of the running product with explanatory captions (no slides, no voice): login + MFA, enrolment and the offline CA, key unlock, client-side encrypted upload with the integrity verdict, verified sharing, grants, the live dashboard and audit chain, settings, and administration (certificate confirmation, user provisioning, policy, mode switch). Captions over the dashboard state the evaluation and test results. |
| **GitHub Repository Link** | https://github.com/lathiyavansh-cmd/zerotrustvault (public; no login needed to view, clone or download). |

## Regenerating the video

```bash
cd client && npm run dev -- --host 127.0.0.1 --port 5173      # dev server proxying to the live API (docker compose up first)
python docs/demo/record_site.py                                # drives Edge through the whole flow and records it (Playwright)
python docs/demo/compose_captions.py                           # burns the lower-third captions and encodes the MP4
```

`record_site.py` writes the raw recording and `captions.json` (caption text + timestamps) to `docs/demo/build/record/`.
