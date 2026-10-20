# ZeroTrustVault — one-command targets (GNU make; on Windows use Git Bash or run the commands by hand)
PY ?= python
COMPOSE ?= docker compose

.PHONY: up down logs certs seed test test-crypto test-server attack-demo attack-demo-baseline attack-demo-ztv eval bench lint ca-approve audit-verify mode-baseline mode-ztv

up:            ## build + start the whole stack (MODE from .env, default zerotrustvault) and seed it
	$(COMPOSE) up -d --build
	$(COMPOSE) run --rm seed
	@echo "UI: https://localhost:8443   API docs: https://localhost:8443/api/docs   MinIO console: http://localhost:9001"

down:
	$(COMPOSE) down -v

logs:
	$(COMPOSE) logs -f api web ca-signer

certs:         ## regenerate dev TLS certs + server keys + OFFLINE org root into infra/
	$(PY) -m ztv_server.tools.gen_certs --out infra/certs --keys infra/keys/server --org-root infra/keys/org_root.json

seed:
	$(COMPOSE) run --rm seed

test-crypto:
	$(PY) -m pytest crypto/tests -q

test-server:
	$(PY) -m pytest server/tests -q

test: test-crypto test-server

mode-baseline: ## switch the running API to conventional baseline mode (demo runtime switch)
	curl -sk -X POST https://localhost:8443/api/admin/mode -H "X-Admin-Key: ztv-dev-admin-key-change-me" -H "Content-Type: application/json" -d '{"mode":"baseline"}'

mode-ztv:
	curl -sk -X POST https://localhost:8443/api/admin/mode -H "X-Admin-Key: ztv-dev-admin-key-change-me" -H "Content-Type: application/json" -d '{"mode":"zerotrustvault"}'

attack-demo:   ## run all six attacks in BOTH modes inside the attack-lab container and print the results table
	$(COMPOSE) --profile attack run --rm attack-lab python runner.py --both-modes

attack-demo-baseline:
	$(COMPOSE) --profile attack run --rm attack-lab python runner.py --mode baseline

attack-demo-ztv:
	$(COMPOSE) --profile attack run --rm attack-lab python runner.py --mode zerotrustvault

eval:          ## evaluation harness (metrics table + CSV/JSON in eval/results)
	MSYS_NO_PATHCONV=1 $(COMPOSE) --profile attack run --rm attack-lab python /eval/run_eval.py --all

bench:         ## primitive benchmark RSA-3072 vs X25519/Ed25519 + client protection vs upload time (CSV + charts)
	$(PY) eval/bench_primitives.py --out eval/results

ca-approve:    ## sign a pending cert request from the OFFLINE root: make ca-approve REQ=<id> FP="AAAA BBBB ..."
	ztv-ca approve --root infra/keys/org_root.json --server https://localhost:8443 --admin-key ztv-dev-admin-key-change-me --request-id $(REQ) --confirm-fingerprint "$(FP)" --insecure

audit-verify:  ## recompute the audit hash chain and pinpoint the first broken entry
	ztv-audit-verify --server https://localhost:8443 --admin-key ztv-dev-admin-key-change-me --insecure

lint:
	$(PY) -m bandit -q -r server/ztv_server crypto/ztv_crypto -x tests || true
	semgrep --config p/python --config p/owasp-top-ten server crypto || true
