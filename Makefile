.PHONY: install test lint security run compose frontend

install:
	cd backend && python -m venv .venv && . .venv/Scripts/activate && pip install -e ".[dev]"

test:
	cd backend && pytest -q

lint:
	cd backend && ruff check app && mypy app

security:
	cd backend && bandit -q -r app
	semgrep --config auto backend || true
	gitleaks detect --no-banner || true

run:
	cd backend && uvicorn app.main:app --reload

frontend:
	cd frontend && npm install && npm run dev

compose:
	docker compose up --build
