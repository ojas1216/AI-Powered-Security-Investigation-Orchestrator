# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.13-slim AS build
WORKDIR /app
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY pyproject.toml ./
RUN python -m venv /venv && /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install .
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./

# ── Runtime stage (distroless, non-root, read-only) ───────────────────────────
FROM gcr.io/distroless/python3-debian12:nonroot
WORKDIR /app
COPY --from=build /venv /venv
COPY --from=build /app /app
ENV PATH="/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONPATH=/app
# distroless 'nonroot' user (uid 65532). Filesystem mounted read-only by the
# Pod securityContext; the app writes nothing to disk.
USER nonroot
EXPOSE 8000
ENTRYPOINT ["/venv/bin/python", "-m", "uvicorn", "app.main:app", \
            "--host", "0.0.0.0", "--port", "8000"]
