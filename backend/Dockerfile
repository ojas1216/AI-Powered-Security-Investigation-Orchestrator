# ── Build stage ───────────────────────────────────────────────────────────────
# Python version MUST match the distroless runtime (python3-debian12 == 3.11) so
# compiled wheels (e.g. psycopg binary) are ABI-compatible.
FROM python:3.11-slim AS build
WORKDIR /src
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY pyproject.toml ./
COPY app ./app
# Install the project + dependencies into a relocatable target dir (no venv —
# a venv's bin/python is a symlink back to this image and dangles in distroless).
RUN pip install --target=/install .

# ── Runtime stage (distroless, non-root, read-only filesystem) ────────────────
FROM gcr.io/distroless/python3-debian12:nonroot
WORKDIR /app
COPY --from=build /install /app/pydeps
COPY alembic ./alembic
COPY alembic.ini ./
ENV PYTHONPATH=/app/pydeps PYTHONUNBUFFERED=1
# distroless 'nonroot' user (uid 65532). The Pod mounts the rootfs read-only;
# the app writes nothing to disk.
USER nonroot
EXPOSE 8000
ENTRYPOINT ["/usr/bin/python3.11", "-m", "uvicorn", "app.main:app", \
            "--host", "0.0.0.0", "--port", "8000"]
