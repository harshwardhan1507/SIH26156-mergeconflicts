# syntax=docker/dockerfile:1

# ── Stage 1: build the wheel and its dependency wheels ────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
RUN pip install --no-cache-dir --upgrade pip setuptools wheel build

COPY . .

# Build ulpf plus the dashboard extra into a local wheelhouse. Building the
# project wheel already resolves its dependencies, so requirements.txt is not
# installed separately.
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[dashboard]"


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="Universal Log Pre-processing Framework"
LABEL org.opencontainers.image.description="Vendor-agnostic perimeter log normalization pipeline"
LABEL org.opencontainers.image.version="1.3.0"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Runtime-authored declarative sources and state live on the writable
    # volume, never inside site-packages.
    ULPF_DATA_DIR=/app/data \
    ULPF_OUTPUT_DIR=/app/output

# Unprivileged runtime user. Its home is deliberately NOT the application
# directory, and site-packages stays root-owned so the process cannot rewrite
# its own code.
RUN useradd --system --create-home --home-dir /home/ulpf --shell /usr/sbin/nologin ulpf

WORKDIR /app

COPY --from=builder /wheels /wheels
# Installed as root so the resulting site-packages tree is read-only to `ulpf`.
RUN pip install --no-cache-dir --no-index --find-links /wheels "ulpf[dashboard]" \
    && rm -rf /wheels

# Example logs are data, not package content — they are mounted read-only.
COPY --chown=root:root examples/sample_logs /app/sample_logs

RUN mkdir -p /app/output /app/data && chown -R ulpf:ulpf /app/output /app/data

USER ulpf

VOLUME ["/app/output", "/app/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status==200 else 1)" \
    || exit 1

ENTRYPOINT ["ulpf"]
CMD ["ingest", "--input", "/app/sample_logs", "--output", "/app/output"]
