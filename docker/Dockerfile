# syntax=docker/dockerfile:1
# ── Stage 1: build dependencies + package wheel ───────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools
RUN pip install --upgrade pip setuptools wheel build

# Copy the whole project so we can build the ulpf wheel
COPY . .

# Build the ulpf wheel and all dependency wheels into /wheels
RUN pip wheel --no-cache-dir --wheel-dir /wheels . \
    && pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="Universal Log Pre-processing Framework"
LABEL org.opencontainers.image.description="Vendor-agnostic perimeter log normalization pipeline"
LABEL org.opencontainers.image.version="1.2.0"

# Create non-root user
RUN useradd -r -s /bin/false -m -d /app ulpf

WORKDIR /app

# Copy pre-built wheels from builder (includes ulpf + all deps)
COPY --from=builder /wheels /wheels

# Install everything from local wheels — zero network access required
RUN pip install --no-cache-dir --no-index --find-links /wheels ulpf \
    && rm -rf /wheels

# Copy application data into the installed Python package
COPY --chown=ulpf:ulpf ulpf/schemas /usr/local/lib/python3.11/site-packages/ulpf/schemas
COPY --chown=ulpf:ulpf ulpf/sample_logs /app/sample_logs
COPY --chown=ulpf:ulpf ulpf/config /usr/local/lib/python3.11/site-packages/ulpf/config

# Create output directory
RUN mkdir -p /app/output && chown ulpf:ulpf /app/output

USER ulpf

VOLUME ["/app/output"]

ENTRYPOINT ["ulpf"]
CMD ["ingest", "--input", "/app/sample_logs", "--output", "/app/output"]
