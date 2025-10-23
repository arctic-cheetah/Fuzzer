# Start from a default ubuntu image.
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim

# Copy/Compile my fuzzer
# COPY fuzzer /
# Make Python stdout unbuffered and avoid creating .pyc files
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Create necessary directories
RUN mkdir -p /app/src /app/binaries /app/fuzzer_input /app/fuzzer_output

WORKDIR app/src

# Copy dependency manifests first to leverage Docker layer cache
COPY src/pyproject.toml src/uv.lock ./
RUN uv sync --locked

# Copy the actual source code (changing code won’t invalidate the dependency layer)
COPY src/ ./

# Run it.
CMD ["uv", "run", "main.py"]

