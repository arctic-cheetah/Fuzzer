# Start from a default ubuntu image.
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim

# Copy/Compile my fuzzer
# COPY fuzzer /


# Create necessary directories
RUN mkdir -p /app/src /app/binaries /app/fuzzer_input /app/fuzzer_output

WORKDIR app/src

COPY src/ ./
RUN uv sync --locked


# Run it.
CMD ["uv", "run", "main.py"]

