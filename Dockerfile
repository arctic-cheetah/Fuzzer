# Start from a default ubuntu image.
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim
# FROM ubuntu:24.04

# Make Python stdout unbuffered # avoid creating .pyc files
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Install tools required for qemu compilation
# ____________________________________________________________________________________
RUN apt-get update && apt-get install -y wget xz-utils && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential pkg-config python3 \
    ninja-build meson \
    libglib2.0-dev libpixman-1-dev libfdt-dev libseccomp-dev \
    zlib1g-dev libzstd-dev \
    ca-certificates wget xz-utils git \
    libzmq3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install C++ tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ make \
    && rm -rf /var/lib/apt/lists/*

# make UV create bytecode (more disk space for a perf gain)
ENV UV_COMPILE_BYTECODE=1

# Create necessary directories
RUN mkdir -p /app/src /app/src /app/binaries /app/fuzzer_input /app/fuzzer_output
WORKDIR /app/src

# Copy dependency manifests first to leverage Docker layer cache
COPY src/fuzzer/pyproject.toml src/fuzzer/uv.lock ./
RUN uv sync --locked

# Copy the actual source code and example files
# COPY src/ ./ <= Who the FUCK WROTE THIS SHIT RELATIVE PATH MOTHER FUCKER ILL KILL YOU
COPY src/ /app/src/
COPY example_inputs /app/example_inputs
COPY binaries /app/binaries

# Copy into / as required by assignment
COPY example_inputs /example_inputs
COPY binaries /binaries
RUN mkdir /fuzzer_output


# Compile it
# Build harness
RUN rm -f /app/src/harness/harness && g++ -std=c++2b -O3 -o /app/src/harness/harness /app/src/harness/harness.cpp

# Install numpy
# Build harness
RUN python3 -m venv /app/src/venv && /app/src/venv/bin/pip3 install numpy && /app/src/venv/bin/pip3 install pikepdf && /app/src/venv/bin/pip3 install fontTools 


# Run it.
# CMD ["uv", "run", "fuzzer/main.py"]
CMD ["/app/src/venv/bin/python3", "fuzzer/main.py"]
# CMD ["python3", "main.py"]
