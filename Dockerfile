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
    && rm -rf /var/lib/apt/lists/*

# Install C++ tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ make \
    && rm -rf /var/lib/apt/lists/*

# Add QEMU
ARG QEMU_VERSION=7.2.19
ENV DEBIAN_FRONTEND=noninteractive

# Download QEMU source code
WORKDIR /usr/src
RUN wget https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz \
    && tar -xf qemu-${QEMU_VERSION}.tar.xz \
    && rm qemu-${QEMU_VERSION}.tar.xz


# Build QEMU user-mode for x64
#WORKDIR /usr/src/qemu-${QEMU_VERSION}
#RUN ./configure --target-list=x86_64-linux-user --disable-docs \
#    && make -j"$(nproc)" \
#    && make install \
#    && strip /usr/local/bin/qemu-*

# This works! But old qemu-x86_64 version 7.2.19 (Debian 1:7.2+dfsg-7+deb12u16)
# RUN apt-get update \
#     && apt-get install -y --no-install-recommends qemu-user qemu-user-static \
#     && rm -rf /var/lib/apt/lists/*


# ____________________________________________________________________________________

# Sanity check this please
#RUN qemu-x86_64 -version

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
RUN g++ -std=c++2b -o /app/src/harness/harness /app/src/harness/harness.cpp

# Run it.
CMD ["uv", "run", "fuzzer/main.py"]
# CMD ["python3", "main.py"]
