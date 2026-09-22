# omp-strix sandbox image — pentest tooling on Debian slim.
# Tool lists live in tools-apt.txt / tools-pip.txt; add a line to add a tool.
# CI publishes multi-arch images to GHCR on changes to this directory.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PIP_NO_CACHE_DIR=1

# Manifest-driven install: comments/blank lines stripped, one layer each.
COPY tools-apt.txt tools-pip.txt /tmp/
RUN grep -v '^\s*#' /tmp/tools-apt.txt | grep -v '^\s*$' | tr '\n' ' ' > /tmp/apt.list \
    && apt-get update \
    && xargs -a /tmp/apt.list apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && grep -v '^\s*#' /tmp/tools-pip.txt | grep -v '^\s*$' | tr '\n' ' ' > /tmp/pip.list \
    && xargs -a /tmp/pip.list pip3 install \
    && rm -f /tmp/apt.list /tmp/pip.list /tmp/tools-*.txt

WORKDIR /workspace
CMD ["sleep", "infinity"]
