# omp-strix sandbox image — essential pentest tooling on Debian slim.
# Replaces strix's dedicated sandbox image; built on first use by the plugin.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    # recon / network
    nmap masscan dnsutils whois iputils-ping traceroute net-tools iproute2 \
    netcat-openbsd socat openssl \
    # web
    curl wget gobuster sqlmap \
    # brute force
    hydra john \
    # scripting / glue
    python3 python3-pip python3-venv git jq ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
CMD ["sleep", "infinity"]
