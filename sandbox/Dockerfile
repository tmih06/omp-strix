# omp-strix sandbox image — essential pentest tooling on Debian slim.
# Replaces strix's dedicated sandbox image; built on first use by the plugin.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    # recon / network
    nmap masscan dnsutils whois iputils-ping traceroute net-tools iproute2 \
    netcat-openbsd socat openssl \
    # web
    curl wget gobuster sqlmap dirsearch \
    # pip-installed recon (httpx, wafw00f, arjun)
    # brute force
    hydra john \
    # scripting / glue
    python3 python3-pip python3-venv git jq ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages \
    httpx wafw00f arjun 2>/dev/null || pip3 install --no-cache-dir httpx wafw00f arjun

WORKDIR /workspace
CMD ["sleep", "infinity"]
