# omp-strix sandbox image — pentest tooling on Debian slim.
# Tool lists live in tools-apt.txt / tools-pip.txt; add a line to add a tool.
# CI publishes multi-arch images (linux/amd64 + linux/arm64) to GHCR on changes
# to this directory. Every downloaded binary below is TARGETARCH-aware.

# ---------------------------------------------------------------------------
# Stage 1: fetch — download upstream release binaries for the target arch.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS fetch

ARG TARGETARCH

# Pinned upstream release tags (verified against GitHub releases).
ARG NUCLEI_VER=3.11.1
ARG SUBFINDER_VER=2.16.0
ARG KATANA_VER=1.7.0
ARG NAABU_VER=2.6.1
ARG HTTPX_VER=1.12.0
ARG DNSX_VER=1.3.1
ARG INTERACTSH_VER=1.3.1
ARG UNCOVER_VER=1.2.1
ARG FEROXBUSTER_VER=2.13.1
ARG ASTGREP_VER=0.45.3
ARG GITLEAKS_VER=8.30.1
ARG TRUFFLEHOG_VER=3.97.5
ARG TRIVY_VER=0.74.0
ARG HURL_VER=8.0.1
ARG AMASS_VER=5.1.1
ARG DALFOX_VER=3.2.3
ARG X8_VER=4.3.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip binutils \
    && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-c"]

RUN set -euo pipefail; \
    mkdir -p /out /debs; \
    # Per-ecosystem arch spellings. TARGETARCH is amd64|arm64 under buildx;
    # fall back to dpkg for plain `docker build`.
    ARCH="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$ARCH" in \
      amd64) PD=amd64;   FEROX=x86_64;  TRIPLE=x86_64-unknown-linux-gnu; GL=x64;   TR=64bit; HURL=amd64; AM=amd64; DL=x86_64;  X8=1 ;; \
      arm64) PD=arm64;   FEROX=aarch64; TRIPLE=aarch64-unknown-linux-gnu; GL=arm64; TR=ARM64; HURL=arm64; AM=arm64; DL=aarch64; X8=0 ;; \
      *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac; \
    \
    dl() { curl -fSL --retry 3 --connect-timeout 20 -o "$1" "$2"; }; \
    # ProjectDiscovery tools: <name>_<ver>_linux_<arch>.zip, binary at zip root.
    pd() { dl /tmp/pd.zip "https://github.com/projectdiscovery/$1/releases/download/v$2/$1_${2}_linux_${PD}.zip"; \
           unzip -o -j /tmp/pd.zip "$1" -d /out; }; \
    pd nuclei            "$NUCLEI_VER"; \
    pd subfinder         "$SUBFINDER_VER"; \
    pd katana            "$KATANA_VER"; \
    pd naabu             "$NAABU_VER"; \
    pd httpx             "$HTTPX_VER"; \
    pd dnsx              "$DNSX_VER"; \
    pd uncover           "$UNCOVER_VER"; \
    dl /tmp/i.zip "https://github.com/projectdiscovery/interactsh/releases/download/v${INTERACTSH_VER}/interactsh-client_${INTERACTSH_VER}_linux_${PD}.zip"; \
    unzip -o -j /tmp/i.zip interactsh-client -d /out; \
    \
    # feroxbuster: <arch>-linux-feroxbuster.zip
    dl /tmp/f.zip "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VER}/${FEROX}-linux-feroxbuster.zip"; \
    unzip -o -j /tmp/f.zip feroxbuster -d /out; \
    \
    # ast-grep: app-<triple>.zip ships `sg` (and `ast-grep` on recent releases)
    dl /tmp/sg.zip "https://github.com/ast-grep/ast-grep/releases/download/${ASTGREP_VER}/app-${TRIPLE}.zip"; \
    unzip -o /tmp/sg.zip -d /tmp/sg; \
    install -m755 /tmp/sg/sg /out/sg; \
    [ -f /tmp/sg/ast-grep ] && install -m755 /tmp/sg/ast-grep /out/ast-grep || ln -sf sg /out/ast-grep; \
    \
    # tarballs: extract, then locate the binary by name.
    tgz() { dl /tmp/t.tgz "$2"; mkdir -p /tmp/t; tar -xzf /tmp/t.tgz -C /tmp/t; \
            install -m755 "$(find /tmp/t -name "$1" -type f | head -1)" /out/"$1"; rm -rf /tmp/t /tmp/t.tgz; }; \
    tgz gitleaks   "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_${GL}.tar.gz"; \
    tgz trufflehog "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VER}/trufflehog_${TRUFFLEHOG_VER}_linux_${PD}.tar.gz"; \
    tgz trivy      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_Linux-${TR}.tar.gz"; \
    tgz amass      "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VER}/amass_linux_${AM}.tar.gz"; \
    tgz dalfox     "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VER}/dalfox-v${DALFOX_VER}-linux-${DL}.tar.gz"; \
    \
    # hurl: official .deb (installed in the final stage so apt resolves libcurl).
    dl "/debs/hurl_${HURL_VER}_${HURL}.deb" "https://github.com/Orange-OpenSource/hurl/releases/download/${HURL_VER}/hurl_${HURL_VER}_${HURL}.deb"; \
    \
    # x8: upstream ships linux amd64 only — warn-and-continue on arm64.
    if [ "$X8" = "1" ]; then \
      dl /tmp/x8.gz "https://github.com/Sh1Yo/x8/releases/download/v${X8_VER}/x86_64-linux-x8.gz"; \
      gunzip -c /tmp/x8.gz > /out/x8 && chmod 755 /out/x8; \
    else \
      echo "::warning::x8 has no linux/arm64 release — skipping" >&2; \
    fi; \
    \
    strip /out/* 2>/dev/null || true; \
    ls -la /out

# ---------------------------------------------------------------------------
# Stage 2: gobuild — Go tools without usable release binaries.
# ---------------------------------------------------------------------------
FROM golang:bookworm AS gobuild

ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=linux GOBIN=/out

RUN set -euo pipefail; \
    export GOARCH="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    mkdir -p /out; \
    go install github.com/tomnomnom/anew@latest; \
    go install github.com/tomnomnom/qsreplace@latest; \
    go install github.com/tomnomnom/unfurl@latest; \
    go install github.com/tomnomnom/waybackurls@latest; \
    go install github.com/lc/gau/v2/cmd/gau@latest; \
    go install github.com/Emoe/kxss@latest; \
    go install github.com/hakluke/hakrawler@latest; \
    git clone --depth 1 https://github.com/tomnomnom/assetfinder /tmp/assetfinder \
        && cd /tmp/assetfinder && go mod init assetfinder && go build -o /out/assetfinder .; \
    ls -la /out

# ---------------------------------------------------------------------------
# Stage 3: wpscan — build the gem against Debian's ruby so the ABI matches.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS wpscan

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ruby ruby-dev build-essential libcurl4-openssl-dev libffi-dev \
       libxml2-dev libxslt1-dev zlib1g-dev \
    && gem install wpscan --no-document --bindir /usr/local/bin \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Final image
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PIP_NO_CACHE_DIR=1

# Manifest-driven install: comments/blank lines stripped, one layer each.
# apt runs first because tools-pip.txt contains git+https URLs (needs git).
COPY tools-apt.txt tools-pip.txt /tmp/
COPY --from=fetch /debs/ /tmp/debs/
RUN grep -v '^\s*#' /tmp/tools-apt.txt | grep -v '^\s*$' | tr '\n' ' ' > /tmp/apt.list \
    && apt-get update \
    && xargs -a /tmp/apt.list apt-get install -y --no-install-recommends \
    && apt-get install -y --no-install-recommends /tmp/debs/*.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/debs \
    && grep -v '^\s*#' /tmp/tools-pip.txt | grep -v '^\s*$' | tr '\n' ' ' > /tmp/pip.list \
    && xargs -a /tmp/pip.list pip3 install \
    && rm -f /tmp/apt.list /tmp/pip.list /tmp/tools-*.txt

# jwt_tool is a single-script repo (no packaging): clone + wrapper.
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
    && pip3 install -r /opt/jwt_tool/requirements.txt \
    && printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
    && chmod +x /usr/local/bin/jwt_tool

# Wordlists (SecLists subsets) for gobuster/feroxbuster/ffuf.
RUN mkdir -p /opt/wordlists /usr/share/wordlists/dirb /usr/share/wordlists/dns; \
    dl() { curl -fSL --retry 3 -o "/opt/wordlists/$1" "$2"; }; \
    dl common.txt                    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt; \
    dl raft-small-directories.txt    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt; \
    dl raft-small-words.txt          https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt; \
    dl subdomains-top1million-5000.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt; \
    ln -sf /opt/wordlists/common.txt /usr/share/wordlists/dirb/common.txt; \
    ln -sf /opt/wordlists/subdomains-top1million-5000.txt /usr/share/wordlists/dns/subdomains-top1million-5000.txt; \
    for f in /opt/wordlists/*.txt; do ln -sf "$f" "/usr/share/wordlists/$(basename "$f")"; done

# Downloaded + compiled binaries land last so /usr/local/bin/httpx (the
# ProjectDiscovery CLI) wins over anything pip may have placed there.
COPY --from=fetch /out/ /usr/local/bin/
COPY --from=gobuild /out/ /usr/local/bin/
COPY --from=wpscan /var/lib/gems /var/lib/gems
COPY --from=wpscan /usr/local/bin/ /usr/local/bin/

WORKDIR /workspace
CMD ["sleep", "infinity"]
