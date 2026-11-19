# syntax=docker/dockerfile:1
#
# Offline overlay for the lab's ARTEX image. It does not change ARTEX's code
# or its own image build; it adds what the tools need to run with no internet
# access, and switches off their runtime self-updates.
#
#   - nuclei-templates pinned to a release and verified by sha256, installed
#     where nuclei looks for them.
#   - disable-update-check for the ProjectDiscovery tools (nuclei, httpx,
#     subfinder, katana) through their config files, which accept any CLI
#     flag. These tools have no environment switch for it.
#   - nuclei template auto-download disabled through its environment switches.
#   - bbot runtime dependency installation disabled (dependencies were
#     installed at image build time by ARTEX's Dockerfile).
#
# Anything that still tries to reach the internet at runtime is stopped by the
# network (ARTEX is on internal-only networks); see docs/ASSUMPTIONS.md.

ARG ARTEX_IMAGE=snare-lab/artex:d89cf78
FROM ${ARTEX_IMAGE}

ARG NUCLEI_TEMPLATES_VERSION=10.5.2
ARG NUCLEI_TEMPLATES_SHA256=016b7abbf931d4d1a851a5a568e44510dc61691dc8a5202e3b24e701515ec574

RUN set -eux; \
    url="https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz"; \
    curl -fsSL "$url" -o /tmp/nt.tar.gz; \
    echo "${NUCLEI_TEMPLATES_SHA256}  /tmp/nt.tar.gz" | sha256sum -c -; \
    mkdir -p /root/nuclei-templates; \
    tar -xzf /tmp/nt.tar.gz -C /root/nuclei-templates --strip-components=1; \
    rm -f /tmp/nt.tar.gz; \
    mkdir -p /root/.config/nuclei; \
    if [ -f /root/nuclei-templates/.nuclei-ignore ]; then \
      cp /root/nuclei-templates/.nuclei-ignore /root/.config/nuclei/.nuclei-ignore; \
    else : > /root/.config/nuclei/.nuclei-ignore; fi; \
    for tool in nuclei httpx subfinder katana; do \
      mkdir -p "/root/.config/$tool"; \
      printf 'disable-update-check: true\n' >> "/root/.config/$tool/config.yaml"; \
    done; \
    printf '\ndeps:\n  behavior: disable\n' >> /root/.config/bbot/bbot.yml

ENV DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true \
    DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD=true \
    DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD=true \
    DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD=true \
    DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD=true \
    DISABLE_CLOUD_UPLOAD=true

# Build-time check: nuclei must load the baked templates without fetching.
RUN n="$(nuclei -duc -tl -silent 2>/dev/null | wc -l)"; echo "nuclei templates: $n"; test "$n" -gt 1000
