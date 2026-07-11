# syntax=docker/dockerfile:1.7
FROM python:3.11-slim-trixie

ARG APP_VERSION=0.24
ARG PIP_INDEX_URL=https://pypi.org/simple

WORKDIR /app

ENV APP_VERSION=${APP_VERSION} \
    PIP_INDEX_URL=${PIP_INDEX_URL} \
    PIP_DEFAULT_TIMEOUT=600 \
    PIP_RETRIES=10 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_INPUT=1

# acme.sh + runtime deps. Use Debian's packaged acme.sh instead of cloning
# GitHub during image builds; cert/account state lives on the mounted db volume
# via ACME_HOME (set below), not in the image.
RUN set -eux; \
    apt-get update -o Acquire::Retries=5; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        acme.sh bash curl openssl socat ca-certificates; \
    rm -rf /var/lib/apt/lists/*

ENV ACME_SH_BIN=/usr/bin/acme.sh \
    ACME_HOME=/app/db/acme \
    ACME_CA_SERVER=letsencrypt

COPY requirements.txt .
# BuildKit keeps downloaded wheels between rebuilds. A temporary network
# failure therefore no longer discards all completed dependency downloads.
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    python -m pip install \
      --retries "${PIP_RETRIES}" \
      --timeout "${PIP_DEFAULT_TIMEOUT}" \
      --prefer-binary \
      -r requirements.txt

COPY . .

RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

EXPOSE 4001

CMD ["./entrypoint.sh"]
