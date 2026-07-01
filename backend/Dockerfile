FROM python:3.11-slim-trixie

ARG APP_VERSION=0.22

WORKDIR /app

ENV APP_VERSION=${APP_VERSION}

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
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

EXPOSE 4001

CMD ["./entrypoint.sh"]
