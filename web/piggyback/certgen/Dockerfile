# One-shot cert/STEK generator. Build context is the challenge root so it can
# copy the shared gen-certs.sh; writes into the mounted /certs volume and exits.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
COPY certs/gen-certs.sh /gen-certs.sh
ENTRYPOINT ["sh", "-c", "OUT=/certs DOMAIN=${DOMAIN:-lab} sh /gen-certs.sh"]
