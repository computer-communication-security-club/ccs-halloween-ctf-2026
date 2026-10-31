FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY src/ ./src/
RUN make -C src
RUN mkdir -p /out \
    && cp /work/public/cursed_signer /out/cursed_signer \
    && cp /work/src/handout/README.md /out/README.md \
    && cp /work/src/handout/ritual_client.py /out/ritual_client.py \
    && chmod 0755 /out/cursed_signer /out/ritual_client.py

FROM scratch AS dist
COPY --from=build /out/ /

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 cursed \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin cursed

WORKDIR /app
COPY --from=build /work/public/cursed_signer /app/cursed_signer
COPY --from=build /work/src/server.py /app/server.py
COPY --from=build /work/src/entrypoint.sh /app/entrypoint.sh
COPY flag.txt /flag.txt
RUN chmod 0555 /app/cursed_signer /app/entrypoint.sh \
    && chmod 0444 /app/server.py /flag.txt

ENV CURSED_APP_DIR=/app \
    CURSED_DATA_DIR=/tmp/cursed-data \
    CURSED_FLAG_FILE=/flag.txt \
    PORT=1337 \
    MAX_QUERIES=600 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001:10001
EXPOSE 1337

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD ["python3", "-c", "import socket; s=socket.create_connection(('127.0.0.1', 1337), 2); s.close()"]

ENTRYPOINT ["/app/entrypoint.sh"]
