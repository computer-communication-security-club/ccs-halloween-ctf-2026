# HYDRA VM — custom-VM reversing challenge.
# Builder and runtime use the reviewed Debian bookworm-slim digest. The
# player handout comes only from the dist stage; the private runtime image
# additionally carries the real flag at /flag.txt.

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY src/ ./src/
RUN mkdir -p /out \
    && gcc -O2 -std=c11 -Wall -Wextra -static -pthread -s \
       -fno-ident -Wl,--build-id=none \
       -I src -o /out/hydra-server src/hydra_vm.c src/fw_crypto.c src/server.c \
    && cp src/firmware/firmware.enc /out/firmware.enc \
    && cp src/handout/README.md src/handout/PROTOCOL.md /out/

FROM scratch AS dist
COPY --from=build /out/ /

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime
RUN groupadd --gid 10001 hydra \
    && useradd --uid 10001 --gid 10001 --no-create-home \
       --shell /usr/sbin/nologin hydra
WORKDIR /app
COPY --from=build /out/hydra-server /out/firmware.enc ./
COPY flag.txt /flag.txt
RUN chmod 444 /flag.txt

ENV HYDRA_PORT=31337 \
    HYDRA_BIND=0.0.0.0 \
    HYDRA_FLAG_FILE=/flag.txt \
    HYDRA_TIMEOUT=15 \
    HYDRA_MAX_CONN=128 \
    HYDRA_MAX_STEPS=1000000

USER 10001:10001
EXPOSE 31337

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/31337"]

CMD ["./hydra-server"]
