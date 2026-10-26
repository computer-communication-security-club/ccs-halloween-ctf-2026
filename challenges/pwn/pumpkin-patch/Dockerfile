FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/chall.c .
RUN gcc -O0 -fno-stack-protector -fno-omit-frame-pointer -fcf-protection=none \
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -no-pie -Wl,-z,relro,-z,now \
    -o /tmp/chall chall.c

# Purge the toolchain, preserving the exact libc installed during the build.
FROM build AS rootfs
RUN apt-get purge -y gcc libc6-dev && apt-get autoremove -y \
    && rm -rf /build /var/lib/apt/lists/* \
    && mkdir -p /app && mv /tmp/chall /app/run && chmod 755 /app/run
COPY flag.txt /app/flag.txt
RUN chmod 444 /app/flag.txt

FROM scratch AS dist
COPY --from=rootfs /app/run /chall
COPY --from=rootfs /usr/lib/x86_64-linux-gnu/libc.so.6 /libc.so.6
COPY --from=rootfs /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /ld-linux-x86-64.so.2
COPY src/chall.c /chall.c
COPY src/Dockerfile.player /Dockerfile
COPY src/flag.fake /flag.txt

FROM ghcr.io/redpwn/jail@sha256:ee52ad5fd6cfed7fd8ea30b09792a6656045dd015f9bef4edbbfa2c6e672c28c AS final
COPY --from=rootfs / /srv
ENV JAIL_TIME=30 JAIL_MEM=32M JAIL_PIDS=10 JAIL_CPU=100 JAIL_CONNS=32
EXPOSE 5000
