FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS rootfs
COPY chall /app/run
COPY libc.so.6 /usr/lib/x86_64-linux-gnu/libc.so.6
COPY ld-linux-x86-64.so.2 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
COPY flag.txt /app/flag.txt
RUN chmod 755 /app/run && chmod 444 /app/flag.txt

FROM ghcr.io/redpwn/jail@sha256:ee52ad5fd6cfed7fd8ea30b09792a6656045dd015f9bef4edbbfa2c6e672c28c
COPY --from=rootfs / /srv
ENV JAIL_TIME=30 JAIL_MEM=32M JAIL_PIDS=10 JAIL_CPU=100 JAIL_CONNS=32
EXPOSE 5000
