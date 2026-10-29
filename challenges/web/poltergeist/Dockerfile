# ============================================================================
#  Poltergeist (web) — compile the Séance worker, run it as the service, and
#  export the player handout. Target: linux/amd64.
# ============================================================================

# ---- build the Séance worker -------------------------------------------------
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev binutils \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/chall.c .
# Build config: hardened -- PIE/ASLR, Full RELRO (GOT read-only), NX, stack
# canaries -- and then FULLY STRIPPED. The handout binary is byte-for-byte the
# deployed one, but it carries no symbol table: a player must reverse-engineer
# the image to locate the globals/return-site the exploit needs. The worker also
# fronts /seance with a signature WAF and a proof-of-work gate (both in chall.c);
# neither changes the language or the vulnerability.
#
# The static offsets the official solver needs (arena, clientfd, write@got, and
# process_request's return site) are captured from the UNstripped intermediate
# into an author-only file; it is NOT part of the player handout.
RUN gcc -O1 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now \
        -o /tmp/run chall.c \
 && A=$(nm /tmp/run | awk '$3=="arena"{print $1}') \
 && C=$(nm /tmp/run | awk '$3=="clientfd"{print $1}') \
 && W=$(objdump -R /tmp/run | awk '/ write@/{print $1}') \
 && CALL=$(objdump -d /tmp/run | grep -E 'call +[0-9a-f]+ <process_request>' | head -1 \
           | awk '{print $1}' | tr -d :) \
 && RET=$(printf '%x' $((0x$CALL + 5))) \
 && printf 'arena 0x%s\nclientfd 0x%s\nwrite_got 0x%s\nretsite 0x%s\n' "$A" "$C" "$W" "$RET" \
      > /tmp/run.offsets \
 && strip --strip-all /tmp/run \
 && cat /tmp/run.offsets

# ---- runtime service ---------------------------------------------------------
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS runtime
WORKDIR /app
COPY --from=build /tmp/run /app/run
RUN chmod 755 /app/run
# The flag is NEVER resident in the worker's memory and the app never serves it:
# it exists only on disk, readable by the service account, and the only way to it
# is code execution that opens and reads the file (the intended RCE).
COPY flag.txt /flag.txt
RUN chmod 444 /flag.txt
RUN useradd -m -u 10001 medium
USER 10001
EXPOSE 8080
# Front-door proof-of-work difficulty (leading zero bits). 0 would disable it.
ENV POW_BITS=24
# One persistent worker, requests handled sequentially — exactly the reused-
# worker model the vulnerability depends on. 256 KiB per-request memory_limit
# (small on purpose: the WAF forbids 7+ digit literals, so the OOM count must be
# shaped to fit under the limit).
CMD ["/app/run", "-S", "0.0.0.0:8080", "-m", "262144"]

# ---- public handout ----------------------------------------------------------
# libc/loader come from the RUNTIME filesystem, i.e. exactly what the deployed
# binary runs against, so any offsets a player computes match production.
FROM scratch AS dist
COPY --from=runtime /app/run /chall
COPY --from=runtime /usr/lib/x86_64-linux-gnu/libc.so.6 /libc.so.6
COPY --from=runtime /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /ld-linux-x86-64.so.2
COPY src/chall.c /chall.c

# ---- author-only offsets (NOT a handout; a separate stage so it never lands in
#      dist/, the zip, or challenge.yml). Refresh solve/chall.offsets with:
#        docker build --target offsets -o type=local,dest=/tmp/o . && cp /tmp/o/chall.offsets solve/
FROM scratch AS offsets
COPY --from=build /tmp/run.offsets /chall.offsets

# ---- default build target (the service) --------------------------------------
FROM runtime AS final
