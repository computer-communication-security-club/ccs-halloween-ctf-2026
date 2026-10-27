# DEAD SIGNAL — static rev challenge. Builds the stripped player handout.
# debian bookworm-slim (gcc 12), pinned by the digest already reviewed in
# challenges/web/piggyback. The handout is deterministic: the generator output
# (src/generated_constants.h) is committed, so this build only compiles and
# strips it. No secrets enter the image; the flag exists here only as
# ciphertext inside the compiled binary.

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY src/dead_signal.c src/dsig_consts.h src/generated_constants.h ./
# -fno-ident: no compiler ident string; strip: no symbols. Optimized native C.
RUN mkdir /out \
    && gcc -O2 -std=c11 -Wall -Wextra -fno-ident -o /out/dead_signal dead_signal.c \
    && strip --strip-all /out/dead_signal
COPY src/handout/README.md /out/README.md
RUN cd /out && sha256sum dead_signal README.md > SHA256SUMS

FROM scratch AS dist
COPY --from=build /out/ /
