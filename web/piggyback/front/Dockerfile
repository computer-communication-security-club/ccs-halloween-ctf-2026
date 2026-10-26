FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY front.c /src/front.c
# -Wno-deprecated-declarations: the STEK callback uses the legacy HMAC_CTX API,
# which is deprecated-but-present in OpenSSL 3 and the simplest cross-version path.
RUN gcc -O2 -Wall -Wno-deprecated-declarations -o /front /src/front.c -lssl -lcrypto -lpthread

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /front /front
EXPOSE 8443
ENTRYPOINT ["/front"]
