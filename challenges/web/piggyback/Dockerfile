# One build context, one target per Compose service: certgen, backend, front, lb.
# golang 1.22.12, debian bookworm-slim, haproxy 2.9.15 — pinned by digest.

FROM golang:1.22-bookworm@sha256:3d699e4d15d0f8f13c9195c0632a16702b8cbdece2955af1c23b37ae5d55a253 AS backend-build
WORKDIR /src
COPY src/backend/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /backend .

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS front-build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY src/front/front.c /src/front.c
# -Wno-deprecated-declarations: the STEK callback uses the legacy HMAC_CTX API,
# which is deprecated-but-present in OpenSSL 3 and the simplest cross-version path.
RUN gcc -O2 -Wall -Wno-deprecated-declarations -o /front /src/front.c -lssl -lcrypto -lpthread

# Black-box challenge: players receive only the endpoint, so the handout is empty.
FROM scratch AS dist

# One-shot: writes the cert and the shared session-ticket key into the certs volume.
# /certs is owned by 10001 so a fresh named volume inherits that ownership.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS certgen
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /certs && chown 10001:10001 /certs
COPY src/certgen/gen-certs.sh /gen-certs.sh
USER 10001:10001
ENTRYPOINT ["sh", "-c", "OUT=/certs DOMAIN=${DOMAIN:-piggyback} sh /gen-certs.sh"]

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS backend
COPY --from=backend-build /backend /backend
COPY flag.txt /app/flag.txt
RUN chmod 444 /app/flag.txt
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/backend"]

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS front
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=front-build /front /front
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/front"]

FROM haproxy:2.9@sha256:81506628494800519f82caf4128cb693df21ee5f38fca467224fcff508d537de AS lb
COPY src/haproxy/haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
EXPOSE 8443
