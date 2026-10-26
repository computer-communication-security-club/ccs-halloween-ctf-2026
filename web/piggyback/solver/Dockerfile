FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl bash \
    && rm -rf /var/lib/apt/lists/*
COPY solve.sh /solve.sh
RUN chmod +x /solve.sh
ENTRYPOINT ["/solve.sh"]
