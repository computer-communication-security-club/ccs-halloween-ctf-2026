FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl python3 \
    && rm -rf /var/lib/apt/lists/*
COPY solve.py /solve.py
ENTRYPOINT ["python3", "/solve.py"]
