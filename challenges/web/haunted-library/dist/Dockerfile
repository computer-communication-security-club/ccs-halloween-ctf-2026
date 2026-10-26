FROM python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0 AS runtime
WORKDIR /app
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/app.py .
COPY src/pages ./pages
COPY flag.txt .
RUN chmod 444 /app/flag.txt
USER 10001:10001
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "2", "--timeout", "15", "--worker-tmp-dir", "/tmp", "app:app"]

FROM scratch AS dist
COPY src /src
COPY Dockerfile /Dockerfile
COPY src/flag.fake /flag.txt

FROM runtime AS final
