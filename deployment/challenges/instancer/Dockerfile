FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:db02bf50858df71bae603149252ea9afcbbab6bca4600276b01c38df5a95dbc7 AS build
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1
COPY apps/docker-instancer/pyproject.toml apps/docker-instancer/uv.lock ./
RUN uv sync --locked --no-dev

FROM python:3.14-slim-trixie@sha256:ec6a14df5b63e3fbb3498e3240f7f640c230f9dca67683d23265db3866697f2d
COPY --from=build /app/.venv /app/.venv
COPY apps/docker-instancer/instancer /app/instancer
COPY ccs/guard.py ccs/run.py ccs/raw_https.py /app/
ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1
# The upstream pruner's process lock is relative to cwd.
WORKDIR /tmp
CMD ["python", "/app/run.py"]
