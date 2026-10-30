# syntax=docker/dockerfile:1
FROM node:24.22.0-bookworm@sha256:925de64a85319052d6971ae81ef2417da956e8a3a2c4a0fac732327970f017f5 AS frontend

RUN npm install -g pnpm@12.15.0
WORKDIR /fe

COPY src/frontend/package.json src/frontend/pnpm-lock.yaml src/frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY src/frontend ./
RUN pnpm build

FROM node:24.22.0-bookworm@sha256:925de64a85319052d6971ae81ef2417da956e8a3a2c4a0fac732327970f017f5 AS app

ENV UV_THREADPOOL_SIZE=1 \
    NODE_ENV=production \
    PORT=8000

RUN npm install -g pnpm@12.15.0

WORKDIR /app

COPY src/backend/package.json src/backend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod

COPY src/backend ./
COPY --from=frontend /fe/dist ./public

COPY flag.txt /flag.txt
RUN chmod 0444 /flag.txt

USER node
EXPOSE 8000

CMD ["sh", "-c", "while true; do node index.js; sleep 0.1; done"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.PORT||8000}/health`).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

FROM scratch AS dist
