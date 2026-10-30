# Shell market API

Node.js / Express boilerplate selling shell-themed products (Bash, Zsh, Fish).
Requires Node.js 22.9+ and pnpm 12.15.0.

```sh
cd src/backend
pnpm install
cp .env.example .env
pnpm dev
```

The API listens on port 8000 by default. Set `PORT` in `.env` to change it.
Use `pnpm start` to run without the file watcher and `pnpm test` for API tests.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Health check |
| GET | `/api/shells` | List the catalog |
| GET | `/api/shells/:id` | Get one shell |
| POST | `/api/orders` | Create an order and deduct stock |
| GET | `/api/orders/:id` | Get an order |

```sh
curl http://localhost:8000/api/shells
curl -X POST http://localhost:8000/api/orders \
  -H 'Content-Type: application/json' \
  -d '{"items":[{"shellId":"bash","quantity":2}]}'
```

Responses use `{ "data": ... }`, errors use `{ "error": "..." }`.
All prices are integer USD cents, calculated from the catalog on the server.
Orders start as `pending`; this starter does not process payment or deliver shells.

Data is stored in memory and resets on restart. Each application instance has its
own catalog and orders. Add persistent storage before running multiple instances.
There is no authentication: order lookup is public to anyone with the order UUID.
Add authentication and ownership checks before storing customer information.

`app.js` builds the Express app, `store.js` provides seed data and storage, and
`index.js` starts the HTTP server and handles shutdown.
