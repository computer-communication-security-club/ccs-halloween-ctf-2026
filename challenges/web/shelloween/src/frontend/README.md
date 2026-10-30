# Shell Market frontend

React + Vite with JavaScript and pnpm. Requires Node.js 22.12+.

Start the backend in one terminal:

```sh
cd src/backend
pnpm install
pnpm dev
```

Start the frontend in another terminal:

```sh
cd src/frontend
pnpm install
cp .env.example .env
pnpm dev
```

Open the local URL printed by Vite (usually http://localhost:5173).
Vite proxies `/api` to `http://127.0.0.1:8000`. Change `API_PROXY_TARGET`
in `.env` if your backend runs elsewhere, then restart Vite.

The storefront loads the live catalog, manages a cart, and submits orders.
It displays the server's order reference and total after checkout.
Cart state lasts for the current page session. The backend stores orders and
stock in memory; restarting it resets both. Checkout does not process payments.

```sh
pnpm build
pnpm preview
```

Production assets are written to `dist/`. Configure your production web server
to forward `/api` to Express; Vite's development proxy does not apply to the
production build or `pnpm preview`. Preview only serves built frontend assets.

`src/api.js` wraps API requests, `src/App.jsx` contains the storefront, and
`src/styles.css` contains responsive styles. Google Fonts are optional; local
fallback fonts are used when they cannot load. No frontend environment variable
should contain secrets; browser code and bundled configuration are public.
