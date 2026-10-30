const express = require("express");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { createStore } = require("./store");

const publicDir = path.join(__dirname, "public");

function createApp(store = createStore()) {
  const app = express();

  app.use(express.json());
  app.use(express.static(publicDir));

  app.get("/health", (req, res) => res.json({ status: "ok" }));

  app.get("/api/shells", (req, res) => {
    res.json({ data: store.shells });
  });

  app.get("/api/shells/:id", (req, res) => {
    const shell = store.shells.find((item) => item.id === req.params.id);
    if (!shell) return res.status(404).json({ error: "Shell not found" });
    res.json({ data: shell });
  });

  app.post("/api/orders", (req, res) => {
    const { items } = req.body || {};
    if (!Array.isArray(items) || items.length === 0 || items.length > 50) {
      return res.status(400).json({ error: "items must contain between 1 and 50 entries" });
    }

    const quantities = new Map();
    for (const item of items) {
      if (!item || typeof item.shellId !== "string" || !Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 100) {
        return res.status(400).json({ error: "Each item requires a shellId and an integer quantity between 1 and 100" });
      }
      quantities.set(item.shellId, (quantities.get(item.shellId) || 0) + item.quantity);
    }

    const lines = [];
    for (const [shellId, quantity] of quantities) {
      const shell = store.shells.find((item) => item.id === shellId);
      if (!shell) return res.status(404).json({ error: `Shell not found: ${shellId}` });
      if (quantity > shell.stock) {
        return res.status(409).json({ error: `Insufficient stock: ${shellId}` });
      }
      lines.push({ shellId, name: shell.name, quantity, unitPriceCents: shell.priceCents, totalCents: shell.priceCents * quantity });
    }

    const order = {
      id: randomUUID(),
      status: "pending",
      currency: "USD",
      items: lines,
      totalCents: lines.reduce((total, line) => total + line.totalCents, 0),
      createdAt: new Date().toISOString(),
    };
    for (const line of lines) {
      store.shells.find((shell) => shell.id === line.shellId).stock -= line.quantity;
    }
    store.orders.set(order.id, order);
    res.status(201).location(`/api/orders/${order.id}`).json({ data: order });
  });

  app.get("/api/orders/:id", (req, res) => {
    const order = store.orders.get(req.params.id);
    if (!order) return res.status(404).json({ error: "Order not found" });
    res.json({ data: order });
  });

  app.use((req, res, next) => {
    if (req.method !== "GET" || req.path.startsWith("/api/")) return next();
    res.sendFile(path.join(publicDir, "index.html"), (error) => error && next());
  });

  app.use((req, res) => res.status(404).json({ error: "Route not found" }));
  app.use((error, req, res, next) => {
    if (error.type === "entity.parse.failed") {
      return res.status(400).json({ error: "Invalid JSON body" });
    }
    if (error.status >= 400 && error.status < 500) {
      return res.status(error.status).json({ error: "Invalid request body" });
    }
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  });
  return app;
}

module.exports = { createApp };
