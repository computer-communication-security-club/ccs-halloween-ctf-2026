const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createApp } = require("../app");

async function start(t) {
  const server = createApp().listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  return (path, options) => fetch(`${base}${path}`, options);
}

const order = (items) => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ items }),
});

test("orders use catalog prices, combine quantities, and reduce stock", async (t) => {
  const request = await start(t);
  const response = await request("/api/orders", order([
    { shellId: "bash", quantity: 2, priceCents: 1 },
    { shellId: "bash", quantity: 1 },
  ]));
  assert.equal(response.status, 201);
  const { data } = await response.json();
  assert.equal(data.totalCents, 3000);
  assert.equal(data.items.length, 1);
  assert.equal(data.items[0].quantity, 3);
  const saved = await request(response.headers.get("location"));
  assert.deepEqual((await saved.json()).data, data);
  const shell = await request("/api/shells/bash");
  assert.equal((await shell.json()).data.stock, 97);
});

test("failed orders preserve all stock, including duplicate-item overselling", async (t) => {
  const request = await start(t);
  for (const items of [
    [{ shellId: "bash", quantity: 1 }, { shellId: "zsh", quantity: 51 }],
    [{ shellId: "bash", quantity: 60 }, { shellId: "bash", quantity: 60 }],
  ]) {
    assert.equal((await request("/api/orders", order(items))).status, 409);
  }
  const shell = await request("/api/shells/bash");
  assert.equal((await shell.json()).data.stock, 100);
});

test("invalid bodies and missing resources produce JSON errors", async (t) => {
  const request = await start(t);
  for (const items of [[], null, [{ shellId: "bash", quantity: -1 }], [{ shellId: "bash", quantity: 1.5 }]]) {
    assert.equal((await request("/api/orders", order(items))).status, 400);
  }
  const malformed = await request("/api/orders", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: "{",
  });
  assert.equal(malformed.status, 400);
  assert.equal((await malformed.json()).error, "Invalid JSON body");
  for (const path of ["/missing", "/api/shells/missing", "/api/orders/missing"]) {
    const response = await request(path);
    assert.equal(response.status, 404);
    assert.equal(typeof (await response.json()).error, "string");
  }
});
