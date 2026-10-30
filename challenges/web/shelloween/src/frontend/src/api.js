async function request(path, options = {}) {
  const response = await fetch(`/api${path}`, options);
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.error || "The market is unavailable. Please try again.");
  if (!body || !("data" in body)) throw new Error("The market returned an unexpected response.");
  return body.data;
}

export const getShells = () => request("/shells");
export const createOrder = (items) => request("/orders", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ items }),
});
