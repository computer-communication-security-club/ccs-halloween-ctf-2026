function createStore() {
  return {
    shells: [
      { id: "bash", name: "Bash", description: "A classic shell for everyday scripting.", priceCents: 1000, currency: "USD", stock: 100 },
      { id: "zsh", name: "Zsh", description: "An interactive shell with powerful customization.", priceCents: 1500, currency: "USD", stock: 50 },
      { id: "fish", name: "Fish", description: "A friendly shell with helpful defaults.", priceCents: 1200, currency: "USD", stock: 75 },
    ],
    orders: new Map(),
  };
}

module.exports = { createStore };
