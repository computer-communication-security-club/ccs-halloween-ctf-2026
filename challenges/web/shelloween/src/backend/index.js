const { createApp } = require("./app");

const port = Number(process.env.PORT || 8000);

const server = createApp().listen(port, () => {
  console.log(`Shell market API listening on port ${port}`);
});

server.on("error", (error) => {
  console.error(error.message);
  process.exitCode = 1;
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
  });
}
