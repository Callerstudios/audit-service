import app from "./app.js";
import { config } from "./config.js";

const server = app.listen(config.PORT, "0.0.0.0", () => {
  console.log(`Audit service listening on port ${config.PORT}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    server.close((error) => {
      if (error) {
        console.error("Error during server shutdown", error);
        process.exit(1);
      }
      process.exit(0);
    });
  });
}
