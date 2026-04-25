import "dotenv/config";
import { startServer } from "./app.js";

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

if (process.env.NODE_ENV !== "test") {
  startServer(PORT).catch((error) => {
    const message = error instanceof Error ? error.message : "Unknown startup error";
    console.error(`[Startup] ${message}`);
    process.exit(1);
  });
}
