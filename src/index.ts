import "dotenv/config";
import { startServer } from "./app.js";
import { logger } from "./utils/logger.js";
import { secretLoader } from "./utils/secret-loader.js";

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

async function bootstrap(): Promise<void> {
  await secretLoader.reload();
  await startServer(PORT);
}

process.on("SIGHUP", async () => {
  logger.info({ event: 'secret_reload_requested', key: 'all' });

  try {
    await secretLoader.reload();
    logger.info({ event: 'secret_reload_succeeded', key: 'all' });
  } catch (error) {
    logger.error({ event: 'secret_reload_failed', key: 'all', error: error instanceof Error ? error.message : String(error) });
  }
});

if (process.env.NODE_ENV !== "test") {
  bootstrap().catch((error) => {
    const message = error instanceof Error ? error.message : "Unknown startup error";
    console.error(`[Startup] ${message}`);
    process.exit(1);
  });
}

