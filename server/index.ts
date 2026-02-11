import "dotenv/config";
import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { serveStatic } from "./static";
import { createServer } from "http";

const app = express();
const httpServer = createServer(app);

// Extend IncomingMessage to store raw body
declare module "http" {
  interface IncomingMessage {
    rawBody: unknown;
  }
}

// Middleware to capture raw body (useful for webhooks, signatures, etc.)
app.use(
  express.json({
    verify: (req, _res, buf) => {
      (req as any).rawBody = buf;
    },
  }),
);

app.use(express.urlencoded({ extended: false }));

// Simple logger
export function log(message: string, source = "express") {
  const formattedTime = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });

  console.log(`${formattedTime} [${source}] ${message}`);
}

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined;

  const originalResJson = res.json.bind(res);
  res.json = (bodyJson: any) => {
    capturedJsonResponse = bodyJson;
    return originalResJson(bodyJson);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      log(logLine);
    }
  });

  next();
});

(async () => {
  // Register API routes
  await registerRoutes(httpServer, app);

  // Global error handler
  app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    console.error("Internal Server Error:", err);

    if (res.headersSent) {
      return next(err);
    }

    return res.status(status).json({ message });
  });

  // Setup frontend serving
  serveStatic(app);

  // -------------------------------
  // ✅ FIXED SERVER LISTEN (WINDOWS SAFE)
  // -------------------------------
  const basePort = parseInt(process.env.PORT || "5000", 10);
  let port = basePort;
  const maxAttempts = process.env.PORT ? 1 : 10; // if user explicitly set PORT, don't auto-hop
  const maxPort = basePort + (maxAttempts - 1);

  httpServer.on("error", (err: NodeJS.ErrnoException) => {
    if (err?.code === "EADDRINUSE") {
      if (port < maxPort) {
        const prev = port;
        port += 1;
        console.warn(`[express] port ${prev} in use, trying ${port}...`);
        setTimeout(() => {
          httpServer.listen(port, "127.0.0.1");
        }, 200);
        return;
      }

      console.error(
        `[express] Port ${port} is already in use. Stop the other process or set PORT to a free port.`,
      );
      process.exit(1);
    }

    console.error("[express] Server error:", err);
    process.exit(1);
  });

  httpServer.listen(port, "127.0.0.1", () => {
    log(`serving on http://localhost:${port}`);
  });
})();
