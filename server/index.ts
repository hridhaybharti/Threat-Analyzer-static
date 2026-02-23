import "dotenv/config";
import express from "express";
import { registerRoutes } from "./routes";
import { serveStatic } from "./static";
import { setupVite } from "./vite";
import { createServer } from "http";
import { reputationService } from "./analysis/reputation";
import { globalErrorHandler } from "./utils/errorHandler";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const app = express();

// Production Security Hardening
app.use(helmet({
  contentSecurityPolicy: false, 
}));

// API Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { 
    error: "Rate Limit Exceeded",
    message: "Too many requests from this IP, please try again after 15 minutes",
    code: "ERR_RATE_LIMIT"
  }
});

app.use("/api/", limiter);

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
  // Initialize Reputation Service (Background Sync)
  reputationService.init().catch(err => {
    console.error("[Startup] ReputationService init failed:", err);
  });

  // Register API routes
  await registerRoutes(httpServer, app);

  // Global error handler (Must be after routes)
  app.use(globalErrorHandler);

  // Setup frontend serving
  if (app.get("env") === "development") {
    await setupVite(httpServer, app);
  } else {
    serveStatic(app);
  }

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
