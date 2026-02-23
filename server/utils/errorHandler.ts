import { type Request, Response, NextFunction } from "express";
import { ZodError } from "zod";

/**
 * Enhanced Error Handler
 * Cinematic, informative, and safe.
 */
export function globalErrorHandler(
  err: any, 
  _req: Request, 
  res: Response, 
  _next: NextFunction
) {
  // Capture basic error stats
  const status = err.status || err.statusCode || 500;
  const message = err.message || "Internal Server Error";
  const code = err.code || "ERR_GENERIC";

  // Detailed logging in server console
  console.error(`\x1b[31m[Critical Error]\x1b[0m ${new Date().toISOString()}`);
  console.error(`- Code: ${code}`);
  console.error(`- Status: ${status}`);
  console.error(`- Message: ${message}`);
  if (err.stack && process.env.NODE_ENV !== "production") {
    console.error(err.stack);
  }

  // Handle Validation Errors specifically (Zod)
  if (err instanceof ZodError) {
    return res.status(400).json({
      error: "Validation Failed",
      details: err.errors.map(e => ({
        path: e.path.join("."),
        message: e.message
      })),
      code: "ERR_VALIDATION"
    });
  }

  // Handle common database errors
  if (code === "23505") { // Unique violation
    return res.status(409).json({
      error: "Conflict",
      message: "This resource already exists.",
      code: "ERR_DUPLICATE"
    });
  }

  // Handle rate limits (handled by middleware but just in case)
  if (status === 429) {
    return res.status(429).json({
      error: "Rate Limit Exceeded",
      message: "Slow down, partner. Too many requests.",
      code: "ERR_RATE_LIMIT"
    });
  }

  // Default Cinematic Error Response
  res.status(status).json({
    error: status >= 500 ? "Internal Engine Failure" : "Request Refused",
    message: message,
    code: code,
    timestamp: new Date().toISOString()
  });
}
