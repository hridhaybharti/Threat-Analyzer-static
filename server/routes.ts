import type { Express } from "express";
import type { Server } from "http";
import { z } from "zod";

import { storage } from "./storage";
import { api } from "@shared/routes";

// 🔥 Evidence-based risk engine
import { analyzeInput } from "./analysis/analyzeInput";
import { reputationService } from "./analysis/reputation";
import { secretsManager } from "./utils/secrets";

/* =========================
   ROUTES (ENGINE-DRIVEN, DB-SAFE)
========================= */

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {

  /**
   * ENGINE STATUS & SECRETS (FOR DASHBOARD)
   */
  app.get("/api/reputation/status", (_req, res) => {
    res.json({
      reputation: reputationService.getStatus(),
      secrets: secretsManager.getStatus(),
    });
  });

  /**
   * ANALYZE INPUT
   */
  app.post(api.analyze.create.path, async (req, res) => {
    try {
      const bodySchema = z.object({
        type: z.enum(["domain", "ip", "url"]),
        value: z.string().optional(),
        input: z.string().optional(),
      });

      const parsed = bodySchema.parse(req.body);
      const actualInput = parsed.value ?? parsed.input;

      if (!actualInput) {
        return res.status(400).json({ message: "Required" });
      }

      // 🔥 Run risk engine
      const assessment = await analyzeInput(
        parsed.type,
        actualInput
      );

      /**
       * ✅ INSERT USING CAMELCASE ONLY
       * Drizzle maps this to snake_case automatically
       */
      const stored = await storage.createAnalysis({
        type: parsed.type,
        input: actualInput,

        // Legacy DB-required fields
        riskScore: assessment.riskScore,
        riskLevel: assessment.riskLevel,
        summary: assessment.summary || `Analysis complete. Risk level: ${assessment.riskLevel}.`,

        // 🔥 All new intelligence safely inside JSONB
        details: assessment.details,
      });

      /**
       * ✅ API RESPONSE (frontend-friendly)
       */
      return res.status(201).json({
        id: stored.id,
        type: stored.type,
        input: stored.input,
        riskScore: stored.riskScore,
        riskLevel: stored.riskLevel,
        summary: stored.summary,
        details: stored.details,
        createdAt: stored.createdAt,
        isFavorite: stored.isFavorite,
      });

    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({
          message: err.errors[0].message,
        });
      }

      console.error(err);
      return res.status(500).json({
        message: "Internal server error",
      });
    }
  });

  /**
   * HISTORY
   */
  app.get(api.history.list.path, async (_req, res) => {
    res.json(await storage.getHistory());
  });

  app.delete(api.history.clear.path, async (_req, res) => {
    await storage.clearHistory();
    res.status(204).send();
  });

  /**
   * GET ANALYSIS BY ID
   */
  app.get(api.analysis.get.path, async (req, res) => {
    const id = Number(req.params.id);
    if (Number.isNaN(id)) {
      return res.status(404).json({ message: "Invalid ID" });
    }

    const analysis = await storage.getAnalysis(id);
    if (!analysis) {
      return res.status(404).json({ message: "Analysis not found" });
    }

    res.json(analysis);
  });

  return httpServer;
}
