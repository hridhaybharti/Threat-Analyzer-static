import {
  pgTable,
  serial,
  text,
  integer,
  jsonb,
  timestamp,
  boolean,
} from "drizzle-orm/pg-core";
import { z } from "zod";

/* =========================
   Heuristic Result (stored inside JSONB)
========================= */

export const heuristicResultSchema = z.object({
  name: z.string(),
  status: z.enum(["pass", "warn", "fail"]),
  description: z.string(),
  scoreImpact: z.number(),
  riskContribution: z.number().optional(),
  trustContribution: z.number().optional(),
});

export type HeuristicResult = z.infer<typeof heuristicResultSchema>;

/* =========================
   Analysis Details (JSONB)
========================= */

export const threatIntelligenceSchema = z.object({
  ipReputation: z.object({
    ip: z.string(),
    abuseConfidenceScore: z.number(),
    totalReports: z.number(),
    threats: z.array(z.string()),
    isp: z.string(),
    domain: z.string(),
    status: z.string().optional(),
  }).nullable(),
  abuseIPDB: z.object({
    ipAddress: z.string(),
    isPublic: z.boolean().optional(),
    isWhitelisted: z.boolean().optional(),
    abuseConfidenceScore: z.number(),
    totalReports: z.number(),
    countryCode: z.string().optional(),
    usageType: z.string().optional(),
    isp: z.string().optional(),
    domain: z.string().optional(),
    lastReportedAt: z.string().nullable().optional(),
  }).nullable().optional(),
  ipLocation: z.object({
    ip: z.string(),
    source: z.string(),
    city: z.string().optional(),
    region: z.string().optional(),
    country: z.string().optional(),
    countryCode: z.string().optional(),
    latitude: z.number().optional(),
    longitude: z.number().optional(),
    googleMapsUrl: z.string().optional(),
    accuracy: z.string().optional(),
    error: z.string().optional(),
  }).nullable().optional(),
  whoisData: z.object({
    domain: z.string(),
    registrationDate: z.string(),
    expirationDate: z.string(),
    ageInDays: z.number(),
    registrar: z.string(),
    nameServers: z.array(z.string()),
    isPrivate: z.boolean(),
    registrantCountry: z.string().optional(),
  }).nullable(),
  detectionEngines: z.array(z.object({
    engine: z.string(),
    category: z.string(),
    result: z.enum(["malicious", "suspicious", "clean", "undetected"]),
    lastAnalysisDate: z.string(),
  })),
  urlReputation: z.array(z.object({
    source: z.string(),
    riskScore: z.number(),
    confidence: z.number().optional(),
    details: z.string(),
    lastSeen: z.string().optional(),
    verdicts: z.array(z.string()).optional(),
  })),
  virusTotal: z.object({
    ok: z.boolean(),
    type: z.enum(["domain", "ip", "url"]),
    id: z.string().optional(),
    permalink: z.string().optional(),
    reputation: z.number().optional(),
    stats: z.object({
      malicious: z.number().optional(),
      suspicious: z.number().optional(),
      harmless: z.number().optional(),
      undetected: z.number().optional(),
      timeout: z.number().optional(),
    }).optional(),
    lastAnalysisDate: z.string().optional(),
    error: z.string().optional(),
  }).nullable().optional(),
  detectionSummary: z.object({
    maliciousCount: z.number(),
    suspiciousCount: z.number(),
    cleanCount: z.number(),
    totalEngines: z.number(),
  }).optional(),
});

export type ThreatIntelligence = z.infer<typeof threatIntelligenceSchema>;

export const analysisDetailsSchema = z.object({
  engine: z.string(),
  engineVersion: z.string(),
  confidence: z.number().min(0).max(100),
  evidence: z.array(heuristicResultSchema),
  heuristics: z.array(heuristicResultSchema).optional(),
  correlations: z.array(heuristicResultSchema).optional(),
  risk_contribution: z.number().optional(),
  trust_contribution: z.number().optional(),
  signal_count: z.number().optional(),
  threatIntelligence: threatIntelligenceSchema.optional(),
  metadata: z.object({
    inputType: z.enum(["ip", "domain", "url"]),
    sanitizedInput: z.string(),
    hasCorrelations: z.boolean(),
  }).optional(),
});

export type AnalysisDetails = z.infer<typeof analysisDetailsSchema>;

/* =========================
   Analyses Table (MATCHES DB)
========================= */

export const analyses = pgTable("analyses", {
  id: serial("id").primaryKey(),

  type: text("type").notNull(), // domain | ip | url
  input: text("input").notNull(),

  // ✅ REQUIRED legacy + UI fields
  riskScore: integer("risk_score").notNull(),
  riskLevel: text("risk_level").notNull(),

  summary: text("summary").notNull(),

  // 🔥 All modern intelligence lives here
  details: jsonb("details").$type<AnalysisDetails>().notNull(),

  createdAt: timestamp("created_at").defaultNow().notNull(),
  isFavorite: boolean("is_favorite").default(false),
});

/* =========================
   Types
========================= */

export type Analysis = typeof analyses.$inferSelect;
export type InsertAnalysis = typeof analyses.$inferInsert;
