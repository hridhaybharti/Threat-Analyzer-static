// server/risk/types.ts

export type EvidenceDirection = "benign" | "malicious";

export type EvidenceSource =
  | "heuristic"
  | "external"
  | "context"
  | "user";

/**
 * A single interpreted signal.
 * Evidence never decides risk alone.
 */
export interface Evidence {
  signal: string;          // e.g. "suspicious_tld"
  direction: EvidenceDirection;
  confidence: number;      // 0.0 – 1.0
  explanation: string;     // human-readable
  source: EvidenceSource;
}

/**
 * Final risk assessment returned by engine
 */
export interface RiskAssessment {
  riskLevel:
    | "Safe"
    | "Likely Safe"
    | "Uncertain"
    | "Suspicious"
    | "Malicious";

  confidence: number;      // overall confidence (0–1)
  maliciousScore: number; // aggregated
  benignScore: number;    // aggregated
  evidence: Evidence[];
}
