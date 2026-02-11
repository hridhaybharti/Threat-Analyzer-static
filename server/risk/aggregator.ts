// server/risk/aggregator.ts

import { Evidence, RiskAssessment } from "./types";

/**
 * Evidence-based risk aggregation.
 * Open-world safe by design.
 */
export function aggregateRisk(evidence: Evidence[]): RiskAssessment {
  let maliciousScore = 0;
  let benignScore = 0;

  for (const ev of evidence) {
    if (ev.direction === "malicious") {
      maliciousScore += ev.confidence;
    } else {
      benignScore += ev.confidence;
    }
  }

  // Net risk balances contradiction
  const netRisk = maliciousScore - benignScore;

  // Confidence grows with amount of evidence, not direction
  const confidence = Math.min(
    (maliciousScore + benignScore) / 3, // soft cap
    1
  );

  let riskLevel: RiskAssessment["riskLevel"] = "Uncertain";

  if (netRisk >= 0.7) riskLevel = "Malicious";
  else if (netRisk >= 0.3) riskLevel = "Suspicious";
  else if (netRisk <= -0.7) riskLevel = "Safe";
  else if (netRisk <= -0.3) riskLevel = "Likely Safe";

  return {
    riskLevel,
    confidence: Number(confidence.toFixed(2)),
    maliciousScore: Number(maliciousScore.toFixed(2)),
    benignScore: Number(benignScore.toFixed(2)),
    evidence,
  };
}
