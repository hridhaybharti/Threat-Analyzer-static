import { HeuristicResult } from "@shared/schema";
import { analyzeIP } from "../analyzers/ip";
import { analyzeDomain } from "../analyzers/domain";
import { analyzeURL } from "../analyzers/url";
import { applyCorrelations } from "../risk/correlation";
import { sanitizeInput } from "./sanitization";
import { analyzeObfuscation } from "./obfuscation";
import { analyzeIDNDomain } from "./idn";
import { analyzeURLPath } from "./path-analysis";
import { analyzePort } from "./port-analysis";
import { analyzeDomainReputation } from "./domain-reputation";
import { analyzeRedirects } from "./redirect-analysis";
import { analyzeMobileThreats } from "./mobile-threats";
import { reputationService } from "./reputation";
import { analyzeHomoglyphs } from "./homoglyph";
import {
  checkIPReputation,
  checkAbuseIPDB,
  checkURLReputation,
  lookupWhoisData,
  lookupIPLocation,
  lookupVirusTotalDomain,
  lookupVirusTotalIP,
  lookupVirusTotalUrl,
  runDetectionEngines,
  type AbuseIPDBReport,
  type IPReputation,
  type IPLocation,
  type VirusTotalReport,
  type WhoisData,
  type DetectionEngineResult,
} from "./threat-intelligence";

export type InputType = "ip" | "domain" | "url";

/**
 * Stage 1: Pre-processing & Sanitization
 */
function preprocess(input: string) {
  const sanitization = sanitizeInput(input);
  const obfuscation = analyzeObfuscation(sanitization.sanitized);
  const analyzedInput = obfuscation.obfuscationLevel === "high" ? obfuscation.decodedContent : sanitization.sanitized;
  
  return {
    analyzedInput,
    heuristics: [...sanitization.heuristics, ...obfuscation.heuristics]
  };
}

/**
 * Stage 2: Intelligence Gathering (Parallel)
 */
async function gatherIntelligence(type: InputType, target: string) {
  const intel: any = {
    ipReputation: null,
    abuseIPDB: null,
    ipLocation: null,
    whoisData: null,
    virusTotal: null,
    detectionEngines: [],
    urlIntelligence: []
  };

  const tasks: Promise<void>[] = [];

  if (type === "ip") {
    tasks.push(checkIPReputation(target).then(res => intel.ipReputation = res).catch(() => {}));
    tasks.push(checkAbuseIPDB(target).then(res => intel.abuseIPDB = res).catch(() => {}));
    tasks.push(lookupVirusTotalIP(target).then(res => intel.virusTotal = res).catch(() => {}));
    tasks.push(lookupIPLocation(target).then(res => intel.ipLocation = res).catch(() => {}));
    tasks.push(runDetectionEngines(target).then(res => intel.detectionEngines = res).catch(() => {}));
  } else if (type === "domain" || type === "url") {
    const hostname = type === "url" ? new URL(target.startsWith('http') ? target : `https://${target}`).hostname : target;
    
    tasks.push(lookupWhoisData(hostname).then(res => intel.whoisData = res).catch(() => {}));
    tasks.push(checkURLReputation(hostname).then(res => intel.urlIntelligence = res).catch(() => {}));
    tasks.push(runDetectionEngines(hostname).then(res => intel.detectionEngines = res).catch(() => {}));
    
    if (type === "domain") {
      tasks.push(lookupVirusTotalDomain(hostname).then(res => intel.virusTotal = res).catch(() => {}));
    } else {
      tasks.push(lookupVirusTotalUrl(target).then(res => intel.virusTotal = res).catch(() => {}));
    }
  }

  // Wait for all intel tasks with an 8s timeout budget for the whole stage
  await Promise.race([
    Promise.allSettled(tasks),
    new Promise(resolve => setTimeout(resolve, 8000))
  ]);

  return intel;
}

/**
 * Main Analysis Pipeline
 */
export async function analyzeInput(type: InputType, input: string) {
  const startAt = Date.now();
  console.log(`[analyzeInput] Pipeline started for ${type}: ${input}`);

  // 1. Preprocess
  const { analyzedInput, heuristics: baseHeuristics } = preprocess(input);
  const evidence: HeuristicResult[] = [...baseHeuristics];

  // 2. Intelligence Gathering
  const intel = await gatherIntelligence(type, analyzedInput);

  // 3. Execution
  let score = evidence.reduce((sum, h) => sum + h.scoreImpact, 0);
  
  if (type === "ip") {
    const r = await analyzeIP(analyzedInput);
    score += r.score;
    evidence.push(...r.heuristics);

    if (intel.ipReputation?.abuseConfidenceScore > 25) {
      const impact = Math.floor(intel.ipReputation.abuseConfidenceScore / 2);
      score += impact;
      evidence.push({
        name: "IP Reputation Score",
        status: intel.ipReputation.abuseConfidenceScore > 75 ? "fail" : "warn",
        description: `IP has abuse confidence score of ${intel.ipReputation.abuseConfidenceScore}%`,
        scoreImpact: impact,
      });
    }
  }

  if (type === "domain" || type === "url") {
    const targetHostname = type === "url" ? new URL(analyzedInput.startsWith('http') ? analyzedInput : `https://${analyzedInput}`).hostname : analyzedInput;
    
    // Core Domain Heuristics
    evidence.push(...analyzeIDNDomain(targetHostname).heuristics);
    evidence.push(...analyzeDomainReputation(targetHostname).heuristics);
    
    // Reputation & Homoglyph (The "Perfected" logic)
    const repSignal = reputationService.getReputationSignal(targetHostname);
    if (repSignal) {
      evidence.push(repSignal);
      score += repSignal.scoreImpact;
    }

    const homoglyphSignal = analyzeHomoglyphs(targetHostname);
    if (homoglyphSignal && !repSignal) {
      evidence.push(homoglyphSignal);
      score += homoglyphSignal.scoreImpact;
    }

    const domainR = await analyzeDomain(targetHostname);
    score += domainR.score;
    evidence.push(...domainR.heuristics);

    if (intel.whoisData) {
      if (intel.whoisData.age < 30) {
        score += 35;
        evidence.push({ name: "Very New Domain", status: "fail", description: `Registered ${intel.whoisData.age} days ago`, scoreImpact: 35 });
      }
    }
  }

  if (type === "url") {
    const urlObj = new URL(analyzedInput.startsWith('http') ? analyzedInput : `https://${analyzedInput}`);
    score += (await analyzeURL(analyzedInput)).score;
    evidence.push(...analyzeURLPath(urlObj.pathname, urlObj.search).heuristics);
    evidence.push(...analyzePort(urlObj).heuristics);
    evidence.push(...analyzeRedirects(urlObj).heuristics);
    evidence.push(...analyzeMobileThreats(urlObj).heuristics);
  }

  // 4. Scoring & Final Verdict
  const { newEvidence, scoreBoost } = applyCorrelations(evidence, { input, type });
  score = Math.min(100, Math.max(0, score + scoreBoost));

  let riskLevel = "Safe";
  if (score >= 70) riskLevel = "Malicious";
  else if (score >= 30) riskLevel = "Suspicious";

  const finalEvidence = newEvidence.map(e => ({ ...e, status: e.status as "pass" | "warn" | "fail" }));

  console.log(`[analyzeInput] Pipeline complete in ${Date.now() - startAt}ms. Score: ${score}`);

  return {
    riskScore: score,
    riskLevel,
    confidence: Math.round((finalEvidence.filter(e => e.status !== "pass").length / Math.max(finalEvidence.length, 1)) * 100),
    evidence: finalEvidence,
    details: {
      engine: "ThreatAnalyzer v2.1 (Optimized)",
      heuristics: finalEvidence,
      threatIntelligence: intel,
      metadata: { inputType: type, processingTimeMs: Date.now() - startAt }
    },
    summary: `Analysis complete. Verdict: ${riskLevel}`
  };
}
