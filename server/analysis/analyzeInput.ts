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
import { osintService } from "./osint-engine";
import { archiveService } from "./archive-intel";
import { visualEngine } from "./visual-engine";
import { emailForensics } from "./email-forensics";
import { webhookService } from "../utils/webhooks";
import {
  lookupWhoisData,
  runDetectionEngines,
  checkURLReputation,
  type WhoisData,
  type DetectionEngineResult,
} from "./threat-intelligence";

export type InputType = "ip" | "domain" | "url" | "email";

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
 * Stage 2: Intelligence Gathering (Parallel OSINT v2)
 */
async function gatherIntelligence(type: InputType, target: string) {
  const intel: any = {
    ipReputation: null,
    abuseIPDB: null,
    ipLocation: null,
    whoisData: null,
    virusTotal: null,
    urlScan: null,
    archiveHistory: null,
    visualCapture: null,
    emailIntel: null,
    detectionEngines: [],
    urlIntelligence: []
  };

  const tasks: Promise<void>[] = [];

  try {
    if (type === "ip") {
      tasks.push(osintService.getAbuseIPDB(target).then(res => { intel.abuseIPDB = res; }).catch(e => console.error("[OSINT] AbuseIPDB failed:", e.message)));
      tasks.push(osintService.getVirusTotal(target, "ip").then(res => { intel.virusTotal = res; }).catch(e => console.error("[OSINT] VirusTotal failed:", e.message)));
      tasks.push(osintService.getIPLocation(target).then(res => { intel.ipLocation = res; }).catch(e => console.error("[OSINT] IPLocation failed:", e.message)));
      tasks.push(runDetectionEngines(target).then(res => { intel.detectionEngines = res; }).catch(e => console.error("[OSINT] Engines failed:", e.message)));
    } else if (type === "domain" || type === "url") {
      const hostname = type === "url" ? new URL(target.startsWith('http') ? target : `https://${target}`).hostname : target;

      tasks.push(lookupWhoisData(hostname).then(res => { intel.whoisData = res; }).catch(e => console.error("[OSINT] WHOIS failed:", e.message)));
      tasks.push(osintService.getVirusTotal(hostname, type === "url" ? "url" : "domain").then(res => { intel.virusTotal = res; }).catch(e => console.error("[OSINT] VirusTotal failed:", e.message)));
      tasks.push(checkURLReputation(hostname).then(res => { intel.urlIntelligence = res; }).catch(e => console.error("[OSINT] URL Reputation failed:", e.message)));
      tasks.push(runDetectionEngines(hostname).then(res => { intel.detectionEngines = res; }).catch(e => console.error("[OSINT] Engines failed:", e.message)));
      tasks.push(archiveService.getHistory(hostname).then(res => { intel.archiveHistory = res; }).catch(e => console.error("[OSINT] Archive failed:", e.message)));
      
      if (type === "url") {
        tasks.push(osintService.getURLScan(target).then(res => { intel.urlScan = res; }).catch(e => console.error("[OSINT] URLScan failed:", e.message)));
        // Background visual capture (best effort)
        const captureId = Buffer.from(target).toString('hex').substring(0, 12);
        tasks.push(visualEngine.captureSafeScreenshot(target, captureId).then(res => { intel.visualCapture = res; }).catch(e => console.error("[OSINT] Visual Capture failed:", e.message)));
      }
    } else if (type === "email") {
      const headers = emailForensics.parseHeaders(target);
      const links = emailForensics.extractLinks(target);
      intel.emailIntel = { headers, links };

      // Run intel on the primary origin IP
      if (headers.received.length > 0) {
        const originIP = headers.received[0];
        tasks.push(osintService.getAbuseIPDB(originIP).then(res => { intel.abuseIPDB = res; }).catch(e => console.error("[OSINT] Email IP lookup failed:", e.message)));
        tasks.push(osintService.getIPLocation(originIP).then(res => { intel.ipLocation = res; }).catch(e => console.error("[OSINT] Email Geo lookup failed:", e.message)));
      }
    }
  } catch (globalError: any) {
    console.error("[Intelligence Gathering] Critical stage failure:", globalError.message);
  }

  // Optimized timeout: 12s for deep OSINT
  await Promise.race([
    Promise.allSettled(tasks),
    new Promise(resolve => setTimeout(resolve, 12000))
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

    // 🔥 Wayback Machine Archive Analysis
    const archiveSignal = await archiveService.getMaturitySignal(targetHostname);
    if (archiveSignal) {
      evidence.push(archiveSignal);
      score += archiveSignal.scoreImpact;
    }

    // 🔥 Visual Behavior Heuristics
    if (type === "url" && intel.visualCapture) {
      const visualSignals = visualEngine.getVisualHeuristics(intel.visualCapture);
      for (const signal of visualSignals) {
        evidence.push(signal);
        score += signal.scoreImpact;
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

  if (type === "email" && intel.emailIntel) {
    const socEngSignal = emailForensics.getSocialEngineeringSignal(input);
    if (socEngSignal) {
      evidence.push(socEngSignal);
      score += socEngSignal.scoreImpact;
    }

    const authSignal = emailForensics.getAuthSignal(intel.emailIntel.headers.authentication);
    if (authSignal) {
      evidence.push(authSignal);
      score += authSignal.scoreImpact;
    }
  }

  // 4. Scoring & Final Verdict
  const { newEvidence, scoreBoost } = applyCorrelations(evidence, { input, type });
  score = Math.min(100, Math.max(0, score + scoreBoost));

  let riskLevel = "Safe";
  if (score >= 70) riskLevel = "Malicious";
  else if (score >= 30) riskLevel = "Suspicious";

  const finalEvidence = newEvidence.map(e => ({ ...e, status: e.status as "pass" | "warn" | "fail" }));

  console.log(`[analyzeInput] Pipeline complete in ${Date.now() - startAt}ms. Score: ${score}`);

  const confidence = Math.round((finalEvidence.filter(e => e.status !== "pass").length / Math.max(finalEvidence.length, 1)) * 100);

  const resultObj = {
    riskScore: score,
    riskLevel,
    confidence,
    evidence: finalEvidence,
    details: {
      engine: "ThreatAnalyzer",
      engineVersion: "2.1.0-optimized",
      confidence,
      evidence: finalEvidence, // Matches required field
      heuristics: finalEvidence, // Optional field
      threatIntelligence: intel,
      metadata: {
        inputType: type,
        sanitizedInput: input,
        hasCorrelations: true,
        processingTimeMs: Date.now() - startAt
      }
    },
    summary: `Analysis complete. Verdict: ${riskLevel}`
  };

  // 🔥 Trigger Webhook for High Risk Threats (Background)
  // We mock a temporary analysis object for the webhook
  if (score >= 70) {
    webhookService.notifyHighRisk({ 
      id: 0, 
      input, 
      type, 
      riskScore: score, 
      riskLevel, 
      summary: resultObj.summary, 
      details: resultObj.details as any, 
      createdAt: new Date(), 
      isFavorite: false 
    }).catch(() => {});
  }

  return resultObj;
}
