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

export async function analyzeInput(type: InputType, input: string) {
  console.log(`[analyzeInput] start type=${type} input=${input}`);
  let score = 0;
  const evidence: HeuristicResult[] = [];
  let url: URL | undefined;

  // Threat Intelligence Data
  let ipReputation: IPReputation | null = null;
  let abuseIPDB: AbuseIPDBReport | null = null;
  let ipLocation: IPLocation | null = null;
  let whoisData: WhoisData | null = null;
  let detectionEngines: DetectionEngineResult[] = [];
  let urlIntelligence: any[] = [];
  let virusTotal: VirusTotalReport | null = null;

  // 1. Input Sanitization - First line of defense
  const sanitization = sanitizeInput(input);
  evidence.push(...sanitization.heuristics);
  const sanitizedInput = sanitization.sanitized;
  score += sanitization.heuristics.reduce((sum, h) => sum + h.scoreImpact, 0);

  // 2. Obfuscation Analysis
  const obfuscation = analyzeObfuscation(sanitizedInput);
  evidence.push(...obfuscation.heuristics);
  let analyzedInput = obfuscation.obfuscationLevel === "high" ? obfuscation.decodedContent : sanitizedInput;
  score += obfuscation.heuristics.reduce((sum, h) => sum + h.scoreImpact, 0);

  // Type-specific analysis
  if (type === "ip") {
    const r = await analyzeIP(analyzedInput);
    score += r.score;
    evidence.push(...r.heuristics);

    // 🔥 Check IP Reputation (abuse.ipdb style)
    try {
      ipReputation = await checkIPReputation(analyzedInput);
    } catch (err) {
      console.error("[analyzeInput] checkIPReputation failed:", err);
      ipReputation = null;
    }

    // 🔥 AbuseIPDB (raw payload for UI, if configured)
    try {
      abuseIPDB = await checkAbuseIPDB(analyzedInput);
    } catch (err) {
      console.error("[analyzeInput] checkAbuseIPDB failed:", err);
      abuseIPDB = null;
    }

    // 🔥 VirusTotal (IP, if configured)
    try {
      virusTotal = await lookupVirusTotalIP(analyzedInput);
    } catch (err) {
      console.error("[analyzeInput] lookupVirusTotalIP failed:", err);
      virusTotal = null;
    }

    // 🔥 IP Location (best-effort)
    try {
      ipLocation = await lookupIPLocation(analyzedInput);
    } catch (err) {
      console.error("[analyzeInput] lookupIPLocation failed:", err);
      ipLocation = null;
    }

    if (ipReputation && ipReputation.abuseConfidenceScore > 25) {
      score += Math.floor(ipReputation.abuseConfidenceScore / 2);
      evidence.push({
        name: "IP Reputation Score",
        status: ipReputation.abuseConfidenceScore > 75 ? "fail" : "warn",
        description: `IP has abuse confidence score of ${ipReputation.abuseConfidenceScore}% with ${ipReputation.totalReports} reports`,
        scoreImpact: Math.floor(ipReputation.abuseConfidenceScore / 2),
      });
    }

    if (virusTotal?.ok && virusTotal.stats) {
      const malicious = Number(virusTotal.stats.malicious || 0);
      const suspicious = Number(virusTotal.stats.suspicious || 0);
      const vtImpact = Math.min(45, malicious * 18 + suspicious * 9);

      if (vtImpact > 0) {
        score += vtImpact;
        evidence.push({
          name: "VirusTotal Detections",
          status: malicious > 0 ? "fail" : "warn",
          description: `VirusTotal reports ${malicious} malicious and ${suspicious} suspicious detections`,
          scoreImpact: vtImpact,
        });
      }
    }

    // Run detection engines
    try {
      detectionEngines = await runDetectionEngines(analyzedInput);
    } catch (err) {
      console.error("[analyzeInput] runDetectionEngines failed:", err);
      detectionEngines = [];
    }
  }

  if (type === "domain") {
    // IDN Analysis
    const idnAnalysis = analyzeIDNDomain(analyzedInput);
    evidence.push(...idnAnalysis.heuristics);
    score += idnAnalysis.heuristics.reduce((sum, h) => sum + h.scoreImpact, 0);

    // Domain Reputation Analysis
    const reputationAnalysis = analyzeDomainReputation(analyzedInput);
    evidence.push(...reputationAnalysis.heuristics);
    score += reputationAnalysis.heuristics.reduce((sum, h) => sum + h.scoreImpact, 0);

    // 🔥 WHOIS Lookup
    try {
      whoisData = await lookupWhoisData(analyzedInput);
    } catch (err) {
      console.error("[analyzeInput] lookupWhoisData failed:", err);
      whoisData = null;
    }

    // 🔥 VirusTotal (Domain, if configured)
    try {
      virusTotal = await lookupVirusTotalDomain(analyzedInput);
    } catch (err) {
      console.error("[analyzeInput] lookupVirusTotalDomain failed:", err);
      virusTotal = null;
    }

    if (whoisData) {
      if (whoisData.age < 30) {
        score += 35;
        evidence.push({
          name: "Very New Domain",
          status: "fail",
          description: `Domain registered only ${whoisData.age} days ago`,
          scoreImpact: 35,
        });
      }
      if (whoisData.isPrivate) {
        score += 15;
        evidence.push({
          name: "Private Registration",
          status: "warn",
          description: "Domain uses private registration (common in phishing)",
          scoreImpact: 15,
        });
      }
    }

    if (virusTotal?.ok && virusTotal.stats) {
      const malicious = Number(virusTotal.stats.malicious || 0);
      const suspicious = Number(virusTotal.stats.suspicious || 0);
      const vtImpact = Math.min(45, malicious * 18 + suspicious * 9);

      if (vtImpact > 0) {
        score += vtImpact;
        evidence.push({
          name: "VirusTotal Detections",
          status: malicious > 0 ? "fail" : "warn",
          description: `VirusTotal reports ${malicious} malicious and ${suspicious} suspicious detections`,
          scoreImpact: vtImpact,
        });
      }
    }

    // 🔥 URL Threat Intelligence
    try {
      urlIntelligence = await checkURLReputation(analyzedInput);
    } catch (err) {
      console.error("[analyzeInput] checkURLReputation failed:", err);
      urlIntelligence = [];
    }
    for (const intel of urlIntelligence) {
      if (intel.riskScore > 50) {
        score += intel.riskScore / 2;
        evidence.push({
          name: `${intel.source} Detection`,
          status: "fail",
          description: `${intel.source}: ${intel.details}`,
          scoreImpact: Math.floor(intel.riskScore / 2),
        });
      }
    }

    // Run detection engines
    try {
      detectionEngines = await runDetectionEngines(analyzedInput);
    } catch (err) {
      console.error("[analyzeInput] runDetectionEngines failed:", err);
      detectionEngines = [];
    }

    // Standard Domain Analysis
    const r = await analyzeDomain(analyzedInput);
    score += r.score;
    evidence.push(...r.heuristics);
  }

  if (type === "url") {
    // Safe URL parsing for detailed analysis
    try {
      let urlToParse = analyzedInput;
      if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(urlToParse)) {
        urlToParse = "https://" + urlToParse;
      }
      url = new URL(urlToParse);

      // URL Analysis
      const urlR = await analyzeURL(analyzedInput);
      score += urlR.score;
      evidence.push(...urlR.heuristics);

      // Path Analysis
      const pathAnalysis = analyzeURLPath(url.pathname, url.search);
      evidence.push(...pathAnalysis.heuristics);
      score += pathAnalysis.heuristics.reduce((sum, h) => sum + h.scoreImpact, 0);

      // Port Analysis
      const portAnalysis = analyzePort(url);
      evidence.push(...portAnalysis.heuristics);
      score += portAnalysis.heuristics.reduce((sum, h) => sum + h.scoreImpact, 0);

      // Redirect Analysis
      const redirectAnalysis = analyzeRedirects(url);
      evidence.push(...redirectAnalysis.heuristics);
      score += redirectAnalysis.heuristics.reduce((sum, h) => sum + h.scoreImpact, 0);

      // Mobile Threats Analysis
      const mobileAnalysis = analyzeMobileThreats(url);
      evidence.push(...mobileAnalysis.heuristics);
      score += mobileAnalysis.heuristics.reduce((sum, h) => sum + h.scoreImpact, 0);

      // Domain Analysis (including IDN and reputation)
      const idnAnalysis = analyzeIDNDomain(url.hostname);
      evidence.push(...idnAnalysis.heuristics);
      score += idnAnalysis.heuristics.reduce((sum, h) => sum + h.scoreImpact, 0);

      const reputationAnalysis = analyzeDomainReputation(url.hostname);
      evidence.push(...reputationAnalysis.heuristics);
      score += reputationAnalysis.heuristics.reduce((sum, h) => sum + h.scoreImpact, 0);

      const domainR = await analyzeDomain(url.hostname);
      score += domainR.score;
      evidence.push(...domainR.heuristics);

      // 🔥 Get threat intelligence for URL/domain
      try {
        whoisData = await lookupWhoisData(url.hostname);
      } catch (err) {
        console.error("[analyzeInput] lookupWhoisData (url) failed:", err);
        whoisData = null;
      }
      try {
        const urlIntel = await checkURLReputation(url.hostname);
        urlIntelligence.push(...urlIntel);
      } catch (err) {
        console.error("[analyzeInput] checkURLReputation (url) failed:", err);
      }
      try {
        virusTotal = await lookupVirusTotalUrl(analyzedInput);
      } catch (err) {
        console.error("[analyzeInput] lookupVirusTotalUrl failed:", err);
        virusTotal = null;
      }

      if (virusTotal?.ok && virusTotal.stats) {
        const malicious = Number(virusTotal.stats.malicious || 0);
        const suspicious = Number(virusTotal.stats.suspicious || 0);
        const vtImpact = Math.min(45, malicious * 18 + suspicious * 9);

        if (vtImpact > 0) {
          score += vtImpact;
          evidence.push({
            name: "VirusTotal Detections",
            status: malicious > 0 ? "fail" : "warn",
            description: `VirusTotal reports ${malicious} malicious and ${suspicious} suspicious detections`,
            scoreImpact: vtImpact,
          });
        }
      }
      try {
        detectionEngines = await runDetectionEngines(url.hostname);
      } catch (err) {
        console.error("[analyzeInput] runDetectionEngines (url) failed:", err);
        detectionEngines = [];
      }

    } catch {
      evidence.push({
        name: "URL Parsing Failed",
        status: "fail" as const,
        description: "Failed to parse URL for detailed analysis",
        scoreImpact: 40,
      });
      score += 40;
    }
  }

  // Apply correlations for pattern-based amplification
  const context = { input, type, url };
  const { newEvidence, scoreBoost } = applyCorrelations(evidence, context);
  
  score += scoreBoost;
  score = Math.min(100, Math.max(0, score)); // Normalize 0-100

  // Final verdict based on correlation patterns, not just score
  const hasCorrelations = newEvidence.some(e => 
    e.name.includes("Pattern") || e.name.includes("Correlation") || e.name.includes("Multiple")
  );
  
  const hasCriticalBrand = newEvidence.some(e => 
    e.name === "Brand Impersonation" && e.description.includes("critical")
  );
  
  // Enhanced verdict logic with correlation authority
  let riskLevel = "Safe";
  if (score >= 70 || (hasCorrelations && score >= 50) || hasCriticalBrand) {
    riskLevel = "Malicious";
  } else if (score >= 30 || hasCorrelations) {
    riskLevel = "Suspicious";
  }

  // Final evidence normalization
  const finalEvidence = newEvidence.map(e => ({
    ...e,
    status: e.status as "pass" | "warn" | "fail"
  }));

  // Extract correlation evidence for detailed storage
  const correlationEvidence = finalEvidence.filter(e => 
    e.name.includes("Pattern") || e.name.includes("Correlation") || e.name.includes("Multiple")
  );

  // Generate summary based on patterns
  const summary = hasCorrelations 
    ? `Multiple threat patterns detected - correlation analysis indicates ${riskLevel.toLowerCase()} activity`
    : hasCriticalBrand
    ? `Critical brand impersonation detected - high confidence ${riskLevel.toLowerCase()} threat`
    : `Structural analysis indicates ${riskLevel.toLowerCase()} risk level`;

  const result = {
    riskScore: score,
    riskLevel,
    confidence: Math.round(
      (finalEvidence.filter(e => e.status !== "pass").length / Math.max(finalEvidence.length, 1)) * 100
    ),
    evidence: finalEvidence,
    details: {
      engine: "ThreatAnalyzer v2.0",
      engineVersion: "2.0.0",
      confidence: Math.round(
        (finalEvidence.filter(e => e.status !== "pass").length / Math.max(finalEvidence.length, 1)) * 100
      ),
      evidence: finalEvidence,
      heuristics: finalEvidence,
      correlations: correlationEvidence,
      signal_count: finalEvidence.length,
      risk_contribution: finalEvidence.filter(e => e.scoreImpact > 0).reduce((sum, e) => sum + e.scoreImpact, 0),
      trust_contribution: finalEvidence.filter(e => e.scoreImpact < 0).reduce((sum, e) => sum + Math.abs(e.scoreImpact), 0),
      // 🔥 THREAT INTELLIGENCE DATA - VirusTotal-style
      threatIntelligence: {
        ipReputation: ipReputation ? {
          ip: analyzedInput,
          abuseConfidenceScore: ipReputation.abuseConfidenceScore,
          totalReports: ipReputation.totalReports,
          threats: ipReputation.threats,
          isp: ipReputation.isp,
          domain: ipReputation.domain,
          status: ipReputation.abuseConfidenceScore > 25 ? "Malicious" : "Clean",
        } : null,
        abuseIPDB: abuseIPDB ? { ...abuseIPDB } : null,
        ipLocation: ipLocation ? { ...ipLocation } : null,
        whoisData: whoisData ? {
          domain: analyzedInput,
          registrationDate: whoisData.registrationDate,
          expirationDate: whoisData.expirationDate,
          ageInDays: whoisData.age,
          registrar: whoisData.registrar,
          nameServers: whoisData.nameServers,
          isPrivate: whoisData.isPrivate,
        } : null,
        detectionEngines: detectionEngines.map(e => ({
          engine: e.engine,
          category: e.category,
          result: e.result,
          lastAnalysisDate: e.lastAnalysisDate,
        })),
        urlReputation: urlIntelligence,
        virusTotal: virusTotal ? { ...virusTotal } : null,
        detectionSummary: {
          maliciousCount: detectionEngines.filter(e => e.result === "malicious").length,
          suspiciousCount: detectionEngines.filter(e => e.result === "suspicious").length,
          cleanCount: detectionEngines.filter(e => e.result === "clean").length,
          totalEngines: detectionEngines.length,
        }
      },
      metadata: {
        inputType: type,
        sanitizedInput: input,
        hasCorrelations,
      }
    },
    summary,
  };

  try {
    console.log("[analyzeInput] returning details.threatIntelligence present=", !!result.details?.threatIntelligence);
  } catch (e) {
    console.error("[analyzeInput] logging result failed:", e);
  }

  return result;
}
