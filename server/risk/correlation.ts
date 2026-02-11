import { HeuristicResult } from "@shared/schema";

interface CorrelationPattern {
  name: string;
  description: string;
  check: (evidence: HeuristicResult[], context: any) => boolean;
  scoreBoost: number;
}

export function applyCorrelations(
  evidence: HeuristicResult[], 
  context: { input: string; type: string; url?: URL }
): { newEvidence: HeuristicResult[], scoreBoost: number } {
  const newEvidence: HeuristicResult[] = [...evidence];
  let scoreBoost = 0;

  // Original Patterns (Enhanced)
  
  // Pattern 1: Brand impersonation + login/credential keywords
  if (
    evidence.some(e => e.name === "Brand Impersonation") &&
    evidence.some(e => e.name === "Keyword Analysis")
  ) {
    newEvidence.push({
      name: "Brand Impersonation + Credential Pattern",
      status: "fail" as const,
      description: "Brand impersonation combined with credential-related keywords indicates phishing",
      scoreImpact: 30,
    });
    scoreBoost += 30;
  }

  // Pattern 2: IP-based URL + hosting context
  if (
    context.url?.hostname && /^\d{1,3}(\.\d{1,3}){3}$/.test(context.url.hostname) &&
    evidence.some(e => e.name === "Hosting Provider Context")
  ) {
    newEvidence.push({
      name: "IP-based URL + Hosting Pattern",
      status: "fail" as const, 
      description: "Direct IP URL with hosting infrastructure indicates advanced obfuscation",
      scoreImpact: 25,
    });
    scoreBoost += 25;
  }

  // Pattern 3: Suspicious TLD + credential path
  if (
    evidence.some(e => e.name === "TLD Reputation" && e.status === "fail") &&
    evidence.some(e => e.name === "Keyword Analysis")
  ) {
    newEvidence.push({
      name: "Suspicious TLD + Credential Pattern",
      status: "fail" as const,
      description: "Abused TLD combined with credential keywords indicates targeted phishing",
      scoreImpact: 20,
    });
    scoreBoost += 20;
  }

  // Pattern 4: Multiple brand impersonation attempts (different brand references)
  const brandImpersonations = evidence.filter(e => e.name === "Brand Impersonation");
  if (brandImpersonations.length > 1) {
    newEvidence.push({
      name: "Multiple Brand Impersonation",
      status: "fail" as const,
      description: "Multiple brand impersonation attempts indicate sophisticated phishing operation",
      scoreImpact: 40,
    });
    scoreBoost += 40;
  }

  // NEW ADVANCED CORRELATION PATTERNS

  // Pattern 5: Advanced Obfuscation + Threat Types
  const hasAdvancedObfuscation = evidence.some(e => 
    ["Unicode Homoglyph Attack", "Multiple Encoding Layers", "Zero-Width Characters"].includes(e.name)
  );
  
  if (hasAdvancedObfuscation && evidence.some(e => e.status === "fail")) {
    newEvidence.push({
      name: "Advanced Obfuscation Attack",
      status: "fail" as const,
      description: "Advanced obfuscation techniques combined with malicious indicators",
      scoreImpact: 45,
    });
    scoreBoost += 45;
  }

  // Pattern 6: Mobile Threats + Brand Impersonation
  const hasMobileThreats = evidence.some(e => 
    e.name.includes("Mobile") || e.name.includes("SMS") || e.name.includes("App Store")
  );
  
  if (hasMobileThreats && evidence.some(e => e.name === "Brand Impersonation")) {
    newEvidence.push({
      name: "Mobile Brand Impersonation Campaign",
      status: "fail" as const,
      description: "Mobile-focused brand impersonation attack detected",
      scoreImpact: 50,
    });
    scoreBoost += 50;
  }

  // Pattern 7: Redirect Chains + Obfuscation
  const hasRedirects = evidence.some(e => e.name.includes("Redirect") || e.name.includes("Shortener"));
  const hasObfuscation = evidence.some(e => 
    e.name.includes("Encoding") || e.name.includes("Obfuscation")
  );
  
  if (hasRedirects && hasObfuscation) {
    newEvidence.push({
      name: "Obfuscated Redirect Attack",
      status: "fail" as const,
      description: "Obfuscated URL with redirect chains - advanced attack pattern",
      scoreImpact: 35,
    });
    scoreBoost += 35;
  }

  // Pattern 8: Path Manipulation + File Execution
  const hasPathManipulation = evidence.some(e => 
    ["Directory Traversal", "Command Injection", "Malicious File Extension"].includes(e.name)
  );
  
  const hasFileExecution = evidence.some(e => 
    e.name === "Malicious File Extension" || e.name === "Double Extension"
  );
  
  if (hasPathManipulation && hasFileExecution) {
    newEvidence.push({
      name: "Path Traversal + File Execution",
      status: "fail" as const,
      description: "Path manipulation combined with executable file delivery",
      scoreImpact: 48,
    });
    scoreBoost += 48;
  }

  // Pattern 9: Port Evasion + Non-Standard Protocols
  const hasPortEvasion = evidence.some(e => 
    e.name.includes("Port") && e.status === "fail"
  );
  
  const hasNonStandardProtocol = evidence.some(e => 
    e.name === "Protocol Port Mismatch" || e.name === "Non-Standard Port"
  );
  
  if (hasPortEvasion && hasNonStandardProtocol) {
    newEvidence.push({
      name: "Advanced Port Evasion",
      status: "fail" as const,
      description: "Sophisticated port-based evasion techniques detected",
      scoreImpact: 32,
    });
    scoreBoost += 32;
  }

  // Pattern 10: Domain Reputation + Multiple Risk Factors
  const hasDomainRisks = evidence.some(e => 
    ["High Risk TLD", "Excessive Subdomains", "High Entropy Domain"].includes(e.name)
  );
  
  const hasMultipleRisks = evidence.filter(e => e.status === "fail").length >= 3;
  
  if (hasDomainRisks && hasMultipleRisks) {
    newEvidence.push({
      name: "Multi-Vector Domain Attack",
      status: "fail" as const,
      description: "Multiple domain risk factors indicate sophisticated attack",
      scoreImpact: 38,
    });
    scoreBoost += 38;
  }

  // Pattern 11: IDN Attacks + Brand Impersonation
  const hasIDNAttack = evidence.some(e => 
    e.name.includes("IDN") || e.name.includes("Unicode") || e.name.includes("Mixed Script")
  );
  
  if (hasIDNAttack && evidence.some(e => e.name === "Brand Impersonation")) {
    newEvidence.push({
      name: "IDN Brand Impersonation",
      status: "fail" as const,
      description: "Internationalized domain name brand impersonation attack",
      scoreImpact: 42,
    });
    scoreBoost += 42;
  }

  // Pattern 12: Mobile Banking + QR Code Threats
  const hasMobileBanking = evidence.some(e => 
    e.name === "Mobile Banking Phishing"
  );
  
  const hasQRThreats = evidence.some(e => 
    e.name.includes("QR") || e.name.includes("SMS")
  );
  
  if (hasMobileBanking && hasQRThreats) {
    newEvidence.push({
      name: "Mobile Banking QR Campaign",
      status: "fail" as const,
      description: "Mobile banking phishing using QR codes or SMS vectors",
      scoreImpact: 55,
    });
    scoreBoost += 55;
  }

  // Pattern 13: Multiple Attack Vectors (5+ different threat categories)
  const threatCategories = new Set(
    evidence
      .filter(e => e.status === "fail")
      .map(e => {
        if (e.name.includes("Brand")) return "brand";
        if (e.name.includes("Mobile") || e.name.includes("SMS")) return "mobile";
        if (e.name.includes("Redirect")) return "redirect";
        if (e.name.includes("Port")) return "network";
        if (e.name.includes("Path") || e.name.includes("File")) return "file";
        if (e.name.includes("Encoding") || e.name.includes("Obfuscation")) return "obfuscation";
        if (e.name.includes("Domain")) return "domain";
        return "other";
      })
  );

  if (threatCategories.size >= 5) {
    newEvidence.push({
      name: "Multi-Vector Advanced Attack",
      status: "fail" as const,
      description: `Attack spans ${threatCategories.size} categories - APT-like activity`,
      scoreImpact: 60,
    });
    scoreBoost += 60;
  }

  // Pattern 14: Zero-Day or Exploit Indicators
  const hasExploitIndicators = evidence.some(e => 
    e.name.includes("Exploit") || e.name.includes("Zero") || e.name.includes("CVE")
  );
  
  if (hasExploitIndicators) {
    newEvidence.push({
      name: "Potential Exploit Activity",
      status: "fail" as const,
      description: "Exploit or zero-day indicators detected",
      scoreImpact: 52,
    });
    scoreBoost += 52;
  }

  // Pattern 5: Hosting context gets boost if other malicious signals present
  const hasMaliciousSignals = evidence.some(e => e.status === "fail");
  const hasHostingContext = evidence.some(e => e.name === "Hosting Provider Context");
  
  if (hasHostingContext && hasMaliciousSignals) {
    // Boost existing hosting context signals
    const hostingIndex = newEvidence.findIndex(e => e.name === "Hosting Provider Context");
    if (hostingIndex !== -1) {
      newEvidence[hostingIndex] = {
        ...newEvidence[hostingIndex],
        scoreImpact: 15, // Now boosted due to correlation
      };
      scoreBoost += 15;
    }

    const abuseIndex = newEvidence.findIndex(e => e.name === "Abuse Pattern Context");
    if (abuseIndex !== -1) {
      newEvidence[abuseIndex] = {
        ...newEvidence[abuseIndex],
        scoreImpact: 10, // Now boosted due to correlation
      };
      scoreBoost += 10;
    }
  }

  return { newEvidence, scoreBoost };
}