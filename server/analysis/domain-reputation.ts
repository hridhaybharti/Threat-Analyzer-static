import { HeuristicResult } from "@shared/schema";

interface DomainReputation {
  heuristics: HeuristicResult[];
  reputationScore: number;
  riskFactors: string[];
}

export function analyzeDomainReputation(domain: string): DomainReputation {
  const heuristics: HeuristicResult[] = [];
  const riskFactors: string[] = [];
  let reputationScore = 0;

  // 1. Domain Length Analysis
  const domainLength = domain.length;
  
  if (domainLength > 50) {
    heuristics.push({
      name: "Excessive Domain Length",
      status: "fail" as const,
      description: `Extremely long domain: ${domainLength} characters`,
      scoreImpact: 25,
    });
    reputationScore -= 25;
    riskFactors.push("long_domain");
  } else if (domainLength > 30) {
    heuristics.push({
      name: "Long Domain",
      status: "warn" as const,
      description: `Unusually long domain: ${domainLength} characters`,
      scoreImpact: 15,
    });
    reputationScore -= 15;
    riskFactors.push("long_domain");
  } else if (domainLength < 4) {
    heuristics.push({
      name: "Very Short Domain",
      status: "warn" as const,
      description: `Very short domain: ${domainLength} characters - potential typo-squatting`,
      scoreImpact: 12,
    });
    reputationScore -= 12;
    riskFactors.push("short_domain");
  }

  // 2. Subdomain Analysis
  const subdomains = domain.split('.');
  const subdomainCount = subdomains.length - 2; // Remove TLD and main domain
  
  if (subdomainCount > 4) {
    heuristics.push({
      name: "Excessive Subdomains",
      status: "fail" as const,
      description: `Too many subdomains: ${subdomainCount}`,
      scoreImpact: 30,
    });
    reputationScore -= 30;
    riskFactors.push("excess_subdomains");
  } else if (subdomainCount > 2) {
    heuristics.push({
      name: "Multiple Subdomains",
      status: "warn" as const,
      description: `Multiple subdomains: ${subdomainCount}`,
      scoreImpact: 15,
    });
    reputationScore -= 15;
    riskFactors.push("multiple_subdomains");
  }

  // 3. Numeric Domain Analysis
  const numericRatio = (domain.match(/\d/g) || []).length / domain.length;
  
  if (numericRatio > 0.5) {
    heuristics.push({
      name: "Heavy Numeric Domain",
      status: "fail" as const,
      description: `Domain contains ${(numericRatio * 100).toFixed(0)}% numbers`,
      scoreImpact: 35,
    });
    reputationScore -= 35;
    riskFactors.push("numeric_domain");
  } else if (numericRatio > 0.3) {
    heuristics.push({
      name: "Numeric Domain",
      status: "warn" as const,
      description: `Domain contains ${(numericRatio * 100).toFixed(0)}% numbers`,
      scoreImpact: 20,
    });
    reputationScore -= 20;
    riskFactors.push("numeric_domain");
  }

  // 4. Hyphen Analysis
  const hyphenCount = (domain.match(/-/g) || []).length;
  const hyphenRatio = hyphenCount / domain.length;
  
  if (hyphenCount > 3) {
    heuristics.push({
      name: "Excessive Hyphens",
      status: "fail" as const,
      description: `Too many hyphens: ${hyphenCount}`,
      scoreImpact: 25,
    });
    reputationScore -= 25;
    riskFactors.push("excess_hyphens");
  } else if (hyphenCount >= 2) {
    heuristics.push({
      name: "Multiple Hyphens",
      status: "warn" as const,
      description: `Multiple hyphens: ${hyphenCount}`,
      scoreImpact: 15,
    });
    reputationScore -= 15;
    riskFactors.push("multiple_hyphens");
  }

  // 5. Consonant/Vowel Pattern Analysis
  const consonants = domain.replace(/[aeiouAEIOU0-9.-]/g, '').length;
  const vowels = domain.replace(/[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ0-9.-]/g, '').length;
  
  if (vowels === 0 && consonants > 0) {
    heuristics.push({
      name: "No Vowels",
      status: "fail" as const,
      description: "Domain contains no vowels - common in DGA domains",
      scoreImpact: 30,
    });
    reputationScore -= 30;
    riskFactors.push("no_vowels");
  } else if (vowels < 2 && consonants > 8) {
    heuristics.push({
      name: "Low Vowel Ratio",
      status: "warn" as const,
      description: "Unusually low vowel to consonant ratio",
      scoreImpact: 18,
    });
    reputationScore -= 18;
    riskFactors.push("low_vowel_ratio");
  }

  // 6. Domain Entropy Analysis (measure randomness)
  const entropy = calculateEntropy(domain.toLowerCase().replace(/[^a-z0-9]/g, ''));
  
  if (entropy > 4.0) {
    heuristics.push({
      name: "High Entropy Domain",
      status: "fail" as const,
      description: `Domain appears random: entropy ${entropy.toFixed(2)}`,
      scoreImpact: 35,
    });
    reputationScore -= 35;
    riskFactors.push("high_entropy");
  } else if (entropy > 3.5) {
    heuristics.push({
      name: "Medium Entropy Domain",
      status: "warn" as const,
      description: `Domain has high randomness: entropy ${entropy.toFixed(2)}`,
      scoreImpact: 20,
    });
    reputationScore -= 20;
    riskFactors.push("medium_entropy");
  }

  // 7. TLD Risk Assessment
  const tld = domain.split('.').pop()?.toLowerCase() || '';
  
  const highRiskTlds = [
    'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'buzz', 'rest', 'click', 'link',
    'shop', 'online', 'live', 'work', 'science', 'rent', 'club', 'fun'
  ];
  
  const suspiciousTlds = [
    'info', 'biz', 'ws', 'cc', 'tv', 'me', 'io', 'co', 'us', 'cn', 'ru'
  ];

  if (highRiskTlds.includes(tld)) {
    heuristics.push({
      name: "High Risk TLD",
      status: "fail" as const,
      description: `TLD .${tld} is frequently abused`,
      scoreImpact: 30,
    });
    reputationScore -= 30;
    riskFactors.push("high_risk_tld");
  } else if (suspiciousTlds.includes(tld)) {
    heuristics.push({
      name: "Suspicious TLD",
      status: "warn" as const,
      description: `TLD .${tld} has elevated risk`,
      scoreImpact: 18,
    });
    reputationScore -= 18;
    riskFactors.push("suspicious_tld");
  }

  // 8. Dictionary Word Detection
  const mainDomain = domain.split('.')[0];
  if (!containsDictionaryWords(mainDomain)) {
    heuristics.push({
      name: "Non-Dictionary Domain",
      status: "warn" as const,
      description: "Domain doesn't contain recognizable words",
      scoreImpact: 15,
    });
    reputationScore -= 15;
    riskFactors.push("non_dictionary");
  }

  // 9. Domain Age Simulation (simplified - in production use WHOIS)
  const recentlyRegistered = simulateRecentRegistration(domain);
  if (recentlyRegistered) {
    heuristics.push({
      name: "Recently Registered",
      status: "warn" as const,
      description: "Domain appears to be recently registered",
      scoreImpact: 20,
    });
    reputationScore -= 20;
    riskFactors.push("recent_registration");
  }

  // 10. Privacy Protection Detection (simplified pattern-based)
  const privacyPatterns = ['whoisguard', 'privacyprotect', 'domainsbyproxy', 'privacyguardian'];
  if (privacyPatterns.some(pattern => domain.toLowerCase().includes(pattern))) {
    heuristics.push({
      name: "Privacy Protection",
      status: "warn" as const,
      description: "Domain uses privacy protection service",
      scoreImpact: 15,
    });
    reputationScore -= 15;
    riskFactors.push("privacy_protection");
  }

  // Normalize reputation score (0-100, higher is better)
  reputationScore = Math.max(0, Math.min(100, reputationScore + 50)); // Start from 50

  return {
    heuristics,
    reputationScore,
    riskFactors
  };
}

// Calculate Shannon entropy for randomness detection
function calculateEntropy(str: string): number {
  const freq: Record<string, number> = {};
  
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  let entropy = 0;
  const len = str.length;
  
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  
  return entropy;
}

// Simple dictionary word check (in production, use a proper dictionary)
function containsDictionaryWords(domain: string): boolean {
  const commonWords = [
    'web', 'site', 'online', 'service', 'app', 'tech', 'digital', 'media',
    'info', 'data', 'cloud', 'net', 'system', 'pro', 'expert', 'best',
    'top', 'new', 'global', 'world', 'link', 'connect', 'social',
    'email', 'secure', 'safe', 'fast', 'quick', 'easy', 'smart'
  ];
  
  const cleanDomain = domain.toLowerCase().replace(/[^a-z]/g, '');
  
  for (const word of commonWords) {
    if (cleanDomain.includes(word)) {
      return true;
    }
  }
  
  // Check for partial word matches
  for (const word of commonWords) {
    for (let i = 0; i <= cleanDomain.length - word.length; i++) {
      const substring = cleanDomain.substring(i, i + word.length);
      if (substring === word) {
        return true;
      }
    }
  }
  
  return false;
}

// Simulate recent registration detection (simplified heuristics)
function simulateRecentRegistration(domain: string): boolean {
  // High entropy + short domain often indicates recent registration
  const entropy = calculateEntropy(domain.toLowerCase().replace(/[^a-z0-9]/g, ''));
  const hasNumbers = /\d/.test(domain);
  const hasManyHyphens = (domain.match(/-/g) || []).length >= 2;
  
  return (entropy > 3.5 && domain.length < 15) || 
         (hasNumbers && hasManyHyphens) ||
         (/^\d/.test(domain) && domain.length < 20);
}