import { HeuristicResult } from "@shared/schema";

interface IDNAnalysis {
  punycode: string;
  unicode: string;
  heuristics: HeuristicResult[];
  isSuspicious: boolean;
  trustScore: number;  // -100 to +100, higher = more trusted
  riskContribution: number;  // risk points added
  trustContribution: number; // trust points added
}

// Trusted domains that legitimately use international characters
const TRUSTED_IDN_DOMAINS = new Set([
  "youtube.com",
  "builder.io",
  "amazon.co.jp",
  "google.co.jp",
  "alibaba.com",
  "baidu.com",
  "wikipedia.org",
]);

export function analyzeIDNDomain(domain: string): IDNAnalysis {
  const heuristics: HeuristicResult[] = [];
  let isSuspicious = false;
  let trustScore = 0;
  let riskContribution = 0;
  let trustContribution = 0;
  
  // Check if domain is punycode (xn-- prefix)
  const punycodeRegex = /^xn--/;
  const isPunycode = punycodeRegex.test(domain);
  
  let unicodeDomain = domain;
  let punycodeDomain = domain;
  
  if (isPunycode) {
    try {
      // Convert punycode to unicode (simplified version)
      // In production, you'd use a proper punycode library
      unicodeDomain = convertPunycodeToUnicode(domain);
      
      // Check if punycode domain is in trusted list
      const isTrusted = TRUSTED_IDN_DOMAINS.has(domain) || 
                       Array.from(TRUSTED_IDN_DOMAINS).some(td => domain.includes(td));
      
      if (isTrusted) {
        heuristics.push({
          name: "Punycode Domain",
          status: "pass" as const,
          description: "Internationalized domain from trusted source",
          scoreImpact: -10,
        });
        trustScore += 30;
        trustContribution += 10;
      } else {
        heuristics.push({
          name: "Punycode Domain",
          status: "warn" as const,
          description: "Internationalized domain name using punycode encoding",
          scoreImpact: 5,
        });
        riskContribution += 5;
      }
    } catch {
      heuristics.push({
        name: "Invalid Punycode",
        status: "fail" as const,
        description: "Invalid punycode encoding detected",
        scoreImpact: 30,
      });
      isSuspicious = true;
      riskContribution += 30;
    }
  }

  // Check for non-ASCII characters - but suppress if trusted domain
  const dangerousChars = /[^\u0000-\u007F\u00A0-\u00FF]/; // Non-ASCII
  const isTrustedDomain = TRUSTED_IDN_DOMAINS.has(domain) || 
                         Array.from(TRUSTED_IDN_DOMAINS).some(td => domain.includes(td));
  
  if (dangerousChars.test(unicodeDomain) && !isTrustedDomain) {
    heuristics.push({
      name: "Non-ASCII Characters",
      status: "warn" as const,
      description: "Domain contains non-ASCII characters",
      scoreImpact: 5,
    });
    riskContribution += 5;
  } else if (dangerousChars.test(unicodeDomain) && isTrustedDomain) {
    // Trusted domain with non-ASCII is OK
    trustScore += 20;
    trustContribution += 5;
  }
  
  // Check for specific dangerous Unicode patterns - only if NOT trusted and mixed with Latin
  const suspiciousUnicode = /[а-яё]/i; // Cyrillic letters that look like Latin
  const hasLatin = /[a-zA-Z]/.test(unicodeDomain);
  
  if (suspiciousUnicode.test(unicodeDomain) && hasLatin && !isTrustedDomain) {
    // Only flag if Cyrillic is MIXED with Latin (true homograph risk)
    heuristics.push({
      name: "Cyrillic Homograph Risk",
      status: "fail" as const,
      description: "Cyrillic characters mixed with Latin - potential homograph attack",
      scoreImpact: 30,
    });
    isSuspicious = true;
    riskContribution += 30;
  } else if (suspiciousUnicode.test(unicodeDomain) && isTrustedDomain) {
    // Trusted domain: downgrade to weak or ignore
    heuristics.push({
      name: "Cyrillic Script",
      status: "pass" as const,
      description: "Cyrillic from trusted domain - not a homograph risk",
      scoreImpact: 0,
    });
    trustScore += 25;
    trustContribution += 10;
  }
  
  // Check for mixed scripts in domain - only flag if not trusted
  const hasCyrillic = /[а-яё]/i.test(unicodeDomain);
  const hasGreek = /[α-ωά-ώ]/i.test(unicodeDomain);
  const hasArabic = /[ا-ى]/.test(unicodeDomain);
  const hasChinese = /[\u4e00-\u9fff]/.test(unicodeDomain);

  const scriptCount = [hasLatin, hasCyrillic, hasGreek, hasArabic, hasChinese].filter(Boolean).length;

  if (scriptCount > 1 && !isTrustedDomain) {
    heuristics.push({
      name: "Mixed Script Domain",
      status: "fail" as const,
      description: "Multiple character scripts in domain - high spoofing risk",
      scoreImpact: 40,
    });
    isSuspicious = true;
    riskContribution += 40;
  } else if (scriptCount > 1 && isTrustedDomain) {
    // Trusted multilingual domain
    heuristics.push({
      name: "Multilingual Domain",
      status: "pass" as const,
      description: "Legitimate multilingual domain from trusted source",
      scoreImpact: -5,
    });
    trustScore += 20;
    trustContribution += 10;
  }
  
  // Check for confusable characters
  const confusablePatterns = [
    { pattern: /а/g, char: 'a', desc: 'Cyrillic a' },
    { pattern: /о/g, char: 'o', desc: 'Cyrillic o' },
    { pattern: /е/g, char: 'e', desc: 'Cyrillic e' },
    { pattern: /р/g, char: 'p', desc: 'Cyrillic p' },
    { pattern: /х/g, char: 'x', desc: 'Cyrillic x' },
    { pattern: /у/g, char: 'y', desc: 'Cyrillic y' },
  ];
  
  let hasConfusable = false;
  for (const { pattern, char, desc } of confusablePatterns) {
    if (pattern.test(unicodeDomain)) {
      hasConfusable = true;
      // Don't break - we want to detect all instances
    }
  }
  
  if (hasConfusable && !isTrustedDomain) {
    heuristics.push({
      name: "Confusable Characters",
      status: "fail" as const,
      description: "Characters visually similar to Latin letters detected",
      scoreImpact: 30,
    });
    isSuspicious = true;
    riskContribution += 30;
  } else if (hasConfusable && isTrustedDomain) {
    heuristics.push({
      name: "International Characters",
      status: "pass" as const,
      description: "International characters from trusted source",
      scoreImpact: 0,
    });
    trustScore += 15;
    trustContribution += 8;
  }
  
  // Check for right-to-left characters - only flag if not trusted
  const rtlChars = /[\u0591-\u07FF\uFB1D-\uFDFD\uFE70-\uFEFC]/;
  if (rtlChars.test(unicodeDomain) && !isTrustedDomain) {
    heuristics.push({
      name: "RTL Characters",
      status: "fail" as const,
      description: "Right-to-left characters detected - potential spoofing",
      scoreImpact: 45,
    });
    isSuspicious = true;
    riskContribution += 45;
  } else if (rtlChars.test(unicodeDomain) && isTrustedDomain) {
    heuristics.push({
      name: "RTL Language",
      status: "pass" as const,
      description: "Right-to-left language from trusted source",
      scoreImpact: 0,
    });
    trustScore += 20;
    trustContribution += 10;
  }
  
  return {
    punycode: punycodeDomain,
    unicode: unicodeDomain,
    heuristics,
    isSuspicious,
    trustScore: Math.min(100, Math.max(-100, trustScore)),
    riskContribution: riskContribution,
    trustContribution: trustContribution
  };
}

// Simplified punycode decoder (in production, use punycode.js library)
function convertPunycodeToUnicode(punycode: string): string {
  if (!punycode.startsWith('xn--')) {
    return punycode;
  }
  
  const ascii = punycode.substring(4); // Remove 'xn--'
  // This is a very simplified version - real punycode decoding is more complex
  try {
    // Basic base36 decode (simplified)
    const decoded = Buffer.from(ascii, 'base64').toString('utf8');
    return decoded || punycode;
  } catch {
    return punycode;
  }
}

// Detect if domain looks like brand impersonation after IDN processing
export function detectIDNBrandImpersonation(domain: string, brands: Record<string, string[]>): HeuristicResult | null {
  const analysis = analyzeIDNDomain(domain);
  
  if (!analysis.isSuspicious) {
    return null;
  }
  
  const normalizedDomain = analysis.unicode.toLowerCase().replace(/[^a-z0-9]/g, '');
  
  for (const [tier, brandList] of Object.entries(brands)) {
    for (const brand of brandList) {
      const normalizedBrand = brand.toLowerCase().replace(/[^a-z0-9]/g, '');
      
      if (normalizedDomain.includes(normalizedBrand) || normalizedBrand.includes(normalizedDomain)) {
        const scores = { critical: 80, high: 60, medium: 45 };
        return {
          name: "IDN Brand Impersonation",
          status: "fail" as const,
          description: `Internationalized domain impersonating ${tier} tier brand "${brand}"`,
          scoreImpact: scores[tier as keyof typeof scores],
        };
      }
    }
  }
  
  return null;
}