import { HeuristicResult } from "@shared/schema";

interface SanitizationResult {
  sanitized: string;
  heuristics: HeuristicResult[];
  obfuscationDetected: boolean;
}

export function sanitizeInput(input: string): SanitizationResult {
  const heuristics: HeuristicResult[] = [];
  let sanitized = input.trim();
  let obfuscationDetected = false;

  // 1. URL Encoding Detection (%xx, %uXXXX)
  const urlEncoded = /%[0-9A-Fa-f]{2}|%u[0-9A-Fa-f]{4}/;
  if (urlEncoded.test(sanitized)) {
    heuristics.push({
      name: "URL Encoding Detected",
      status: "warn" as const,
      description: "Input contains URL encoded characters commonly used for obfuscation",
      scoreImpact: 15,
    });
    obfuscationDetected = true;
    
    // Decode URL encoding
    try {
      sanitized = decodeURIComponent(sanitized);
    } catch {
      heuristics.push({
        name: "Malformed URL Encoding",
        status: "fail" as const,
        description: "Invalid URL encoding pattern detected",
        scoreImpact: 25,
      });
    }
  }

  // 2. HTML Entity Detection (&#x;, &lt;, etc)
  const htmlEntities = /&[a-zA-Z]+;|&#x?[0-9A-Fa-f]+;/;
  if (htmlEntities.test(sanitized)) {
    heuristics.push({
      name: "HTML Entity Encoding",
      status: "warn" as const,
      description: "HTML entity encoding detected - common XSS/phishing technique",
      scoreImpact: 20,
    });
    obfuscationDetected = true;
    
    // Decode common HTML entities
    const entityMap: Record<string, string> = {
      '&lt;': '<',
      '&gt;': '>',
      '&amp;': '&',
      '&quot;': '"',
      '&#39;': "'",
      '&#x27;': "'",
    };
    
    for (const [entity, char] of Object.entries(entityMap)) {
      sanitized = sanitized.replace(new RegExp(entity, 'g'), char);
    }
  }

  // 3. Unicode Homoglyph Detection (lookalike characters)
  const homoglyphs: Record<string, string> = {
    'а': 'a', // Cyrillic a
    'о': 'o', // Cyrillic o  
    'е': 'e', // Cyrillic e
    'і': 'i', // Ukrainian i
    'ѡ': 'w', // Cyrillic omega
    '𝗮': 'a', // Mathematical bold
    '𝗼': 'o', // Mathematical bold
    '𝗲': 'e', // Mathematical bold
    'ɑ': 'a', // Latin script alpha
    'ɡ': 'g', // Latin script g
    'ⅰ': 'i', // Roman numeral i
    'ⅼ': 'l', // Roman numeral l
  };

  let hasHomoglyphs = false;
  for (const [homoglyph, normal] of Object.entries(homoglyphs)) {
    if (sanitized.includes(homoglyph)) {
      sanitized = sanitized.replace(new RegExp(homoglyph, 'g'), normal);
      hasHomoglyphs = true;
    }
  }

  if (hasHomoglyphs) {
    heuristics.push({
      name: "Unicode Homoglyph Attack",
      status: "fail" as const,
      description: "Unicode lookalike characters detected - sophisticated brand impersonation",
      scoreImpact: 35,
    });
    obfuscationDetected = true;
  }

  // 4. Visual Obfuscation ([.] → ., hxxp → http, etc)
  const visualObfuscation = /\[\.\]|hxxps?|d[0o]t|[0o]rg/;
  if (visualObfuscation.test(sanitized.toLowerCase())) {
    heuristics.push({
      name: "Visual Obfuscation",
      status: "warn" as const,
      description: "Visual character substitution detected ([.], hxxp, d0t, 0rg)",
      scoreImpact: 25,
    });
    obfuscationDetected = true;
    
    // Clean visual obfuscation
    sanitized = sanitized
      .replace(/\[\.\]/g, '.')
      .replace(/hxxps?:/gi, (match) => 
        match.toLowerCase().includes('s') ? 'https:' : 'http:'
      )
      .replace(/d[0o]t/gi, '.')
      .replace(/[0o]rg/gi, 'org');
  }

  // 5. Zero-width character detection
  const zeroWidthChars = /[\u200B-\u200D\uFEFF]/;
  if (zeroWidthChars.test(sanitized)) {
    heuristics.push({
      name: "Zero-Width Characters",
      status: "fail" as const,
      description: "Zero-width characters detected - advanced obfuscation technique",
      scoreImpact: 30,
    });
    obfuscationDetected = true;
    
    // Remove zero-width characters
    sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF]/g, '');
  }

  // 6. Mixed script detection
  const hasLatin = /[a-zA-Z]/.test(sanitized);
  const hasCyrillic = /[а-яё]/i.test(sanitized);
  const hasGreek = /[α-ωά-ώ]/i.test(sanitized);
  
  if ((hasLatin && hasCyrillic) || (hasLatin && hasGreek)) {
    heuristics.push({
      name: "Mixed Script Attack",
      status: "fail" as const,
      description: "Multiple character scripts detected - advanced spoofing attempt",
      scoreImpact: 40,
    });
    obfuscationDetected = true;
  }

  return {
    sanitized,
    heuristics,
    obfuscationDetected
  };
}