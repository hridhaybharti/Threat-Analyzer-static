import { HeuristicResult } from "@shared/schema";

/**
 * Common homoglyph mapping for visual similarity checks
 */
const HOMOGLYPH_MAP: Record<string, string> = {
  'l': 'i', '1': 'i', '|': 'i', 'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ı': 'i',
  '0': 'o', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o', 'ø': 'o',
  'a': 'a', 'à': 'a', 'á': 'a', 'â': 'a', 'ã': 'a', 'ä': 'a', 'å': 'a', 'ɑ': 'a',
  'e': 'e', 'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e', 'е': 'e',
  'i': 'i', 'ï': 'i', 'í': 'i', 'ì': 'i', 'î': 'i', 'ɩ': 'i',
  's': 's', 'ś': 's', 'š': 's', 'ş': 's', 'ѕ': 's',
};

// High-value protected brands
const PROTECTED_BRANDS = [
  "google", "openai", "chatgpt", "microsoft", "apple", "amazon", "facebook", 
  "instagram", "netflix", "github", "dropbox", "steam", "discord", "spotify",
  "paypal", "bankofamerica", "chase", "wellsfargo", "icloud", "outlook", "office"
];

function getSkeleton(text: string): string {
  let t = text.toLowerCase();
  
  // Multi-char homoglyphs
  t = t.replace(/vv/g, 'w').replace(/rn/g, 'm');
  
  let skeleton = "";
  for (const char of t) {
    skeleton += HOMOGLYPH_MAP[char] || char;
  }
  return skeleton;
}

/**
 * Detect visually similar domains using skeleton normalization.
 */
export function analyzeHomoglyphs(domain: string): HeuristicResult | null {
  // Extract SLD (e.g. "google" from "google.com")
  const parts = domain.split(".");
  const sld = parts.length >= 2 ? parts[parts.length - 2].toLowerCase() : domain.toLowerCase();

  if (sld.length < 4) return null;

  const skeleton = getSkeleton(sld);

  for (const brand of PROTECTED_BRANDS) {
    const brandSkeleton = getSkeleton(brand);
    
    // If skeletons match but actual strings don't -> possible homoglyph attack
    if (skeleton === brandSkeleton && sld !== brand) {
      return {
        name: "Homoglyph Visual Lookalike",
        status: "fail",
        description: `Domain '${sld}' is visually similar to protected brand '${brand}' using lookalike characters.`,
        scoreImpact: 45, // High critical impact
      };
    }
  }

  return null;
}
