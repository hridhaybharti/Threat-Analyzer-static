import { HeuristicResult } from "@shared/schema";

/* =========================
   URL Normalization
 ========================= */

function sanitizeURL(input: string): string {
  let sanitized = input.trim();
  
  // De-obfuscate [.] → .
  sanitized = sanitized.replace(/\[\.\]/g, ".");
  
  // Convert hxxp/hxxps → http/https
  sanitized = sanitized.replace(/^hxxps?:\/\//i, (match) => {
    return match.toLowerCase().startsWith("hxxps") ? "https://" : "http://";
  });
  
  // Add scheme if missing (assume https)
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(sanitized)) {
    sanitized = "https://" + sanitized;
  }
  
  return sanitized;
}

/* =========================
   URL Analyzer
========================= */

export async function analyzeURL(
  input: string
): Promise<{ score: number; heuristics: HeuristicResult[] }> {
  const heuristics: HeuristicResult[] = [];
  let score = 0;

  const sanitized = sanitizeURL(input);

  let url: URL;

  try {
    url = new URL(sanitized);
    heuristics.push({
      name: "URL Parsing",
      status: "pass" as const,
      description: "Valid URL structure after sanitization.",
      scoreImpact: 0,
    });
  } catch {
    heuristics.push({
      name: "URL Parsing",
      status: "fail" as const,
      description: "Input could not be parsed as a valid URL even after sanitization.",
      scoreImpact: 100,
    });

    return { score: 100, heuristics };
  }

  /* =========================
     Scheme Check
  ========================= */

  if (url.protocol !== "https:") {
    score += 10;
    heuristics.push({
      name: "Insecure Scheme",
      status: "warn" as const,
      description: "URL does not use HTTPS.",
      scoreImpact: 10,
    });
  }

  /* =========================
     IP-based URL
  ========================= */

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) {
    score += 30;
    heuristics.push({
      name: "IP-based URL",
      status: "warn" as const,
      description: "Uses raw IP address instead of domain.",
      scoreImpact: 30,
    });
  }

  /* =========================
     Keyword Signals
  ========================= */

  const sensitive = ["login", "verify", "update", "secure", "account"];
  for (const word of sensitive) {
    if (url.pathname.toLowerCase().includes(word)) {
      score += 15;
      heuristics.push({
        name: "Keyword Analysis",
        status: "warn" as const,
        description: `Suspicious keyword detected: "${word}".`,
        scoreImpact: 15,
      });
      break;
    }
  }

  return {
    score: Math.min(score, 100),
    heuristics,
  };
}
