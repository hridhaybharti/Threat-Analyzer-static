import { HeuristicResult } from "@shared/schema";
import brands from "./brands.json";

const BRAND_SCORING = {
  critical: 70,
  high: 50,
  medium: 35
};

const SUSPICIOUS_TLDS = ["top", "xyz", "tk", "ml", "ga", "cf", "buzz", "rest"];

function normalize(s: string) {
  return s.toLowerCase().replace(/[-_.]/g, "").replace(/[0-9]/g, "o");
}

function levenshtein(a: string, b: string) {
  const m = Array.from({ length: a.length + 1 }, () =>
    Array(b.length + 1).fill(0)
  );
  for (let i = 0; i <= a.length; i++) m[i][0] = i;
  for (let j = 0; j <= b.length; j++) m[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      m[i][j] = Math.min(
        m[i - 1][j] + 1,
        m[i][j - 1] + 1,
        m[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return m[a.length][b.length];
}

export async function analyzeDomain(domain: string) {
  let score = 0;
  const heuristics: HeuristicResult[] = [];

  const parts = domain.split(".");
  const tld = parts.at(-1)!;
  const stem = normalize(parts[0]);

  if (SUSPICIOUS_TLDS.includes(tld)) {
    score += 25;
    heuristics.push({
      name: "TLD Reputation",
      status: "fail" as const,
      description: `TLD .${tld} is frequently abused.`,
      scoreImpact: 25,
    });
  }

  for (const [tier, brandList] of Object.entries(brands)) {
    for (const brand of brandList) {
      const d = levenshtein(stem, normalize(brand));
      if (d > 0 && d <= 2) {
        const tierScore = BRAND_SCORING[tier as keyof typeof BRAND_SCORING];
        score += tierScore;
        heuristics.push({
          name: "Brand Impersonation",
          status: "fail" as const,
          description: `Domain mimics ${tier} tier brand "${brand}".`,
          scoreImpact: tierScore,
        });
        break;
      }
    }
    if (heuristics.some(h => h.name === "Brand Impersonation")) break;
  }

  return { score, heuristics };
}
