import { HeuristicResult } from "@shared/schema";

const CLOUD_PROVIDERS = [
  { name: "AWS", cidrs: ["3.", "13.", "18.", "52.", "54."] },
  { name: "Google Cloud", cidrs: ["34.", "35."] },
  { name: "Azure", cidrs: ["20.", "40.", "52.", "104."] },
  { name: "DigitalOcean", cidrs: ["134.122.", "159.65.", "165.227."] },
  { name: "OVH", cidrs: ["51.", "145.", "148.", "198."] },
];

function startsWithAny(ip: string, prefixes: string[]) {
  return prefixes.some(p => ip.startsWith(p));
}

export function analyzeInfrastructureContext(ip: string) {
  let score = 0;
  const heuristics: HeuristicResult[] = [];

  for (const provider of CLOUD_PROVIDERS) {
    if (startsWithAny(ip, provider.cidrs)) {
      heuristics.push({
        name: "Hosting Provider Context",
        status: "warn" as const,
        description: `IP belongs to ${provider.name} cloud/VPS infrastructure.`,
        scoreImpact: 0, // Never malicious alone, only correlation boosts this
      });

      heuristics.push({
        name: "Abuse Pattern Context",
        status: "warn" as const,
        description:
          "Cloud and VPS IPs are commonly abused for phishing, malware delivery, scanners, and botnets.",
        scoreImpact: 0, // Never malicious alone, only correlation boosts this
      });

      // Base score is 0 - correlation will boost if needed
      score += 0;
      break;
    }
  }

  return { score, heuristics };
}
