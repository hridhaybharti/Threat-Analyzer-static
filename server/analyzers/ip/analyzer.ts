import { HeuristicResult } from "@shared/schema";
import { analyzeInfrastructureContext } from "./context";

function isValidIPv4(ip: string): boolean {
  const p = ip.split(".");
  return (
    p.length === 4 &&
    p.every(x => /^\d+$/.test(x) && Number(x) >= 0 && Number(x) <= 255)
  );
}

function isPrivate(ip: string) {
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function isBogon(ip: string) {
  const [a, b] = ip.split(".").map(Number);
  return (
    a === 0 ||
    a === 127 ||
    a >= 224 ||
    (a === 169 && b === 254) ||
    ip === "255.255.255.255"
  );
}

export async function analyzeIP(ip: string) {
  let score = 0;
  const heuristics: HeuristicResult[] = [];

  if (!isValidIPv4(ip)) {
    return {
      score: 100,
      heuristics: [{
        name: "IP Format Validation",
        status: "fail" as const,
        description: "Invalid IPv4 address.",
        scoreImpact: 100,
      }],
    };
  }

  if (isBogon(ip)) {
    return {
      score: 80,
      heuristics: [{
        name: "Bogon Address",
        status: "fail" as const,
        description: "Reserved or non-routable IP address.",
        scoreImpact: 80,
      }],
    };
  }

  if (isPrivate(ip)) {
    score += 10;
    heuristics.push({
      name: "Private Network",
      status: "warn" as const,
      description: "Private IP address (internal network).",
      scoreImpact: 10,
    });
  }

  const infra = analyzeInfrastructureContext(ip);
  score += infra.score;
  heuristics.push(...infra.heuristics);

  return { score, heuristics };
}
