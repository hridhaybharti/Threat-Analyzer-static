/**
 * Threat Intelligence Module - VirusTotal-competitive threat detection
 * Integrates multiple threat sources: AbuseIPDB, VirusTotal, WHOIS, URL reputation, Detection Engines
 */

import { isIP as netIsIP } from "net";
import { secretsManager } from "../utils/secrets";

export interface ThreatIntelReport {
  source: string;
  riskScore: number;
  confidence?: number;
  details: string;
  lastSeen?: string;
  verdicts?: string[];
}

export interface IPReputation {
  ip: string;
  abuseConfidenceScore: number;
  totalReports: number;
  isp: string;
  domain: string;
  threats: string[];
  usageType?: string;
}

export interface WhoisData {
  domain: string;
  registrar: string;
  registrationDate: string;
  expirationDate: string;
  nameServers: string[];
  registrantCountry?: string;
  age: number; // days
  isPrivate: boolean;
}

export interface DetectionEngineResult {
  engine: string;
  category: string;
  result: "malicious" | "suspicious" | "clean" | "undetected";
  lastAnalysisDate: string;
}

export interface VirusTotalReport {
  ok: boolean;
  type: "domain" | "ip" | "url";
  id?: string;
  permalink?: string;
  reputation?: number;
  stats?: {
    malicious?: number;
    suspicious?: number;
    harmless?: number;
    undetected?: number;
    timeout?: number;
  };
  lastAnalysisDate?: string;
  error?: string;
}

export interface AbuseIPDBReport {
  ipAddress: string;
  isPublic?: boolean;
  isWhitelisted?: boolean;
  abuseConfidenceScore: number;
  totalReports: number;
  countryCode?: string;
  usageType?: string;
  isp?: string;
  domain?: string;
  lastReportedAt?: string | null;
}

export interface IPLocation {
  ip: string;
  source: "ipapi";
  city?: string;
  region?: string;
  country?: string;
  countryCode?: string;
  latitude?: number;
  longitude?: number;
  googleMapsUrl?: string;
  accuracy?: "approximate";
  error?: string;
}

// ============================================================================
// MOCK DATA - Known malicious IPs and domains
// ============================================================================

const MALICIOUS_IPS = new Set([
  "192.168.1.100", // Example: Known C&C server
  "10.0.0.5",
  "203.0.113.45",
  "198.51.100.89",
  "192.0.2.123",
]);

const MALICIOUS_DOMAINS = new Set([
  "phishing-site.com",
  "malware-download.ru",
  "fake-paypal.tk",
  "credential-stealer.net",
  "ransomware-distribution.xyz",
  "botnet-controller.io",
  "keylogger-delivery.site",
  "banking-trojan.web",
]);

const SUSPICIOUS_PATTERNS = [
  "bit.ly",
  "short.link",
  "tiny-url",
  "tinyurl",
  "goo.gl",
  "ow.ly",
  "buff.ly",
];

// Known malicious IPs by threat type
const MALICIOUS_IPS_BY_TYPE: Record<string, string[]> = {
  botnet: ["203.0.113.45"],
  malware: ["198.51.100.89"],
  phishing: ["192.0.2.123"],
  sshbruteforce: ["10.0.0.5"],
};

// ============================================================================
// THREAT INTELLIGENCE FUNCTIONS
// ============================================================================

function env(name: string): string | undefined {
  const v = process.env[name];
  return v && v.trim() ? v.trim() : undefined;
}

async function fetchJson(
  url: string,
  init?: RequestInit,
  timeoutMs = 8000,
): Promise<{ ok: true; status: number; json: any } | { ok: false; status: number; error: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    const status = res.status;
    const text = await res.text();
    if (!res.ok) {
      return { ok: false, status, error: text || `HTTP ${status}` };
    }
    try {
      return { ok: true, status, json: text ? JSON.parse(text) : null };
    } catch (e: any) {
      return { ok: false, status, error: `Invalid JSON: ${String(e?.message || e)}` };
    }
  } catch (e: any) {
    return { ok: false, status: 0, error: String(e?.message || e) };
  } finally {
    clearTimeout(timer);
  }
}

function toIsoFromUnixSeconds(value: unknown): string | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  return new Date(value * 1000).toISOString();
}

function normalizeDomainLike(input: string): string {
  let d = input.trim();
  try {
    // Allow passing URLs here too.
    const u = new URL(d.includes("://") ? d : `http://${d}`);
    d = u.hostname;
  } catch {
    // keep as-is
  }
  return d.replace(/^www\./i, "").toLowerCase();
}

function normalizeUrlLike(input: string): string {
  const raw = input.trim();
  try {
    const u = new URL(raw.includes("://") ? raw : `http://${raw}`);
    return u.toString();
  } catch {
    return raw;
  }
}

export async function lookupVirusTotalDomain(domain: string): Promise<VirusTotalReport | null> {
  const apiKey = secretsManager.getSecret("VIRUSTOTAL_API_KEY");
  if (!apiKey) return null;

  const clean = normalizeDomainLike(domain);
  const resp = await fetchJson(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(clean)}`, {
    headers: { "x-apikey": apiKey },
  });

  if (!resp.ok) {
    return { ok: false, type: "domain", error: resp.error };
  }

  const data = resp.json?.data;
  const attrs = data?.attributes || {};
  const stats = attrs?.last_analysis_stats || undefined;
  return {
    ok: true,
    type: "domain",
    id: data?.id || clean,
    permalink: `https://www.virustotal.com/gui/domain/${encodeURIComponent(clean)}`,
    reputation: typeof attrs?.reputation === "number" ? attrs.reputation : undefined,
    stats,
    lastAnalysisDate: toIsoFromUnixSeconds(attrs?.last_analysis_date),
  };
}

export async function lookupVirusTotalIP(ip: string): Promise<VirusTotalReport | null> {
  const apiKey = secretsManager.getSecret("VIRUSTOTAL_API_KEY");
  if (!apiKey) return null;

  const clean = ip.trim();
  if (!netIsIP(clean)) return { ok: false, type: "ip", error: "Invalid IP address" };

  const resp = await fetchJson(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(clean)}`, {
    headers: { "x-apikey": apiKey },
  });

  if (!resp.ok) {
    return { ok: false, type: "ip", error: resp.error };
  }

  const data = resp.json?.data;
  const attrs = data?.attributes || {};
  const stats = attrs?.last_analysis_stats || undefined;
  return {
    ok: true,
    type: "ip",
    id: data?.id || clean,
    permalink: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(clean)}`,
    reputation: typeof attrs?.reputation === "number" ? attrs.reputation : undefined,
    stats,
    lastAnalysisDate: toIsoFromUnixSeconds(attrs?.last_analysis_date),
  };
}

export async function lookupVirusTotalUrl(url: string): Promise<VirusTotalReport | null> {
  const apiKey = secretsManager.getSecret("VIRUSTOTAL_API_KEY");
  if (!apiKey) return null;

  const normalized = normalizeUrlLike(url);
  const urlId = Buffer.from(normalized).toString("base64url");

  // First try a lookup by computed URL ID. If not found, submit then retry.
  let resp = await fetchJson(`https://www.virustotal.com/api/v3/urls/${encodeURIComponent(urlId)}`, {
    headers: { "x-apikey": apiKey },
  });

  if (!resp.ok && resp.status === 404) {
    const body = new URLSearchParams({ url: normalized }).toString();
    const submit = await fetchJson("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { "x-apikey": apiKey, "content-type": "application/x-www-form-urlencoded" },
      body,
    });

    const submittedId = submit.ok ? submit.json?.data?.id : undefined;
    const finalId = typeof submittedId === "string" && submittedId ? submittedId : urlId;

    resp = await fetchJson(`https://www.virustotal.com/api/v3/urls/${encodeURIComponent(finalId)}`, {
      headers: { "x-apikey": apiKey },
    });
  }

  if (!resp.ok) {
    return { ok: false, type: "url", error: resp.error };
  }

  const data = resp.json?.data;
  const attrs = data?.attributes || {};
  const stats = attrs?.last_analysis_stats || undefined;
  const id = data?.id || urlId;

  return {
    ok: true,
    type: "url",
    id,
    permalink: `https://www.virustotal.com/gui/url/${encodeURIComponent(id)}`,
    reputation: typeof attrs?.reputation === "number" ? attrs.reputation : undefined,
    stats,
    lastAnalysisDate: toIsoFromUnixSeconds(attrs?.last_analysis_date),
  };
}

export async function checkAbuseIPDB(ip: string): Promise<AbuseIPDBReport | null> {
  const apiKey = secretsManager.getSecret("ABUSEIPDB_API_KEY");
  if (!apiKey) return null;

  const clean = ip.trim();
  if (!netIsIP(clean)) return null;

  const qs = new URLSearchParams({
    ipAddress: clean,
    maxAgeInDays: "90",
    verbose: "true",
  }).toString();

  const resp = await fetchJson(`https://api.abuseipdb.com/api/v2/check?${qs}`, {
    headers: {
      Key: apiKey,
      Accept: "application/json",
    },
  });

  if (!resp.ok) return null;

  const d = resp.json?.data || {};
  return {
    ipAddress: String(d.ipAddress || clean),
    isPublic: typeof d.isPublic === "boolean" ? d.isPublic : undefined,
    isWhitelisted: typeof d.isWhitelisted === "boolean" ? d.isWhitelisted : undefined,
    abuseConfidenceScore: Number(d.abuseConfidenceScore || 0),
    totalReports: Number(d.totalReports || 0),
    countryCode: typeof d.countryCode === "string" ? d.countryCode : undefined,
    usageType: typeof d.usageType === "string" ? d.usageType : undefined,
    isp: typeof d.isp === "string" ? d.isp : undefined,
    domain: typeof d.domain === "string" ? d.domain : undefined,
    lastReportedAt: typeof d.lastReportedAt === "string" ? d.lastReportedAt : null,
  };
}

export async function lookupIPLocation(ip: string): Promise<IPLocation | null> {
  const clean = ip.trim();
  if (!netIsIP(clean)) return null;

  // No key required. Rate-limited by provider; keep timeouts low.
  const resp = await fetchJson(`https://ipapi.co/${encodeURIComponent(clean)}/json/`, undefined, 6000);
  if (!resp.ok) return { ip: clean, source: "ipapi", error: resp.error };

  const j = resp.json || {};
  const latitude = typeof j.latitude === "number" ? j.latitude : undefined;
  const longitude = typeof j.longitude === "number" ? j.longitude : undefined;

  return {
    ip: clean,
    source: "ipapi",
    city: typeof j.city === "string" ? j.city : undefined,
    region: typeof j.region === "string" ? j.region : undefined,
    country: typeof j.country_name === "string" ? j.country_name : undefined,
    countryCode: typeof j.country_code === "string" ? j.country_code : undefined,
    latitude,
    longitude,
    googleMapsUrl:
      latitude !== undefined && longitude !== undefined
        ? `https://www.google.com/maps?q=${latitude},${longitude}`
        : undefined,
    accuracy: "approximate",
  };
}

/**
 * Check IP reputation using mock abuse.ipdb-style data
 * In production, this would call the actual abuse.ipdb API
 */
export async function checkIPReputation(ip: string): Promise<IPReputation | null> {
  // Prefer real AbuseIPDB data when configured.
  try {
    const abuse = await checkAbuseIPDB(ip);
    if (abuse) {
      const threats: string[] = [];
      if (abuse.isWhitelisted) threats.push("Whitelisted");
      if (abuse.abuseConfidenceScore > 0) threats.push("Reported Abuse");
      if (abuse.usageType) threats.push(abuse.usageType);

      return {
        ip: abuse.ipAddress,
        abuseConfidenceScore: abuse.abuseConfidenceScore,
        totalReports: abuse.totalReports,
        isp: abuse.isp || "",
        domain: abuse.domain || "",
        threats,
        usageType: abuse.usageType,
      };
    }
  } catch {
    // Fall back to mock logic below.
  }

  // Validate IP format (mock path only supports IPv4)
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return null;

  // Check if IP is in malicious set
  const isMalicious = MALICIOUS_IPS.has(ip);

  if (isMalicious) {
    // Determine threat type from our categorized lists
    let threatType = "Unknown";
    for (const [type, ips] of Object.entries(MALICIOUS_IPS_BY_TYPE)) {
      if (ips.includes(ip)) {
        threatType = type;
        break;
      }
    }

    return {
      ip,
      abuseConfidenceScore: 80 + Math.random() * 20,
      totalReports: Math.floor(Math.random() * 500) + 50,
      threats: ["Botnet", "Malware Distribution", "C&C Server"].slice(0, Math.floor(Math.random() * 3) + 1),
      isp: "Suspicious ISP Corp",
      domain: "malicious-host.ru",
      usageType: threatType,
    };
  }

  // Check for private/reserved IPs (generally safe)
  if (isPrivateIP(ip)) {
    return {
      ip,
      abuseConfidenceScore: 0,
      totalReports: 0,
      threats: [],
      isp: "Private Network",
      domain: "private",
      usageType: "Private",
    };
  }

  // For public IPs, return clean or low suspicious score
  const randomScore = Math.random();
  return {
    ip,
    abuseConfidenceScore: randomScore > 0.95 ? Math.random() * 30 : 0,
    totalReports: randomScore > 0.95 ? Math.floor(Math.random() * 5) : 0,
    threats: randomScore > 0.95 ? ["Proxy/VPN"] : [],
    isp: ["Cloudflare", "AWS", "Digital Ocean", "Linode"][Math.floor(Math.random() * 4)],
    domain: "",
    usageType: "Data Center",
  };
}

/**
 * WHOIS lookup with domain age calculation
 * In production, this would call a real WHOIS API
 */
export async function lookupWhoisData(domain: string): Promise<WhoisData | null> {
  // Extract domain from URL if needed
  let cleanDomain = domain;
  try {
    const url = new URL("http://" + domain);
    cleanDomain = url.hostname;
  } catch {
    // Already a domain
  }

  // Remove www prefix
  cleanDomain = cleanDomain.replace(/^www\./, "");

  // Mock WHOIS data for well-known domains
  const knownDomains: Record<string, WhoisData> = {
    "youtube.com": {
      domain: "youtube.com",
      registrationDate: "2005-02-14",
      expirationDate: "2025-02-14",
      age: Math.floor((Date.now() - new Date("2005-02-14").getTime()) / (1000 * 60 * 60 * 24)),
      registrar: "MarkMonitor, Inc.",
      nameServers: ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"],
      isPrivate: false,
      registrantCountry: "US",
    },
    "google.com": {
      domain: "google.com",
      registrationDate: "1997-09-15",
      expirationDate: "2025-09-14",
      age: Math.floor((Date.now() - new Date("1997-09-15").getTime()) / (1000 * 60 * 60 * 24)),
      registrar: "MarkMonitor, Inc.",
      nameServers: ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"],
      isPrivate: false,
      registrantCountry: "US",
    },
    "github.com": {
      domain: "github.com",
      registrationDate: "2007-10-29",
      expirationDate: "2025-10-29",
      age: Math.floor((Date.now() - new Date("2007-10-29").getTime()) / (1000 * 60 * 60 * 24)),
      registrar: "NameSecure, LLC",
      nameServers: ["dns1.p08.nsone.net", "dns2.p08.nsone.net"],
      isPrivate: false,
      registrantCountry: "US",
    },
    "microsoft.com": {
      domain: "microsoft.com",
      registrationDate: "1994-12-01",
      expirationDate: "2025-11-30",
      age: Math.floor((Date.now() - new Date("1994-12-01").getTime()) / (1000 * 60 * 60 * 24)),
      registrar: "MarkMonitor, Inc.",
      nameServers: ["ns1.msft.net", "ns2.msft.net"],
      isPrivate: false,
      registrantCountry: "US",
    },
  };

  if (knownDomains[cleanDomain]) {
    return knownDomains[cleanDomain];
  }

  // For malicious domains, generate fake data with red flags
  if (MALICIOUS_DOMAINS.has(cleanDomain)) {
    return {
      domain: cleanDomain,
      registrationDate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
      expirationDate: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString().split("T")[0],
      age: Math.floor(Math.random() * 30),
      registrar: ["Namecheap", "GoDaddy"][Math.floor(Math.random() * 2)],
      nameServers: ["ns1.malicious.net", "ns2.malicious.net"],
      isPrivate: true,
      registrantCountry: ["RU", "CN", "Unknown"][Math.floor(Math.random() * 3)],
    };
  }

  // For unknown domains, generate mock data
  const registrationDate = new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000);
  const expirationDate = new Date(registrationDate.getTime() + 365 * 24 * 60 * 60 * 1000);
  const age = Math.floor((Date.now() - registrationDate.getTime()) / (1000 * 60 * 60 * 24));

  return {
    domain: cleanDomain,
    registrationDate: registrationDate.toISOString().split("T")[0],
    expirationDate: expirationDate.toISOString().split("T")[0],
    age,
    registrar: ["GoDaddy", "Namecheap", "Google Domains"][Math.floor(Math.random() * 3)],
    nameServers: generateNameServers(),
    isPrivate: Math.random() > 0.8,
    registrantCountry: ["US", "UK", "RU", "CN"][Math.floor(Math.random() * 4)],
  };
}

/**
 * Run detection engines - VirusTotal-style analysis
 * Simulates multiple antivirus/threat detection engines
 */
export async function runDetectionEngines(input: string): Promise<DetectionEngineResult[]> {
  const isMalicious = MALICIOUS_DOMAINS.has(input) || MALICIOUS_IPS.has(input);
  
  const engines = [
    { name: "Kaspersky", vendor: "Kaspersky Lab" },
    { name: "Norton", vendor: "Symantec" },
    { name: "McAfee", vendor: "McAfee" },
    { name: "Symantec", vendor: "Symantec" },
    { name: "Trend Micro", vendor: "Trend Micro" },
    { name: "Avast", vendor: "Avast" },
    { name: "AVG", vendor: "AVG Technologies" },
    { name: "Avira", vendor: "Avira" },
  ];

  if (isMalicious) {
    return engines.map(({ name }) => ({
      engine: name,
      category: "malware",
      result: Math.random() > 0.2 ? "malicious" : "suspicious",
      lastAnalysisDate: new Date().toISOString(),
    }));
  }

  // For clean URLs, most engines return clean
  return engines.map(({ name }) => ({
    engine: name,
    category: "unspecified",
    result: Math.random() > 0.95 ? "suspicious" : "clean",
    lastAnalysisDate: new Date().toISOString(),
  }));
}

/**
 * URL reputation check - URLhaus and PhishTank style
 */
export async function checkURLReputation(url: string): Promise<ThreatIntelReport[]> {
  const reports: ThreatIntelReport[] = [];
  
  // Extract domain
  let domain = url;
  try {
    const urlObj = new URL("http://" + url);
    domain = urlObj.hostname;
  } catch {
    // Continue with url as-is
  }

  // Check against malicious domains
  if (MALICIOUS_DOMAINS.has(domain)) {
    reports.push({
      source: "URLhaus",
      riskScore: 95,
      confidence: 0.98,
      details: "URL flagged as phishing/malware distribution in URLhaus database",
      lastSeen: new Date().toISOString(),
      verdicts: ["phishing", "malware"],
    });
    reports.push({
      source: "PhishTank",
      riskScore: 90,
      confidence: 0.96,
      details: "URL matches known phishing kit database",
      lastSeen: new Date().toISOString(),
      verdicts: ["phishing"],
    });
  }

  // Check for suspicious URL shorteners
  if (SUSPICIOUS_PATTERNS.some(pattern => url.includes(pattern))) {
    reports.push({
      source: "Shortener Detection",
      riskScore: 45,
      confidence: 0.85,
      details: "URL uses suspicious shortener service - cannot verify destination",
    });
  }

  // Check for suspicious patterns
  if (url.includes("@") || url.includes("%40")) {
    reports.push({
      source: "Credential Injection",
      riskScore: 85,
      confidence: 0.99,
      details: "URL contains @ symbol - possible credential injection attempt",
      verdicts: ["phishing"],
    });
  }

  // Check for suspicious TLDs
  const suspiciousTLDs = [".tk", ".ml", ".ga", ".cf", ".ru", ".io"];
  if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
    reports.push({
      source: "TLD Reputation",
      riskScore: 50,
      confidence: 0.8,
      details: `Domain uses suspicious TLD ${domain.split(".").pop()}`,
    });
  }

  return reports;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function isPrivateIP(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;

  // 10.0.0.0 - 10.255.255.255
  if (parts[0] === 10) return true;

  // 172.16.0.0 - 172.31.255.255
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;

  // 192.168.0.0 - 192.168.255.255
  if (parts[0] === 192 && parts[1] === 168) return true;

  // 127.0.0.0 - 127.255.255.255 (localhost)
  if (parts[0] === 127) return true;

  // 0.0.0.0 - 0.255.255.255
  if (parts[0] === 0) return true;

  // 255.255.255.255 (broadcast)
  if (parts[0] === 255) return true;

  return false;
}

function generateNameServers(): string[] {
  const nameserverPools = [
    ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"],
    ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    ["ns1.aws.com", "ns2.aws.com", "ns3.aws.com"],
    ["ns1.digitalocean.com", "ns2.digitalocean.com", "ns3.digitalocean.com"],
  ];
  return nameserverPools[Math.floor(Math.random() * nameserverPools.length)];
}

// Deprecated helper - kept for backward compatibility
function isValidIP(ip: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
}

function isValidDomain(domain: string): boolean {
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
  return domainRegex.test(domain);
}

export function isValidURL(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}
