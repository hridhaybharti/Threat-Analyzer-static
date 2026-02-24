import axios from "axios";
import { isIP as netIsIP } from "net";
import { secretsManager } from "../utils/secrets";

/**
 * Enhanced OSINT Service - Seamless Multi-Source Intelligence
 * Handles real-time lookups for IPs, Domains, and URLs.
 */

export interface OSINTReport {
  virusTotal?: any;
  abuseIPDB?: any;
  ipLocation?: any;
  urlScan?: any;
  shodan?: any;
}

class OSINTService {
  private static instance: OSINTService;

  private constructor() {}

  public static getInstance(): OSINTService {
    if (!OSINTService.instance) {
      OSINTService.instance = new OSINTService();
    }
    return OSINTService.instance;
  }

  /**
   * Safe JSON fetch with timeout and simple retry
   */
  private async fetchSafe(url: string, headers: Record<string, string>, timeout = 5000, retries = 1) {
    for (let i = 0; i <= retries; i++) {
      try {
        const response = await axios.get(url, { headers, timeout });
        return response.data;
      } catch (error: any) {
        if (i === retries) {
          console.error(`[OSINT] Final failure for ${url}:`, error.message);
          return null;
        }
        console.warn(`[OSINT] Retry ${i + 1} for ${url}...`);
        await new Promise(resolve => setTimeout(resolve, 1000)); // Wait before retry
      }
    }
    return null;
  }

  /**
   * VirusTotal lookup (v3 API)
   */
  public async getVirusTotal(target: string, type: "ip" | "domain" | "url") {
    const key = secretsManager.getSecret("VIRUSTOTAL_API_KEY");
    if (!key) return null;

    let endpoint = "";
    if (type === "ip") endpoint = `ip_addresses/${target}`;
    else if (type === "domain") endpoint = `domains/${target}`;
    else {
      const urlId = Buffer.from(target).toString("base64url").replace(/=/g, "");
      endpoint = `urls/${urlId}`;
    }

    const data = await this.fetchSafe(`https://www.virustotal.com/api/v3/${endpoint}`, { "x-apikey": key });
    if (!data?.data) return { ok: false, error: "No data returned" };

    const attrs = data.data.attributes;
    return {
      ok: true,
      stats: attrs.last_analysis_stats,
      reputation: attrs.reputation,
      permalink: `https://www.virustotal.com/gui/${type}/${type === 'url' ? Buffer.from(target).toString("base64url") : target}`,
      lastAnalysis: attrs.last_analysis_date
    };
  }

  /**
   * AbuseIPDB lookup (v2 API)
   */
  public async getAbuseIPDB(ip: string) {
    const key = secretsManager.getSecret("ABUSEIPDB_API_KEY");
    if (!key || !netIsIP(ip)) return null;

    const data = await this.fetchSafe(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose=true`, { 
      "Key": key,
      "Accept": "application/json"
    });
    
    return data?.data || null;
  }

  /**
   * urlscan.io lookup - NEW Source
   */
  public async getURLScan(url: string) {
    const key = secretsManager.getSecret("URLSCAN_API_KEY");
    if (!key) return null;

    // Search for existing scans first to be seamless
    const search = await this.fetchSafe(`https://urlscan.io/api/v1/search/?q=url:"${url}"`, { "API-Key": key });
    return search?.results?.[0] || null;
  }

  /**
   * IP-API Geolocation (No key required)
   */
  public async getIPLocation(ip: string) {
    if (!netIsIP(ip)) return null;
    return await this.fetchSafe(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting`, {});
  }
}

export const osintService = OSINTService.getInstance();
