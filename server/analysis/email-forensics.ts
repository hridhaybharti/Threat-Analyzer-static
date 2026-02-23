import { HeuristicResult } from "@shared/schema";
import { isIP } from "net";

/**
 * Email Forensic Service
 * Dismantles raw email source (EML) to extract headers, IPs, and links.
 */
class EmailForensics {
  private static instance: EmailForensics;

  private constructor() {}

  public static getInstance(): EmailForensics {
    if (!EmailForensics.instance) {
      EmailForensics.instance = new EmailForensics();
    }
    return EmailForensics.instance;
  }

  /**
   * Parses raw email headers to extract key intelligence.
   */
  public parseHeaders(rawEmail: string) {
    const headers: Record<string, string> = {};
    const lines = rawEmail.split('\n');
    
    for (const line of lines) {
      if (line.trim() === '') break; // End of headers
      const match = line.match(/^([a-zA-Z0-9-]+):\s*(.*)$/i);
      if (match) {
        headers[match[1].toLowerCase()] = match[2];
      }
    }

    return {
      from: headers['from'] || 'Unknown',
      to: headers['to'] || 'Unknown',
      subject: headers['subject'] || 'No Subject',
      date: headers['date'] || 'Unknown',
      authentication: headers['authentication-results'] || 'No Auth Results Found',
      received: this.extractIPsFromReceived(rawEmail),
    };
  }

  /**
   * Extracts the chain of IP addresses from the 'Received' headers.
   */
  private extractIPsFromReceived(rawEmail: string): string[] {
    const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const receivedHeaders = rawEmail.match(/^received:.*$/gmi) || [];
    const ips: string[] = [];

    for (const header of receivedHeaders) {
      const found = header.match(ipPattern);
      if (found) ips.push(...found);
    }

    return [...new Set(ips)]; // Unique IPs
  }

  /**
   * Extracts all URLs from the email body.
   */
  public extractLinks(rawEmail: string): string[] {
    const urlPattern = /https?:\/\/[^\s"'<>]+/g;
    const found = rawEmail.match(urlPattern) || [];
    return [...new Set(found)];
  }

  /**
   * Checks for social engineering patterns (Urgency, Pressure).
   */
  public getSocialEngineeringSignal(rawEmail: string): HeuristicResult | null {
    const suspiciousKeywords = ['urgent', 'verify', 'suspended', 'unusual', 'confirm', 'billing', 'invoice'];
    const lowerContent = rawEmail.toLowerCase();
    const hits = suspiciousKeywords.filter(k => lowerContent.includes(k));

    if (hits.length >= 2) {
      return {
        name: "Social Engineering Pattern",
        status: "warn",
        description: `High-pressure keywords detected (${hits.join(', ')}). Typical of phishing lures.`,
        scoreImpact: 20
      };
    }
    return null;
  }

  /**
   * Validates authentication results (SPF, DKIM, DMARC).
   */
  public getAuthSignal(authHeader: string): HeuristicResult | null {
    if (!authHeader) return null;

    const lowerAuth = authHeader.toLowerCase();
    const failures = [];
    if (lowerAuth.includes('spf=fail')) failures.push('SPF');
    if (lowerAuth.includes('dkim=fail')) failures.push('DKIM');
    if (lowerAuth.includes('dmarc=fail')) failures.push('DMARC');

    if (failures.length > 0) {
      return {
        name: "Email Auth Failure",
        status: "fail",
        description: `Authentication failed for: ${failures.join(', ')}. This email is likely spoofed.`,
        scoreImpact: 40
      };
    }
    return null;
  }
}

export const emailForensics = EmailForensics.getInstance();
