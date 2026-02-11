import logging from "loglevel";

/**
 * Secrets Manager
 * Centralizes access to sensitive API keys and provides masking/redaction
 * to prevent accidental exposure in logs or UI responses.
 */
class SecretsManager {
  private static instance: SecretsManager;
  private logger = logging.getLogger("secrets_manager");

  private constructor() {}

  public static getInstance(): SecretsManager {
    if (!SecretsManager.instance) {
      SecretsManager.instance = new SecretsManager();
    }
    return SecretsManager.instance;
  }

  /**
   * Safe getter for API keys with validation
   */
  public getSecret(name: string): string | null {
    const value = process.env[name];
    if (!value || value.trim() === "" || value === "YOUR_API_KEY_HERE") {
      return null;
    }
    return value.trim();
  }

  /**
   * Returns metadata about available keys without exposing the keys themselves.
   * Useful for the Frontend to show "Service Active" badges.
   */
  public getStatus() {
    return {
      virusTotal: {
        active: !!this.getSecret("VIRUSTOTAL_API_KEY"),
        provider: "VirusTotal",
        masked: this.maskKey(this.getSecret("VIRUSTOTAL_API_KEY")),
      },
      abuseIPDB: {
        active: !!this.getSecret("ABUSEIPDB_API_KEY"),
        provider: "AbuseIPDB",
        masked: this.maskKey(this.getSecret("ABUSEIPDB_API_KEY")),
      },
      ipApi: {
        active: true, // Community edition usually active by default
        provider: "ip-api.com",
        masked: "Public / Rate-limited",
      }
    };
  }

  /**
   * Mask a key for safe display (e.g., "ghp_...3d4f")
   */
  private maskKey(key: string | null): string {
    if (!key) return "Not Configured";
    if (key.length < 8) return "****";
    return `${key.substring(0, 4)}...${key.substring(key.length - 4)}`;
  }

  /**
   * Utility to redact secrets from any string or object
   */
  public redact(data: any): any {
    const secrets = [
      this.getSecret("VIRUSTOTAL_API_KEY"),
      this.getSecret("ABUSEIPDB_API_KEY"),
    ].filter(Boolean) as string[];

    let jsonString = JSON.stringify(data);
    for (const secret of secrets) {
      // Escape for regex and replace all occurrences
      const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      jsonString = jsonString.replace(new RegExp(escaped, 'g'), "[REDACTED]");
    }
    
    return JSON.parse(jsonString);
  }
}

export const secretsManager = SecretsManager.getInstance();
