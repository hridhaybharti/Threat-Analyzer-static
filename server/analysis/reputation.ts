import axios from "axios";
import fs from "fs";
import path from "path";
import { HeuristicResult } from "@shared/schema";

/**
 * Efficient Reputation Service for TypeScript Backend
 * Manages the Tranco Top 100K list and provides O(1) lookups.
 */
class ReputationService {
  private static instance: ReputationService;
  private topDomains: Set<string> = new Set();
  private status = {
    loaded: false,
    count: 0,
    lastSync: null as string | null,
    error: null as string | null,
  };

  private constructor() {}

  public static getInstance(): ReputationService {
    if (!ReputationService.instance) {
      ReputationService.instance = new ReputationService();
    }
    return ReputationService.instance;
  }

  public getStatus() {
    return this.status;
  }

  /**
   * Sync and Load the dataset. Runs in background to avoid blocking server start.
   */
  public async init() {
    const dataDir = path.join(process.cwd(), "server", "data");
    const filePath = path.join(dataDir, "top_100k.json");

    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    // 1. Try loading from local JSON cache first (fastest)
    if (fs.existsSync(filePath)) {
      try {
        const data = JSON.parse(fs.readFileSync(filePath, "utf-8"));
        this.topDomains = new Set(data.domains);
        this.status.loaded = true;
        this.status.count = this.topDomains.size;
        this.status.lastSync = new Date(fs.statSync(filePath).mtime).toISOString();
        console.log(`[ReputationService] Loaded ${this.status.count} domains from local cache.`);
      } catch (e) {
        console.error("[ReputationService] Cache load failed:", e);
      }
    }

    // 2. Trigger async sync if missing or old (>7 days)
    const isOld = this.status.lastSync 
      ? (Date.now() - new Date(this.status.lastSync).getTime()) > 7 * 24 * 3600 * 1000
      : true;

    if (!this.status.loaded || isOld) {
      // Use setImmediate to ensure this runs after the event loop tick
      setImmediate(() => {
        this.syncFromTranco(filePath).catch(err => {
          console.error("[ReputationService] Background sync failed:", err);
        });
      });
    }
  }

  private async syncFromTranco(outputPath: string) {
    const url = "https://tranco-list.eu/download/current/100000";
    console.log(`[ReputationService] Syncing latest Tranco list from ${url}...`);

    try {
      const response = await axios.get(url, { responseType: "text", timeout: 30000 });
      const domains: string[] = [];

      // Parse CSV (rank,domain)
      const lines = response.data.split("\n");
      for (const line of lines) {
        const parts = line.trim().split(",");
        if (parts.length >= 2) {
          domains.push(parts[1].toLowerCase());
        }
      }

      if (domains.length > 0) {
        // Atomic write to JSON cache
        fs.writeFileSync(outputPath, JSON.stringify({ domains, updated: new Date().toISOString() }));
        
        // Update memory state
        this.topDomains = new Set(domains);
        this.status.loaded = true;
        this.status.count = domains.length;
        this.status.lastSync = new Date().toISOString();
        this.status.error = null;
        console.log(`[ReputationService] Sync complete. ${domains.length} domains active.`);
      }
    } catch (e: any) {
      this.status.error = e.message;
      console.error("[ReputationService] Sync failed:", e.message);
    }
  }

  /**
   * Fast O(1) lookup for domain reputation
   */
  public isReputable(domain: string): boolean {
    if (!this.status.loaded) return false;
    
    // Simple normalization
    const d = domain.toLowerCase().trim().replace(/^www\./, "").replace(/\/$/, "");
    return this.topDomains.has(d);
  }

  /**
   * Generates a trust signal for the analysis engine
   */
  public getReputationSignal(domain: string): HeuristicResult | null {
    if (this.isReputable(domain)) {
      return {
        name: "Global Authority Reputation",
        status: "pass",
        description: `Domain is recognized in the Tranco Top 100K list of global reputable services.`,
        scoreImpact: -70, // Strong trust signal to cancel out structural random noise
      };
    }
    return null;
  }
}

export const reputationService = ReputationService.getInstance();
