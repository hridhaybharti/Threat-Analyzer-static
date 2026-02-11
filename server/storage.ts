import { analyses, type Analysis, type InsertAnalysis } from "@shared/schema";
import { db } from "./db";
import { desc, eq } from "drizzle-orm";

export interface IStorage {
  createAnalysis(analysis: InsertAnalysis): Promise<Analysis>;
  getHistory(): Promise<Analysis[]>;
  getAnalysis(id: number): Promise<Analysis | undefined>;
  clearHistory(): Promise<void>;
}

export class DatabaseStorage implements IStorage {
  /* =========================
     CREATE
  ========================= */

  async createAnalysis(
    insertAnalysis: InsertAnalysis
  ): Promise<Analysis> {
    const [analysis] = await db
      .insert(analyses)
      .values(insertAnalysis)
      .returning();

    return analysis;
  }

  /* =========================
     HISTORY
  ========================= */

  async getHistory(): Promise<Analysis[]> {
    return await db
      .select()
      .from(analyses)
      .orderBy(desc(analyses.createdAt));
  }

  /* =========================
     SINGLE ANALYSIS
  ========================= */

  async getAnalysis(id: number): Promise<Analysis | undefined> {
    const [analysis] = await db
      .select()
      .from(analyses)
      .where(eq(analyses.id, id));

    return analysis;
  }

  /* =========================
     CLEAR
  ========================= */

  async clearHistory(): Promise<void> {
    await db.delete(analyses);
  }
}

export const storage = new DatabaseStorage();
