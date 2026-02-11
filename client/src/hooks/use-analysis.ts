import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, buildUrl } from "@shared/routes";
import { useToast } from "@/hooks/use-toast";
import { z } from "zod";

/* ---------------- Types ---------------- */

// Frontend-only input (DO NOT send inputType to backend)
type CreateAnalysisInput = {
  inputType: "domain" | "ip" | "url";
  value: string;
};

type Analysis = z.infer<typeof api.analysis.get.responses[200]>;

/* ---------------- Create Analysis ---------------- */

export function useCreateAnalysis() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation<
    z.infer<typeof api.analyze.create.responses[201]>,
    Error,
    CreateAnalysisInput
  >({
    mutationFn: async ({ inputType, value }) => {
      // ✅ MAP frontend → backend contract
      const payload: z.infer<typeof api.analyze.create.input> = {
        type: inputType,
        input: value.trim(),
      };

      const res = await fetch(api.analyze.create.path, {
        method: api.analyze.create.method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        credentials: "include",
      });

      if (!res.ok) {
        if (res.status === 400) {
          const error = api.analyze.create.responses[400].parse(
            await res.json()
          );
          throw new Error(error.message);
        }
        throw new Error("Analysis failed to start");
      }

      return api.analyze.create.responses[201].parse(await res.json());
    },

    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: [api.history.list.path],
      });
    },

    onError: (error) => {
      toast({
        title: "Analysis Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

/* ---------------- Get Single Analysis ---------------- */

export function useAnalysis(id: number) {
  return useQuery<Analysis | null>({
    queryKey: [api.analysis.get.path, id],
    queryFn: async () => {
      const url = buildUrl(api.analysis.get.path, { id });
      const res = await fetch(url, { credentials: "include" });

      if (res.status === 404) return null;
      if (!res.ok) throw new Error("Failed to fetch analysis");

      return api.analysis.get.responses[200].parse(await res.json());
    },
    enabled: !!id,
  });
}

/* ---------------- History ---------------- */

export function useHistory() {
  return useQuery({
    queryKey: [api.history.list.path],
    queryFn: async () => {
      const res = await fetch(api.history.list.path, {
        credentials: "include",
      });

      if (!res.ok) throw new Error("Failed to fetch history");

      return api.history.list.responses[200].parse(await res.json());
    },
  });
}

/* ---------------- Clear History ---------------- */

export function useClearHistory() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation<void, Error>({
    mutationFn: async () => {
      const res = await fetch(api.history.clear.path, {
        method: api.history.clear.method,
        credentials: "include",
      });

      if (!res.ok) throw new Error("Failed to clear history");
    },

    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: [api.history.list.path],
      });

      toast({
        title: "History Cleared",
        description: "All past analysis records have been removed.",
      });
    },
  });
}

/* ---------------- Reputation & Secrets Status ---------------- */

export function useReputationStatus() {
  return useQuery({
    queryKey: ["/api/reputation/status"],
    queryFn: async () => {
      const res = await fetch("/api/reputation/status", {
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to fetch engine status");
      return res.json() as Promise<{
        reputation: {
          loaded: boolean;
          count: number;
          lastSync: string | null;
          source: string;
        };
        secrets: {
          virusTotal: { active: boolean; provider: string; masked: string };
          abuseIPDB: { active: boolean; provider: string; masked: string };
          ipApi: { active: boolean; provider: string; masked: string };
        };
      }>;
    },
    refetchInterval: 60000,
  });
}
