import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { motion } from "framer-motion";
import { useCreateAnalysis, useReputationStatus } from "@/hooks/use-analysis";
import { detectInputType, type InputType } from "@/lib/detectInputType";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

import {
  Shield,
  Globe,
  Server,
  Link as LinkIcon,
  Search,
  Loader2,
  RotateCcw,
  CheckCircle,
  AlertCircle,
  Database,
} from "lucide-react";

export default function Dashboard() {
  const [, setLocation] = useLocation();

  const [input, setInput] = useState("");
  const [detectedType, setDetectedType] = useState<InputType>("domain");
  const [userOverride, setUserOverride] = useState(false);

  const { mutate, isPending } = useCreateAnalysis();
  const { data: reputation } = useReputationStatus();

  /* ---------------- Hybrid auto-detect ---------------- */
  useEffect(() => {
    if (userOverride) return;

    const value = input.trim();
    if (!value) return;

    const autoType = detectInputType(value);
    setDetectedType((prev) => (prev === autoType ? prev : autoType));
  }, [input, userOverride]);

  /* ---------------- Reset (NEW BUTTON) ---------------- */
  const handleNew = () => {
    setInput("");
    setDetectedType("domain");
    setUserOverride(false);
  };

  /* ---------------- Submit ---------------- */
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const value = input.trim();
    if (!value) return;

    mutate(
      {
        value,
        inputType: detectedType,
      },
      {
        onSuccess: (data) => {
          setLocation(`/analysis/${data.id}`);
        },
      }
    );
  };

  /* ---------------- Helpers ---------------- */
  const getPlaceholder = (t: InputType) => {
    switch (t) {
      case "domain":
        return "example.com";
      case "ip":
        return "192.168.1.1";
      case "url":
        return "https://example.com/suspicious-path";
    }
  };

  const getIcon = (t: InputType) => {
    switch (t) {
      case "domain":
        return Globe;
      case "ip":
        return Server;
      case "url":
        return LinkIcon;
    }
  };

  const ActiveIcon = getIcon(detectedType);

  return (
    <div className="min-h-[calc(100vh-4rem)] flex flex-col items-center justify-center p-4 bg-grid-pattern relative overflow-hidden">
      {/* Ambient blobs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-2xl relative z-10"
      >
        {/* Header */}
        <div className="text-center mb-10 space-y-4">
          <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl mb-4">
            <Shield className="w-12 h-12 text-emerald-500" />
          </div>

          <h1 className="text-4xl md:text-5xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-slate-400">
            Threat Intelligence
          </h1>

          <p className="text-slate-400 text-lg max-w-lg mx-auto">
            Analyze domains, IPs, and URLs using real security intelligence and heuristics.
          </p>

          {/* Reputation Sync Status */}
          <div className="flex justify-center pt-2">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge 
                    variant="outline" 
                    className={`gap-1.5 py-1 px-3 border transition-all duration-500 cursor-help
                      ${reputation?.loaded 
                        ? 'bg-emerald-500/5 text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/10' 
                        : 'bg-slate-500/5 text-slate-400 border-slate-700 hover:bg-slate-500/10'}`}
                  >
                    <Database className={`w-3.5 h-3.5 ${!reputation?.loaded ? 'animate-pulse' : ''}`} />
                    {reputation?.loaded ? `Global Reputation: ${reputation.count.toLocaleString()} domains` : 'Loading Global Reputation...'}
                    {reputation?.loaded ? (
                      <CheckCircle className="w-3 h-3 ml-0.5" />
                    ) : (
                      <Loader2 className="w-3 h-3 animate-spin ml-0.5" />
                    )}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-[280px] p-3 bg-slate-900 border-slate-800 text-slate-300">
                  <div className="space-y-1.5">
                    <p className="font-semibold text-white">Trust Intelligence Sync</p>
                    <p className="text-xs leading-relaxed">
                      Automatically synced with the <span className="text-emerald-400">Tranco Top 100K</span> authority list to identify and white-label reputable services.
                    </p>
                    {reputation?.last_sync && (
                      <p className="text-[10px] text-slate-500 pt-1 border-t border-slate-800">
                        Last sync: {reputation.last_sync}
                      </p>
                    )}
                  </div>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>
        </div>

        {/* Input Card */}
        <Card className="glass-card p-2 border-slate-800">
          <Tabs
            value={detectedType}
            onValueChange={(val) => {
              setDetectedType(val as InputType);
              setUserOverride(true);
            }}
            className="w-full"
          >
            <TabsList className="grid w-full grid-cols-3 bg-slate-900/50 p-1 rounded-lg border border-slate-800/50 mb-6">
              <TabsTrigger value="domain" disabled={isPending}>
                <Globe className="w-4 h-4 mr-2" /> Domain
              </TabsTrigger>
              <TabsTrigger value="ip" disabled={isPending}>
                <Server className="w-4 h-4 mr-2" /> IP
              </TabsTrigger>
              <TabsTrigger value="url" disabled={isPending}>
                <LinkIcon className="w-4 h-4 mr-2" /> URL
              </TabsTrigger>
            </TabsList>

            <form onSubmit={handleSubmit} className="relative p-2">
              <div className="relative group">
                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                  <ActiveIcon className="h-5 w-5 text-slate-500 group-focus-within:text-emerald-500" />
                </div>

                <Input
                  placeholder={getPlaceholder(detectedType)}
                  className="pl-12 h-14 bg-slate-950/50 border-slate-700 text-lg font-mono rounded-xl"
                  value={input}
                  onChange={(e) => {
                    setInput(e.target.value);
                    setUserOverride(false);
                  }}
                  disabled={isPending}
                />

                {/* Buttons */}
                <div className="absolute inset-y-1 right-1 flex gap-2">
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={handleNew}
                    disabled={isPending}
                    className="h-12 px-4 rounded-lg"
                  >
                    <RotateCcw className="w-4 h-4 mr-2" />
                    New
                  </Button>

                  <Button
                    type="submit"
                    size="lg"
                    disabled={isPending || !input.trim()}
                    className="h-12 px-6 rounded-lg bg-emerald-600 hover:bg-emerald-500"
                  >
                    {isPending ? (
                      <Loader2 className="w-5 h-5 animate-spin" />
                    ) : (
                      <>
                        <span className="mr-2">Analyze</span>
                        <Search className="w-4 h-4" />
                      </>
                    )}
                  </Button>
                </div>
              </div>
            </form>
          </Tabs>
        </Card>
      </motion.div>
    </div>
  );
}
