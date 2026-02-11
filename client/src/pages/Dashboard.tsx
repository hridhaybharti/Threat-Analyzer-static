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
  const { data: status } = useReputationStatus();
  const reputation = status?.reputation;
  const secrets = status?.secrets;

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
      {/* Background Cinematic Lighting */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-emerald-500/10 rounded-full blur-[120px] animate-pulse" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-blue-600/10 rounded-full blur-[120px] animate-pulse" />

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="w-full max-w-2xl relative z-10"
      >
        {/* Header Section */}
        <div className="text-center mb-12 space-y-6">
          <motion.div 
            className="inline-flex items-center justify-center p-4 rounded-3xl bg-slate-900/80 border border-white/10 shadow-[0_0_40px_rgba(16,185,129,0.1)] animate-float"
          >
            <Shield className="w-14 h-14 text-emerald-500" />
          </motion.div>

          <div className="space-y-2">
            <h1 className="text-5xl md:text-6xl font-bold tracking-tighter premium-gradient-text">
              Elixir Analyzer
            </h1>
            <p className="text-slate-400 text-lg max-w-lg mx-auto font-medium">
              Next-generation structural intelligence for a safer internet.
            </p>
          </div>

          {/* Engine & Secret Status */}
          <div className="flex flex-wrap justify-center gap-2 pt-2">
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
                    {reputation?.loaded ? `Global Reputation: ${reputation.count.toLocaleString()}` : 'Loading Intelligence...'}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-[280px] p-3 bg-slate-900 border-slate-800 text-slate-300">
                  <div className="space-y-1.5">
                    <p className="font-semibold text-white">Trust Intelligence Sync</p>
                    <p className="text-xs leading-relaxed">
                      Automatically synced with the <span className="text-emerald-400">Tranco Top 100K</span> authority list.
                    </p>
                  </div>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>

            {/* API Key Health Badge */}
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge 
                    variant="outline" 
                    className={`gap-1.5 py-1 px-3 border transition-all duration-500 cursor-help
                      ${secrets?.virusTotal.active || secrets?.abuseIPDB.active
                        ? 'bg-blue-500/5 text-blue-400 border-blue-500/20 hover:bg-blue-500/10' 
                        : 'bg-amber-500/5 text-amber-400 border-amber-500/20 hover:bg-amber-500/10'}`}
                  >
                    <Shield className="w-3.5 h-3.5" />
                    {secrets?.virusTotal.active && secrets?.abuseIPDB.active ? 'All APIs Active' : 'Partial Intelligence'}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-[280px] p-3 bg-slate-900 border-slate-800 text-slate-300">
                  <div className="space-y-2">
                    <p className="font-semibold text-white">External API Status</p>
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <span className="text-slate-400">VirusTotal:</span>
                      <span className={secrets?.virusTotal.active ? 'text-emerald-400' : 'text-rose-400'}>
                        {secrets?.virusTotal.active ? 'Active' : 'Offline'}
                      </span>
                      <span className="text-slate-400">AbuseIPDB:</span>
                      <span className={secrets?.abuseIPDB.active ? 'text-emerald-400' : 'text-rose-400'}>
                        {secrets?.abuseIPDB.active ? 'Active' : 'Offline'}
                      </span>
                    </div>
                  </div>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>
        </div>

        {/* Input Card */}
        <Card className="glass-card p-3 border-white/5 overflow-hidden">
          <Tabs
            value={detectedType}
            onValueChange={(val) => {
              setDetectedType(val as InputType);
              setUserOverride(true);
            }}
            className="w-full"
          >
            <TabsList className="grid w-full grid-cols-3 bg-slate-950/40 p-1.5 rounded-xl border border-white/5 mb-8">
              <TabsTrigger value="domain" disabled={isPending} className="rounded-lg transition-all data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-400">
                <Globe className="w-4 h-4 mr-2" /> Domain
              </TabsTrigger>
              <TabsTrigger value="ip" disabled={isPending} className="rounded-lg transition-all data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-400">
                <Server className="w-4 h-4 mr-2" /> IP
              </TabsTrigger>
              <TabsTrigger value="url" disabled={isPending} className="rounded-lg transition-all data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-400">
                <LinkIcon className="w-4 h-4 mr-2" /> URL
              </TabsTrigger>
            </TabsList>

            <form onSubmit={handleSubmit} className="relative p-1">
              <div className="relative group input-glow">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <ActiveIcon className="h-6 w-6 text-slate-500 group-focus-within:text-emerald-500 transition-colors duration-300" />
                </div>

                <Input
                  placeholder={getPlaceholder(detectedType)}
                  className="pl-14 h-16 bg-slate-950/40 border-slate-800 text-xl font-mono rounded-2xl placeholder:text-slate-600 transition-all focus:border-emerald-500/50"
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
                    className="h-14 px-8 rounded-xl bg-emerald-600 hover:bg-emerald-500 shadow-[0_0_20px_rgba(16,185,129,0.2)] transition-all active:scale-95"
                  >
                    {isPending ? (
                      <Loader2 className="w-6 h-6 animate-spin" />
                    ) : (
                      <>
                        <span className="mr-2 font-bold uppercase tracking-widest text-sm">Analyze Now</span>
                        <Search className="w-5 h-5" />
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
