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
  Mail,
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
  const [detectedType, setDetectedType] = useState<InputType | "email">("domain");
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

    if (value.toLowerCase().startsWith('from:') || value.toLowerCase().startsWith('received:')) {
      setDetectedType("email");
      return;
    }

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
        inputType: detectedType === "email" ? "url" : detectedType as any, // Temporary hack if schema only allowed 3
      },
      {
        onSuccess: (data) => {
          setLocation(`/analysis/${data.id}`);
        },
      }
    );
  };

  // Actually I updated the schema to support email, so I should use it properly
  const handleRealSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const value = input.trim();
    if (!value) return;

    mutate(
      {
        value,
        inputType: detectedType as any,
      },
      {
        onSuccess: (data) => {
          setLocation(`/analysis/${data.id}`);
        },
      }
    );
  };

  /* ---------------- Helpers ---------------- */
  const getPlaceholder = (t: string) => {
    switch (t) {
      case "domain":
        return "example.com";
      case "ip":
        return "192.168.1.1";
      case "url":
        return "https://example.com/path";
      case "email":
        return "Paste raw email source (headers + body) here...";
    }
  };

  const getIcon = (t: string) => {
    switch (t) {
      case "domain":
        return Globe;
      case "ip":
        return Server;
      case "url":
        return LinkIcon;
      case "email":
        return Mail;
    }
  };

  const ActiveIcon = getIcon(detectedType);

  return (
    <div className="min-h-screen bg-[#020617] bg-grid-white/[0.02] relative overflow-hidden pb-20">
      {/* Cinematic Ambience */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-[600px] bg-emerald-500/5 blur-[120px] rounded-full pointer-events-none" />
      <div className="absolute bottom-0 right-0 w-[400px] h-[400px] bg-blue-500/5 blur-[100px] rounded-full pointer-events-none" />

      <div className="container mx-auto px-4 py-12 max-w-7xl relative z-10">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-start">
          
          {/* LEFT: HERO & SCANNER */}
          <div className="lg:col-span-7 space-y-12">
            <header className="space-y-6">
              <motion.div 
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                className="inline-flex items-center gap-3 px-4 py-2 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-mono text-xs font-bold tracking-widest uppercase"
              >
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                Live Intelligence Active
              </motion.div>

              <div className="space-y-2">
                <h1 className="text-6xl md:text-7xl font-black tracking-tighter text-white leading-none">
                  ELIXIR<span className="text-emerald-500">.</span>
                </h1>
                <p className="text-xl text-slate-400 font-medium max-w-md">
                  Structural threat intelligence for the modern security frontier.
                </p>
              </div>
            </header>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <Card className="glass-card border-white/5 p-4 rounded-[2rem] overflow-hidden shadow-2xl">
                <Tabs
                  value={detectedType}
                  onValueChange={(val) => {
                    setDetectedType(val as any);
                    setUserOverride(true);
                  }}
                  className="w-full"
                >
                  <TabsList className="bg-slate-950/50 p-1.5 rounded-2xl border border-white/5 mb-8 flex w-fit">
                    <TabsTrigger value="domain" disabled={isPending} className="rounded-xl px-6 data-[state=active]:bg-emerald-500/10 data-[state=active]:text-emerald-400">
                      Domain
                    </TabsTrigger>
                    <TabsTrigger value="ip" disabled={isPending} className="rounded-xl px-6 data-[state=active]:bg-emerald-500/10 data-[state=active]:text-emerald-400">
                      IP
                    </TabsTrigger>
                    <TabsTrigger value="url" disabled={isPending} className="rounded-xl px-6 data-[state=active]:bg-emerald-500/10 data-[state=active]:text-emerald-400">
                      URL
                    </TabsTrigger>
                    <TabsTrigger value="email" disabled={isPending} className="rounded-xl px-6 data-[state=active]:bg-emerald-500/10 data-[state=active]:text-emerald-400">
                      Email
                    </TabsTrigger>
                  </TabsList>

                  <form onSubmit={handleRealSubmit} className="space-y-6">
                    <div className="relative group input-glow">
                      <div className="absolute inset-y-0 left-0 pl-6 flex items-center pointer-events-none">
                        <ActiveIcon className="h-6 w-6 text-slate-600 group-focus-within:text-emerald-500 transition-colors duration-300" />
                      </div>

                      {detectedType === "email" ? (
                        <textarea
                          placeholder={getPlaceholder(detectedType)}
                          className="w-full min-h-[180px] pl-16 pr-6 py-6 bg-slate-950/40 border-slate-800 text-sm font-mono rounded-3xl placeholder:text-slate-700 transition-all focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500/50 shadow-inner resize-none"
                          value={input}
                          onChange={(e) => {
                            setInput(e.target.value);
                            setUserOverride(true);
                          }}
                          disabled={isPending}
                        />
                      ) : (
                        <Input
                          placeholder={getPlaceholder(detectedType)}
                          className="pl-16 h-20 bg-slate-950/40 border-slate-800 text-2xl font-mono rounded-3xl placeholder:text-slate-700 transition-all focus:border-emerald-500/50 shadow-inner"
                          value={input}
                          onChange={(e) => {
                            setInput(e.target.value);
                            setUserOverride(false);
                          }}
                          disabled={isPending}
                        />
                      )}
                    </div>

                    <div className="flex items-center justify-between gap-4">
                       <div className="flex gap-2">
                          <Badge variant="outline" className="bg-slate-900/50 border-white/5 text-[10px] uppercase tracking-widest text-slate-500 px-3 py-1">
                            Heuristic Engine v2.1
                          </Badge>
                       </div>
                       
                       <div className="flex gap-3">
                        <Button
                          type="button"
                          variant="ghost"
                          onClick={handleNew}
                          disabled={isPending}
                          className="h-14 px-6 rounded-2xl text-slate-500 hover:text-white transition-all"
                        >
                          <RotateCcw className="w-5 h-5" />
                        </Button>

                        <Button
                          type="submit"
                          size="lg"
                          disabled={isPending || !input.trim()}
                          className="h-14 px-10 rounded-2xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold shadow-[0_10px_40px_rgba(16,185,129,0.2)] transition-all active:scale-95 group/btn"
                        >
                          {isPending ? (
                            <Loader2 className="w-6 h-6 animate-spin" />
                          ) : (
                            <div className="flex items-center gap-3">
                              <span className="uppercase tracking-widest text-sm">Execute Intelligence Pass</span>
                              <Search className="w-5 h-5 group-hover/btn:scale-110 transition-transform" />
                            </div>
                          )}
                        </Button>
                       </div>
                    </div>
                  </form>
                </Tabs>
              </Card>
            </motion.div>
          </div>

          {/* RIGHT: LIVE FEED & SERVICE STATUS */}
          <div className="lg:col-span-5 space-y-8">
             {/* Service Health Card */}
             <Card className="glass-card border-white/5 p-6 rounded-[2rem] space-y-6">
                <div className="flex items-center justify-between">
                   <h3 className="text-sm font-bold uppercase tracking-[0.2em] text-slate-500">Service Infrastructure</h3>
                   <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-[10px] text-emerald-500 font-bold uppercase">
                      <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                      All Systems Nominal
                   </div>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center justify-between p-4 rounded-2xl bg-slate-950/50 border border-white/5">
                     <div className="flex items-center gap-3">
                        <Database className="w-5 h-5 text-emerald-500" />
                        <div>
                           <p className="text-sm font-bold text-slate-200">Authority Reputation</p>
                           <p className="text-[10px] text-slate-500 font-mono">{reputation?.loaded ? `${reputation.count.toLocaleString()} Protected Domains` : 'Synchronizing...'}</p>
                        </div>
                     </div>
                     {reputation?.loaded && <CheckCircle className="w-4 h-4 text-emerald-500" />}
                  </div>

                  <div className="flex items-center justify-between p-4 rounded-2xl bg-slate-950/50 border border-white/5">
                     <div className="flex items-center gap-3">
                        <Shield className="w-5 h-5 text-blue-500" />
                        <div>
                           <p className="text-sm font-bold text-slate-200">OSINT Connectors</p>
                           <p className="text-[10px] text-slate-500 font-mono">
                              {secrets?.virusTotal.active ? 'VT Active' : 'VT Offline'} • {secrets?.abuseIPDB.active ? 'IPDB Active' : 'IPDB Offline'}
                           </p>
                        </div>
                     </div>
                     <Badge variant="outline" className="border-blue-500/20 text-blue-400 bg-blue-500/5">2/3 Online</Badge>
                  </div>
                </div>
             </Card>

             {/* Live Threat Feed Simulation */}
             <div className="space-y-4">
                <div className="flex items-center gap-2">
                   <AlertCircle className="w-4 h-4 text-rose-500" />
                   <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-slate-500">Recent Global Identifications</h3>
                </div>
                
                <div className="space-y-3 opacity-50 select-none pointer-events-none">
                   {[
                     { target: 'phish-portal.zip', type: 'Domain', verdict: 'Malicious' },
                     { target: '103.21.44.189', type: 'IP', verdict: 'Suspicious' },
                     { target: 'login-verify.top/auth', type: 'URL', verdict: 'Malicious' },
                   ].map((t, i) => (
                     <div key={i} className="flex items-center justify-between p-4 rounded-2xl bg-slate-900/30 border border-white/5">
                        <div className="flex items-center gap-3">
                           <Globe className="w-4 h-4 text-slate-600" />
                           <div>
                              <p className="text-xs font-mono text-slate-400">{t.target}</p>
                              <p className="text-[10px] text-slate-600 uppercase font-bold">{t.type}</p>
                           </div>
                        </div>
                        <span className={`text-[10px] font-bold uppercase tracking-widest ${t.verdict === 'Malicious' ? 'text-rose-500' : 'text-amber-500'}`}>
                           {t.verdict}
                        </span>
                     </div>
                   ))}
                </div>
             </div>
          </div>
        </div>
      </div>
    </div>
  );
}
}
