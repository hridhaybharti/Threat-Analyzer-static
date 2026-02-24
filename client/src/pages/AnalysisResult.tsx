import React, { useState } from "react";
import { useRoute, useLocation, Link } from "wouter";
import { useAnalysis } from "@/hooks/use-analysis";

import { RiskGauge } from "@/components/RiskGauge";
import { HeuristicList } from "@/components/HeuristicList";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";

import {
  ArrowLeft,
  Globe,
  ShieldAlert,
  CheckCircle,
  ExternalLink,
  FileDown,
  Database,
  Mail,
} from "lucide-react";

import { format } from "date-fns";
import { motion } from "framer-motion";
import type { AnalysisDetails } from "@shared/schema";

/* =========================
   Main Page
========================= */

export default function AnalysisResult() {
  const [, params] = useRoute<{ id: string }>("/analysis/:id");
  const [, setLocation] = useLocation();

  if (!params?.id) return <AnalysisError />;

  const id = Number(params.id);
  const { data: analysis, isLoading, error } = useAnalysis(id);

  if (isLoading) return <AnalysisLoading />;
  if (error || !analysis) return <AnalysisError />;

  const details = (analysis.details || {}) as AnalysisDetails;

  // Normalize backend risk labels
  const rawLevel = String(analysis.riskLevel || "");
  const upper = rawLevel.toUpperCase();
  let displayLevel = rawLevel || "Unknown";
  let statusColor = "text-emerald-500";

  if (upper.includes("MALIC")) {
    displayLevel = "Malicious";
    statusColor = "text-rose-500";
  } else if (upper.includes("SUSPIC")) {
    displayLevel = "Suspicious";
    statusColor = "text-amber-500";
  } else if (upper.includes("LOW") || upper.includes("RISK")) {
    displayLevel = "Low Risk";
    statusColor = "text-amber-400";
  } else if (upper.includes("BENIGN") || upper.includes("CLEAN")) {
    displayLevel = "Benign";
    statusColor = "text-emerald-500";
  }

  return (
    <div className="min-h-screen bg-[#020617] bg-grid-white/[0.02] relative overflow-hidden pb-20">
      {/* Background Ambience */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-[500px] bg-emerald-500/5 blur-[120px] rounded-full pointer-events-none" />

      <div className="container mx-auto px-4 py-8 max-w-7xl relative z-10">
        <div className="flex items-center justify-between mb-10">
          <Button
            variant="ghost"
            onClick={() => setLocation("/")}
            className="text-slate-400 hover:text-emerald-400 hover:bg-emerald-500/5 group transition-all"
          >
            <ArrowLeft className="w-4 h-4 mr-2 group-hover:-translate-x-1 transition-transform" />
            Back to Hub
          </Button>

          <div className="flex gap-3">
             <Badge variant="outline" className="bg-slate-900/50 border-white/5 py-1.5 px-4 font-mono text-[11px] uppercase tracking-tighter text-slate-500">
               ID: {id}
             </Badge>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
          {/* LEFT COLUMN - VERDICT CARD */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="xl:col-span-4 space-y-6"
          >
            <Card className="glass-card border-white/5 overflow-hidden">
              <div className={`h-1.5 w-full ${
                upper.includes('MALIC') ? 'bg-rose-500 shadow-[0_0_15px_rgba(244,63,94,0.5)]' : 
                upper.includes('SUSPIC') ? 'bg-amber-500 shadow-[0_0_15px_rgba(245,158,11,0.5)]' : 'bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.5)]'
              }`} />
              
              <CardHeader className="items-center pb-2">
                <RiskGauge
                  score={analysis.riskScore}
                  level={displayLevel}
                  confidence={
                    typeof details.confidence === "number"
                      ? details.confidence / 100
                      : 0
                  }
                  size={240}
                />
                <div className="mt-6 flex flex-col items-center gap-1">
                  <div className={`text-4xl font-black tracking-tighter uppercase ${statusColor}`}>
                    {displayLevel}
                  </div>
                  <div className="text-[10px] text-slate-500 uppercase tracking-[0.2em] font-bold">
                    Safety Verdict
                  </div>
                </div>
              </CardHeader>

              <CardContent className="space-y-6 px-8 pb-8">
                <div className="space-y-2">
                  <div className="text-[10px] text-slate-500 uppercase font-bold tracking-widest">
                    Investigated Target
                  </div>
                  <div className="flex items-center gap-3 bg-slate-950/50 p-4 rounded-2xl border border-white/5 shadow-inner group/target">
                    {analysis.type === 'email' ? <Mail className="w-5 h-5 text-slate-500" /> : <Globe className="w-5 h-5 text-slate-500 group-hover/target:text-emerald-500 transition-colors" />}
                    <code className="text-sm text-slate-200 break-all font-mono">
                      {analysis.input}
                    </code>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 py-6 border-y border-white/5">
                   <div className="space-y-1">
                      <p className="text-[10px] text-slate-500 uppercase font-bold">Scanner Mode</p>
                      <p className="text-sm font-medium text-slate-200 uppercase">{analysis.type}</p>
                   </div>
                   <div className="space-y-1 text-right">
                      <p className="text-[10px] text-slate-500 uppercase font-bold">Scan Time</p>
                      <p className="text-sm font-medium text-slate-200 font-mono">
                        {analysis.createdAt ? format(new Date(analysis.createdAt), "HH:mm:ss") : "N/A"}
                      </p>
                   </div>
                </div>

                {/* Export Action */}
                <Button 
                  onClick={() => window.open(`/api/analysis/${id}/export`, '_blank')}
                  className="w-full h-14 bg-slate-100 hover:bg-white text-slate-950 font-bold rounded-2xl gap-3 shadow-[0_10px_30px_rgba(255,255,255,0.1)] transition-all active:scale-95"
                >
                  <FileDown className="w-5 h-5" />
                  Generate Forensic PDF
                </Button>
              </CardContent>
            </Card>

            {/* SUMMARY CARD */}
            <Card className="glass-card border-white/5 p-6 space-y-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-emerald-500/10 rounded-lg">
                  <ShieldAlert className="w-5 h-5 text-emerald-500" />
                </div>
                <h3 className="font-bold text-slate-200">Intelligence Summary</h3>
              </div>
              <p className="text-slate-400 text-sm leading-relaxed">
                {analysis.summary}
              </p>
            </Card>
          </motion.div>

          {/* RIGHT COLUMN - TABS */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="xl:col-span-8"
          >
            <Tabs defaultValue="heuristics" className="w-full">
              <TabsList className="bg-slate-950/50 p-1.5 rounded-2xl border border-white/5 mb-8 w-full max-w-md">
                <TabsTrigger value="heuristics" className="rounded-xl flex-1 data-[state=active]:bg-emerald-500/10 data-[state=active]:text-emerald-400 transition-all">
                  Security Heuristics
                </TabsTrigger>
                <TabsTrigger value="technical" className="rounded-xl flex-1 data-[state=active]:bg-blue-500/10 data-[state=active]:text-blue-400 transition-all">
                  Technical Data
                </TabsTrigger>
              </TabsList>

              <TabsContent value="heuristics" className="mt-0">
                <Card className="glass-card border-white/5 p-8">
                  <div className="flex items-center justify-between mb-8">
                    <div className="space-y-1">
                      <h2 className="text-2xl font-bold text-white tracking-tight">Logic Chain Analysis</h2>
                      <p className="text-sm text-slate-500">Evidence discovered by Elixir's structural inspection engine.</p>
                    </div>
                    <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20 py-1.5 px-4 rounded-lg font-mono">
                      {details.heuristics?.length || 0} Signals
                    </Badge>
                  </div>
                  
                  <HeuristicList
                    heuristics={details.heuristics || []}
                    riskContribution={details.risk_contribution}
                    trustContribution={details.trust_contribution}
                  />
                </Card>
              </TabsContent>

              <TabsContent value="technical" className="mt-0 space-y-6">
                {details.threatIntelligence ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <VirusTotalCard vt={details.threatIntelligence.virusTotal} />

                    {details.threatIntelligence.ipReputation && (
                      <IPReputationCard ip={details.threatIntelligence.ipReputation} />
                    )}

                    <AbuseIPDBCard abuse={details.threatIntelligence.abuseIPDB} />

                    <div className="md:col-span-2">
                       <IPLocationCard loc={details.threatIntelligence.ipLocation} />
                    </div>

                    {details.threatIntelligence.whoisData && (
                      <WhoisCard whois={details.threatIntelligence.whoisData} input={analysis.input} />
                    )}
                    
                    {details.threatIntelligence.urlReputation?.length > 0 && (
                      <div className="md:col-span-2">
                        <URLReputationCard reports={details.threatIntelligence.urlReputation} />
                      </div>
                    )}
                  </div>
                ) : (
                  <Card className="glass-card border-white/5 p-12 flex flex-col items-center justify-center text-center space-y-4">
                    <div className="p-4 bg-slate-900 rounded-full">
                      <Database className="w-10 h-10 text-slate-700" />
                    </div>
                    <div className="space-y-1">
                      <h4 className="text-lg font-bold text-white">No Intelligence Data</h4>
                      <p className="text-sm text-slate-500 max-w-xs mx-auto">External OSINT providers did not return any structured results for this target.</p>
                    </div>
                  </Card>
                )}
              </TabsContent>
            </Tabs>
          </motion.div>
        </div>
      </div>
    </div>
  );
}

/* =========================
   Helper Components
========================= */

function IPReputationCard({ ip }: { ip: any }) {
  return (
    <Card className="border-slate-800 bg-slate-900/50">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest flex items-center gap-2">
           <Database className="w-4 h-4 text-blue-400" />
           IP Reputation
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-4">
          <InfoBlock label="IP Address" value={ip.ip} />
          <InfoBlock label="Status" value={ip.status} />
          <InfoBlock
            label="Abuse Score"
            value={
              typeof ip.abuseConfidenceScore === "number"
                ? `${Math.round(ip.abuseConfidenceScore)}%`
                : undefined
            }
          />
          <InfoBlock label="Reports" value={ip.totalReports?.toString()} />
          <InfoBlock label="ISP" value={ip.isp} />
          <InfoBlock label="Reverse DNS" value={ip.domain} />
        </div>

        {ip.threats?.length > 0 && (
          <div className="mt-4 p-3 bg-rose-500/5 rounded-xl border border-rose-500/20">
            <div className="text-[10px] text-rose-400 font-bold uppercase tracking-widest mb-2">
              Threat Vector Match
            </div>
            <div className="flex flex-wrap gap-1.5">
              {ip.threats.map((t: string, i: number) => (
                <Badge
                  key={i}
                  variant="outline"
                  className="text-[10px] bg-rose-500/10 text-rose-400 border-rose-500/20"
                >
                  {t}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function VirusTotalCard({ vt }: { vt: any }) {
  if (!vt) {
    return (
      <Card className="border-slate-800 bg-amber-950/5">
        <CardHeader>
          <CardTitle className="text-sm uppercase tracking-widest flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-amber-500" />
            VirusTotal
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-slate-400">
          <p className="mb-2 font-medium">Intelligence engine offline.</p>
          <p className="text-[11px] leading-relaxed opacity-70">
            To enable deep multi-engine scanning, add your <code className="text-amber-200/80">VIRUSTOTAL_API_KEY</code> to the <code className="text-amber-200/80">.env</code> file and restart the server.
          </p>
        </CardContent>
      </Card>
    );
  }

  const stats = vt?.stats || {};
  const items: Array<{ label: string; value: any; cls: string }> = [
    { label: "Malicious", value: stats.malicious, cls: "text-rose-400 bg-rose-500/10 border-rose-500/20" },
    { label: "Suspicious", value: stats.suspicious, cls: "text-amber-400 bg-amber-500/10 border-amber-500/20" },
    { label: "Harmless", value: stats.harmless, cls: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" },
    { label: "Undetected", value: stats.undetected, cls: "text-slate-300 bg-slate-800/60 border-white/5" },
  ].filter((x) => typeof x.value === "number");

  return (
    <Card className="border-white/5 bg-slate-900/50 overflow-hidden">
      <CardHeader className="border-b border-white/5">
        <CardTitle className="text-xs uppercase tracking-[0.2em] font-bold flex items-center justify-between">
          <div className="flex items-center gap-2">
             <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
             VirusTotal Intel
          </div>
          {vt?.permalink && (
            <a
              href={vt.permalink}
              target="_blank"
              rel="noreferrer"
              className="text-[10px] text-slate-500 hover:text-emerald-400 uppercase tracking-widest transition-colors"
            >
              Raw Feed
            </a>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="p-6 space-y-4">
        {vt?.ok === false && vt?.error ? (
          <div className="text-xs text-rose-400 bg-rose-400/5 p-3 rounded-lg border border-rose-400/20">{vt.error}</div>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-4">
              <InfoBlock label="Detection Type" value={vt.type} />
              <InfoBlock label="Community Score" value={vt.reputation?.toString()} />
            </div>
            {items.length > 0 && (
              <div className="grid grid-cols-2 gap-2 pt-2">
                {items.map((it) => (
                  <div key={it.label} className={`flex items-center justify-between px-3 py-2 rounded-xl border text-[10px] font-bold uppercase tracking-wider ${it.cls}`}>
                    <span>{it.label}</span>
                    <span>{it.value}</span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function AbuseIPDBCard({ abuse }: { abuse: any }) {
  if (!abuse) {
    return (
      <Card className="border-slate-800 bg-amber-950/5">
        <CardHeader>
          <CardTitle className="text-sm uppercase tracking-widest flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-amber-500" />
            AbuseIPDB
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-slate-400">
          <p className="mb-2 font-medium">IP Reputation data restricted.</p>
          <p className="text-[11px] leading-relaxed opacity-70">
            Configure <code className="text-amber-200/80">ABUSEIPDB_API_KEY</code> in your environment to identify malicious IP behavior and abuse history.
          </p>
        </CardContent>
      </Card>
    );
  }

  const ip = abuse?.ipAddress;
  const link = ip ? `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}` : null;

  return (
    <Card className="border-white/5 bg-slate-900/50">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-500" />
            AbuseIPDB Feed
          </div>
          {link && (
            <a
              href={link}
              target="_blank"
              rel="noreferrer"
              className="text-[10px] text-slate-500 hover:text-emerald-400 transition-colors"
            >
              Verify External
            </a>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 p-6">
        <div className="grid grid-cols-2 gap-4">
          <InfoBlock label="Observed IP" value={ip} />
          <InfoBlock label="Origin" value={abuse?.countryCode} />
          <InfoBlock
            label="Confidence"
            value={
              typeof abuse?.abuseConfidenceScore === "number"
                ? `${Math.round(abuse.abuseConfidenceScore)}%`
                : undefined
            }
          />
          <InfoBlock label="Abuse Reports" value={abuse?.totalReports?.toString()} />
        </div>
      </CardContent>
    </Card>
  );
}

function IPLocationCard({ loc }: { loc: any }) {
  if (!loc) {
    return (
      <Card className="border-slate-800 bg-slate-900/20">
        <CardHeader>
          <CardTitle className="text-sm uppercase tracking-widest flex items-center gap-2">
            <Globe className="w-4 h-4 text-slate-500" />
            IP Location
          </CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-slate-500 italic">
          Geolocation data is only calculated for IP-based targets.
        </CardContent>
      </Card>
    );
  }

  const lat = typeof loc?.latitude === "number" ? loc.latitude : null;
  const lng = typeof loc?.longitude === "number" ? loc.longitude : null;
  const embedUrl =
    lat !== null && lng !== null
      ? `https://www.google.com/maps?q=${lat},${lng}&z=12&output=embed`
      : null;

  return (
    <Card className="border-white/5 bg-slate-900/40">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest flex items-center justify-between">
          Geospatial Intelligence
          {loc?.googleMapsUrl && (
            <a
              href={loc.googleMapsUrl}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-slate-400 hover:text-emerald-400 inline-flex items-center gap-1"
            >
              View Satellite
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6 p-6">
        {loc?.error ? (
          <div className="text-sm text-slate-400">{loc.error}</div>
        ) : (
          <>
            {embedUrl && (
              <div className="aspect-video w-full overflow-hidden rounded-2xl border border-white/5 bg-slate-950 shadow-2xl">
                <iframe
                  title="IP location map"
                  src={embedUrl}
                  className="w-full h-full grayscale invert opacity-80"
                  loading="lazy"
                  referrerPolicy="no-referrer-when-downgrade"
                />
              </div>
            )}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <InfoBlock label="City" value={loc?.city} />
              <InfoBlock label="Region" value={loc?.region} />
              <InfoBlock label="Country" value={loc?.country} />
              <InfoBlock label="Accuracy" value={loc?.accuracy} />
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function WhoisCard({ whois, input }: { whois: any; input: string }) {
  const [showRaw, setShowRaw] = useState(false);
  const rawText =
    whois?.raw || whois?.raw_text || whois?.whois_raw || null;

  return (
    <Card className="border-white/5 bg-slate-900/50">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest flex items-center gap-2">
           <Clock className="w-4 h-4 text-emerald-500" />
           Ownership Lifecycle
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 p-6">
        <div className="grid grid-cols-2 gap-4">
          <InfoBlock label="Registered Domain" value={whois.domain || input} />
          <InfoBlock label="Primary Registrar" value={whois.registrar} />
          <InfoBlock label="Activation Date" value={whois.registrationDate} />
          <InfoBlock
            label="Domain Age"
            value={whois.ageInDays ? `${whois.ageInDays} Days` : undefined}
          />
        </div>

        {rawText && (
          <div className="pt-4 border-t border-white/5">
            <button
              className="text-[10px] uppercase font-bold tracking-widest text-slate-500 hover:text-emerald-400 transition-colors"
              onClick={() => setShowRaw(!showRaw)}
            >
              {showRaw ? "Collapse Registry Records" : "View Raw Registry Records"}
            </button>
            {showRaw && (
              <motion.pre 
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                className="mt-4 p-4 bg-slate-950 rounded-xl text-[11px] overflow-auto max-h-72 font-mono text-slate-400 border border-white/5 leading-relaxed shadow-inner"
              >
                {rawText}
              </motion.pre>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function DetectionEnginesCard({ engines }: { engines: any[] }) {
  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest">
          Reputation Engines
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {engines.map((engine, i) => {
          const color =
            engine.result === "malicious"
              ? "text-rose-400 bg-rose-500/10"
              : engine.result === "suspicious"
              ? "text-amber-400 bg-amber-500/10"
              : "text-emerald-400 bg-emerald-500/10";

          return (
            <div
              key={i}
              className="flex items-center justify-between p-2 bg-slate-900 rounded text-sm"
            >
              <div className="text-slate-300">{engine.engine}</div>
              <div className={`px-2 py-1 rounded text-xs font-mono ${color}`}>
                {(engine.result || "unknown").toUpperCase()}
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function URLReputationCard({ reports }: { reports: any[] }) {
  return (
    <Card className="border-white/5 bg-slate-900/50">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest">
          Contextual URL Intelligence
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 p-6">
        {reports.map((r, i) => (
          <div
            key={i}
            className="p-4 rounded-2xl border border-white/5 bg-slate-950/50 shadow-inner"
          >
            <div className="flex justify-between mb-2">
              <span className="font-bold text-slate-200">{r.source}</span>
              <Badge variant="outline" className="font-mono text-[10px] border-emerald-500/30 text-emerald-400">
                {r.riskScore}/100
              </Badge>
            </div>
            <div className="text-xs text-slate-400 leading-relaxed">{r.details}</div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function InfoBlock({
  label,
  value,
}: {
  label: string;
  value?: React.ReactNode;
}) {
  if (value === undefined || value === null) return null;
  return (
    <div className="space-y-1">
      <div className="text-[10px] text-slate-500 uppercase font-bold tracking-tight">{label}</div>
      <div className="text-sm text-slate-200 font-medium">{value}</div>
    </div>
  );
}

function AnalysisLoading() {
  return (
    <div className="flex flex-col items-center py-32 space-y-8 min-h-screen bg-[#020617]">
      <div className="relative">
        <div className="w-20 h-20 border-4 border-emerald-500/20 rounded-full" />
        <div className="absolute inset-0 w-20 h-20 border-4 border-emerald-500 border-t-transparent rounded-full animate-spin" />
      </div>
      <div className="space-y-3 flex flex-col items-center">
        <Skeleton className="h-4 w-64 bg-slate-800" />
        <Skeleton className="h-3 w-48 bg-slate-800 opacity-50" />
      </div>
    </div>
  );
}

function AnalysisError() {
  return (
    <div className="flex flex-col items-center py-32 text-center min-h-screen bg-[#020617]">
      <div className="p-6 bg-rose-500/10 rounded-full mb-6">
        <ShieldAlert className="w-16 h-16 text-rose-500" />
      </div>
      <h2 className="text-3xl font-black text-white tracking-tighter mb-2">
        INTEL RETRIEVAL FAILED
      </h2>
      <p className="text-slate-400 max-w-sm mb-10 leading-relaxed">
        The requested forensic report ID could not be located in the database or a decryption error occurred.
      </p>
      <Link href="/">
        <Button className="bg-white text-slate-950 font-bold px-10 h-14 rounded-2xl hover:bg-slate-200 transition-all">
          Return to Hub
        </Button>
      </Link>
    </div>
  );
}
