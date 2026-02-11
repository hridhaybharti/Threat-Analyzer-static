import React, { useState } from "react";
import { useRoute, useLocation, Link } from "wouter";
import { useAnalysis } from "@/hooks/use-analysis";

import { RiskGauge } from "@/components/RiskGauge";
import { HeuristicList } from "@/components/HeuristicList";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";

import {
  ArrowLeft,
  Globe,
  ShieldAlert,
  CheckCircle,
  ExternalLink,
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
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      <Button
        variant="ghost"
        onClick={() => setLocation("/")}
        className="mb-8 text-slate-400 hover:text-emerald-400"
      >
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Dashboard
      </Button>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* LEFT */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="space-y-6"
        >
          <Card className="border-slate-800">
            <CardHeader className="items-center">
              <RiskGauge
                score={analysis.riskScore}
                level={displayLevel}
                confidence={
                  typeof details.confidence === "number"
                    ? details.confidence / 100
                    : 0
                }
                size={220}
              />
              <div className={`text-2xl font-bold mt-4 ${statusColor}`}>
                {displayLevel}
              </div>
              <div className="text-xs text-slate-500 uppercase tracking-widest">
                Verdict
              </div>
            </CardHeader>

            <CardContent className="space-y-4">
              <div>
                <div className="text-xs text-slate-500 uppercase mb-1">
                  Target
                </div>
                <div className="flex items-center gap-2 bg-slate-900 p-3 rounded border border-slate-800">
                  <Globe className="w-4 h-4 text-slate-400" />
                  <code className="text-sm text-slate-200 break-all">
                    {analysis.input}
                  </code>
                </div>
              </div>

              <div className="flex justify-between text-sm pt-4 border-t border-slate-800">
                <span className="text-slate-500">Scan Time</span>
                <span className="text-slate-300 font-mono">
                  {analysis.createdAt
                    ? format(
                        new Date(analysis.createdAt),
                        "HH:mm:ss dd/MM/yyyy"
                      )
                    : "N/A"}
                </span>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-800">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-emerald-500" />
                Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="text-slate-400 text-sm">
              {analysis.summary}
            </CardContent>
          </Card>
        </motion.div>

        {/* RIGHT */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="lg:col-span-2"
        >
          <Tabs defaultValue="heuristics">
            <TabsList className="mb-6">
              <TabsTrigger value="heuristics">
                Security Heuristics
              </TabsTrigger>
              <TabsTrigger value="technical">
                Technical Data
              </TabsTrigger>
            </TabsList>

            <TabsContent value="heuristics">
              <Card className="border-slate-800">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-emerald-500" />
                    Checks
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <HeuristicList
                    heuristics={details.heuristics || []}
                    riskContribution={details.risk_contribution}
                    trustContribution={details.trust_contribution}
                  />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="technical" className="space-y-6">
              {details.threatIntelligence ? (
                <>
                  <VirusTotalCard vt={details.threatIntelligence.virusTotal} />

                  {details.threatIntelligence.ipReputation && (
                    <IPReputationCard
                      ip={details.threatIntelligence.ipReputation}
                    />
                  )}

                  <AbuseIPDBCard abuse={details.threatIntelligence.abuseIPDB} />

                  <IPLocationCard loc={details.threatIntelligence.ipLocation} />

                  {details.threatIntelligence.whoisData && (
                    <WhoisCard
                      whois={details.threatIntelligence.whoisData}
                      input={analysis.input}
                    />
                  )}

                  {details.threatIntelligence.detectionEngines?.length >
                    0 && (
                    <DetectionEnginesCard
                      engines={details.threatIntelligence.detectionEngines}
                    />
                  )}

                  {details.threatIntelligence.urlReputation?.length >
                    0 && (
                    <URLReputationCard
                      reports={details.threatIntelligence.urlReputation}
                    />
                  )}
                </>
              ) : (
                <div className="text-slate-400 text-sm p-4 rounded border border-slate-800">
                  Threat intelligence data not yet available.
                </div>
              )}
            </TabsContent>
          </Tabs>
        </motion.div>
      </div>
    </div>
  );
}

/* =========================
   Helper Components
========================= */

function IPReputationCard({ ip }: { ip: any }) {
  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest">
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
          <div className="mt-4 p-3 bg-rose-500/10 rounded border border-rose-500/30">
            <div className="text-xs text-rose-400 font-semibold mb-2">
              Threat Categories
            </div>
            <div className="flex flex-wrap gap-2">
              {ip.threats.map((t: string, i: number) => (
                <span
                  key={i}
                  className="text-xs bg-rose-500/20 text-rose-300 px-2 py-1 rounded"
                >
                  {t}
                </span>
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
          <p className="mb-2">Intelligence engine offline.</p>
          <p className="text-[11px] leading-relaxed opacity-70">
            To enable deep multi-engine scanning, add your <code className="text-amber-200/80">VIRUSTOTAL_API_KEY</code> to the <code className="text-amber-200/80">.env</code> file and restart the server.
          </p>
        </CardContent>
      </Card>
    );
  }

  const stats = vt?.stats || {};
  const items: Array<{ label: string; value: any; cls: string }> = [
    { label: "Malicious", value: stats.malicious, cls: "text-rose-400 bg-rose-500/10" },
    { label: "Suspicious", value: stats.suspicious, cls: "text-amber-400 bg-amber-500/10" },
    { label: "Harmless", value: stats.harmless, cls: "text-emerald-400 bg-emerald-500/10" },
    { label: "Undetected", value: stats.undetected, cls: "text-slate-300 bg-slate-800/60" },
  ].filter((x) => typeof x.value === "number");

  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest flex items-center justify-between">
          VirusTotal
          {vt?.permalink && (
            <a
              href={vt.permalink}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-slate-400 hover:text-emerald-400 inline-flex items-center gap-1"
            >
              Open
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {vt?.ok === false && vt?.error ? (
          <div className="text-sm text-slate-400">{vt.error}</div>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-4">
              <InfoBlock label="Type" value={vt.type} />
              <InfoBlock label="Reputation" value={vt.reputation?.toString()} />
              <InfoBlock label="Last Analysis" value={vt.lastAnalysisDate} />
            </div>
            {items.length > 0 && (
              <div className="flex flex-wrap gap-2 pt-2">
                {items.map((it) => (
                  <span key={it.label} className={`px-2 py-1 rounded text-xs font-mono ${it.cls}`}>
                    {it.label}: {it.value}
                  </span>
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
          <p className="mb-2">IP Reputation data restricted.</p>
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
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest flex items-center justify-between">
          AbuseIPDB
          {link && (
            <a
              href={link}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-slate-400 hover:text-emerald-400 inline-flex items-center gap-1"
            >
              Open
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-4">
          <InfoBlock label="IP Address" value={ip} />
          <InfoBlock label="Country" value={abuse?.countryCode} />
          <InfoBlock
            label="Abuse Score"
            value={
              typeof abuse?.abuseConfidenceScore === "number"
                ? `${Math.round(abuse.abuseConfidenceScore)}%`
                : undefined
            }
          />
          <InfoBlock label="Reports" value={abuse?.totalReports?.toString()} />
          <InfoBlock label="Usage Type" value={abuse?.usageType} />
          <InfoBlock label="ISP" value={abuse?.isp} />
          <InfoBlock label="Domain" value={abuse?.domain} />
          <InfoBlock label="Whitelisted" value={typeof abuse?.isWhitelisted === "boolean" ? String(abuse.isWhitelisted) : undefined} />
          <InfoBlock label="Last Reported" value={abuse?.lastReportedAt || undefined} />
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
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest flex items-center justify-between">
          IP Location
          {loc?.googleMapsUrl && (
            <a
              href={loc.googleMapsUrl}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-slate-400 hover:text-emerald-400 inline-flex items-center gap-1"
            >
              Open Map
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {loc?.error ? (
          <div className="text-sm text-slate-400">{loc.error}</div>
        ) : (
          <>
            {embedUrl && (
              <div className="aspect-video w-full overflow-hidden rounded border border-slate-800 bg-slate-950">
                <iframe
                  title="IP location map"
                  src={embedUrl}
                  className="w-full h-full"
                  loading="lazy"
                  referrerPolicy="no-referrer-when-downgrade"
                />
              </div>
            )}
            <div className="grid grid-cols-2 gap-4">
              <InfoBlock label="IP Address" value={loc?.ip} />
              <InfoBlock label="City" value={loc?.city} />
              <InfoBlock label="Region" value={loc?.region} />
              <InfoBlock label="Country" value={loc?.country} />
              <InfoBlock label="Latitude" value={loc?.latitude?.toString()} />
              <InfoBlock label="Longitude" value={loc?.longitude?.toString()} />
              <InfoBlock label="Accuracy" value={loc?.accuracy} />
            </div>
            <div className="text-xs text-slate-500">
              IP geolocation is approximate; it may not represent the exact physical location.
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
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest">
          WHOIS Information
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-4">
          <InfoBlock label="Domain" value={whois.domain || input} />
          <InfoBlock label="Registrar" value={whois.registrar} />
          <InfoBlock label="Created" value={whois.creation_date} />
          <InfoBlock
            label="Age (Days)"
            value={whois.age_days?.toString()}
          />
        </div>

        {rawText && (
          <div>
            <button
              className="text-xs text-slate-400 hover:text-emerald-400"
              onClick={() => setShowRaw(!showRaw)}
            >
              {showRaw ? "Hide raw WHOIS" : "Show raw WHOIS"}
            </button>
            {showRaw && (
              <pre className="mt-2 p-3 bg-slate-900 rounded text-xs overflow-auto max-h-72 font-mono text-slate-300">
                {rawText}
              </pre>
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
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest">
          URL Reputation
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {reports.map((r, i) => (
          <div
            key={i}
            className="p-3 rounded border border-slate-800 bg-slate-900"
          >
            <div className="flex justify-between mb-1">
              <span className="font-semibold">{r.source}</span>
              <span className="font-mono text-sm">{r.riskScore}/100</span>
            </div>
            <div className="text-sm text-slate-400">{r.details}</div>
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
    <div>
      <div className="text-xs text-slate-500">{label}</div>
      <div className="text-slate-200">{value}</div>
    </div>
  );
}

function AnalysisLoading() {
  return (
    <div className="flex flex-col items-center py-24 space-y-6">
      <div className="w-16 h-16 border-4 border-emerald-500 border-t-transparent rounded-full animate-spin" />
      <Skeleton className="h-4 w-64 bg-slate-800" />
      <Skeleton className="h-4 w-48 bg-slate-800" />
    </div>
  );
}

function AnalysisError() {
  return (
    <div className="flex flex-col items-center py-24 text-center">
      <ShieldAlert className="w-16 h-16 text-rose-500 mb-4" />
      <h2 className="text-2xl font-bold text-white mb-2">
        Analysis Not Found
      </h2>
      <p className="text-slate-400 mb-6">
        The analysis does not exist or failed to load.
      </p>
      <Link href="/">
        <Button>Go Home</Button>
      </Link>
    </div>
  );
}
