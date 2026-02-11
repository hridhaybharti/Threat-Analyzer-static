import { CheckCircle2, AlertTriangle, XCircle, Shield, TrendingUp, TrendingDown } from "lucide-react";
import { type HeuristicResult } from "@shared/schema";
import { Badge } from "@/components/ui/badge";

interface HeuristicListProps {
  heuristics: HeuristicResult[];
  riskContribution?: number;
  trustContribution?: number;
}

export function HeuristicList({ heuristics, riskContribution = 0, trustContribution = 0 }: HeuristicListProps) {
  if (!heuristics?.length) return null;

  return (
    <div className="space-y-4">
      {/* Contribution Summary */}
      {(riskContribution > 0 || trustContribution > 0) && (
        <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-slate-800/30 border border-slate-700">
          {riskContribution > 0 && (
            <div className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-rose-500" />
              <div className="text-sm">
                <p className="text-slate-400">Risk Added</p>
                <p className="font-mono font-bold text-rose-400">+{riskContribution}</p>
              </div>
            </div>
          )}
          {trustContribution > 0 && (
            <div className="flex items-center gap-2">
              <TrendingDown className="w-4 h-4 text-emerald-500" />
              <div className="text-sm">
                <p className="text-slate-400">Trust Added</p>
                <p className="font-mono font-bold text-emerald-400">+{trustContribution}</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Heuristics List */}
      <div className="space-y-3">
        {heuristics.map((h, idx) => (
          <div 
            key={idx}
            className={`flex items-start gap-4 p-4 rounded-xl border transition-colors ${
              h.status === 'pass' 
                ? 'bg-emerald-950/20 border-emerald-900/40 hover:border-emerald-800/60' 
                : h.status === 'warn'
                ? 'bg-amber-950/20 border-amber-900/40 hover:border-amber-800/60'
                : 'bg-rose-950/20 border-rose-900/40 hover:border-rose-800/60'
            }`}
          >
            <div className="mt-1">
              {h.status === 'pass' && <CheckCircle2 className="w-5 h-5 text-emerald-500" />}
              {h.status === 'warn' && <AlertTriangle className="w-5 h-5 text-amber-500" />}
              {h.status === 'fail' && <XCircle className="w-5 h-5 text-rose-500" />}
            </div>
            
            <div className="flex-1">
              <div className="flex items-center justify-between mb-1">
                <h4 className="font-medium text-slate-200">{h.name}</h4>
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={`
                    uppercase text-[10px] tracking-wider font-mono
                    ${h.status === 'pass' ? 'border-emerald-500/20 text-emerald-400 bg-emerald-500/10' : ''}
                    ${h.status === 'warn' ? 'border-amber-500/20 text-amber-400 bg-amber-500/10' : ''}
                    ${h.status === 'fail' ? 'border-rose-500/20 text-rose-400 bg-rose-500/10' : ''}
                  `}>
                    {h.status}
                  </Badge>
                  {h.scoreImpact !== 0 && (
                    <Badge variant="outline" className={`
                      text-[10px] font-mono
                      ${h.scoreImpact > 0 ? 'border-rose-500/30 text-rose-400 bg-rose-500/5' : 'border-emerald-500/30 text-emerald-400 bg-emerald-500/5'}
                    `}>
                      {h.scoreImpact > 0 ? '+' : ''}{h.scoreImpact}
                    </Badge>
                  )}
                </div>
              </div>
              <p className="text-sm text-slate-400 leading-relaxed">{h.description}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
