import { useHistory, useClearHistory } from "@/hooks/use-analysis";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Trash2, Search, ArrowRight, Clock, Shield } from "lucide-react";
import { format } from "date-fns";
import { Link } from "wouter";
import { motion } from "framer-motion";

export default function History() {
  const { data: history, isLoading } = useHistory();
  const { mutate: clearHistory, isPending: isClearing } = useClearHistory();

  if (isLoading) {
    return <div className="p-8 text-center text-slate-500">Loading history...</div>;
  }

  const isEmpty = !history || history.length === 0;

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl min-h-[calc(100vh-80px)]">
      <motion.div 
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between mb-8"
      >
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <HistoryIcon className="w-8 h-8 text-emerald-500" />
            Scan History
          </h1>
          <p className="text-slate-400 mt-1">Recent threat analysis reports</p>
        </div>
        
        {!isEmpty && (
          <Button 
            variant="destructive" 
            onClick={() => clearHistory()}
            disabled={isClearing}
            className="bg-rose-900/30 text-rose-400 hover:bg-rose-900/50 border border-rose-900/50"
          >
            <Trash2 className="w-4 h-4 mr-2" />
            Clear History
          </Button>
        )}
      </motion.div>

      {isEmpty ? (
        <Card className="glass-card border-dashed border-slate-800 py-20">
          <div className="flex flex-col items-center justify-center text-center">
            <div className="bg-slate-900 p-4 rounded-full mb-4 ring-1 ring-slate-800">
              <Search className="w-8 h-8 text-slate-500" />
            </div>
            <h3 className="text-xl font-medium text-slate-200 mb-2">No scans yet</h3>
            <p className="text-slate-500 max-w-sm mb-6">Start by analyzing a domain, IP address, or URL to see it appear in your history.</p>
            <Link href="/">
              <Button className="bg-emerald-600 hover:bg-emerald-500">Start New Scan</Button>
            </Link>
          </div>
        </Card>
      ) : (
        <Card className="glass-card border-slate-800 overflow-hidden">
          <Table>
            <TableHeader className="bg-slate-900/50">
              <TableRow className="border-slate-800/60 hover:bg-transparent">
                <TableHead className="text-slate-400 font-bold uppercase tracking-widest text-[10px]">Date</TableHead>
                <TableHead className="text-slate-400 font-bold uppercase tracking-widest text-[10px]">Target</TableHead>
                <TableHead className="text-slate-400 font-bold uppercase tracking-widest text-[10px]">Type</TableHead>
                <TableHead className="text-slate-400 font-bold uppercase tracking-widest text-[10px]">Risk Profile</TableHead>
                <TableHead className="text-slate-400 font-bold uppercase tracking-widest text-[10px]">Verdict</TableHead>
                <TableHead className="text-right text-slate-400 font-bold uppercase tracking-widest text-[10px]">Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {history.map((item) => (
                <TableRow key={item.id} className="border-slate-800/60 hover:bg-emerald-500/[0.02] transition-colors group">
                  <TableCell className="text-slate-400 font-mono text-xs">
                    <div className="flex items-center gap-2">
                      <Clock className="w-3.5 h-3.5 text-slate-500" />
                      {item.createdAt ? format(new Date(item.createdAt), "MMM dd, HH:mm") : "-"}
                    </div>
                  </TableCell>
                  <TableCell className="font-medium text-slate-200">
                    <span className="break-all font-mono text-sm">{item.input}</span>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="uppercase text-[10px] tracking-wider border-slate-800 bg-slate-900/40 text-slate-400">
                      {item.type}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <div className="h-1.5 w-20 bg-slate-900 rounded-full overflow-hidden border border-white/5">
                        <div 
                          className={`h-full rounded-full transition-all duration-1000 ${
                            item.riskScore < 30 ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" : 
                            item.riskScore < 70 ? "bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]" : 
                            "bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.5)]"
                          }`} 
                          style={{ width: `${item.riskScore}%` }}
                        />
                      </div>
                      <span className="text-xs font-mono font-bold text-slate-400">{item.riskScore}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge className={`
                      uppercase text-[10px] tracking-widest font-bold px-2 py-0.5 border
                      ${item.riskLevel === 'Safe' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/20' : ''}
                      ${item.riskLevel === 'Suspicious' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20 hover:bg-amber-500/20' : ''}
                      ${item.riskLevel === 'Malicious' ? 'bg-rose-500/10 text-rose-400 border-rose-500/20 hover:bg-rose-500/20' : ''}
                    `}>
                      {item.riskLevel}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Link href={`/analysis/${item.id}`}>
                      <Button size="sm" variant="ghost" className="h-8 w-8 p-0 hover:bg-emerald-500/10 text-slate-500 hover:text-emerald-400 transition-colors">
                        <ArrowRight className="w-4 h-4" />
                      </Button>
                    </Link>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </div>
  );
}

function HistoryIcon({ className }: { className?: string }) {
  return (
    <svg 
      xmlns="http://www.w3.org/2000/svg" 
      viewBox="0 0 24 24" 
      fill="none" 
      stroke="currentColor" 
      strokeWidth="2" 
      strokeLinecap="round" 
      strokeLinejoin="round" 
      className={className}
    >
      <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
      <path d="M3 3v5h5" />
      <path d="M12 7v5l4 2" />
    </svg>
  );
}
