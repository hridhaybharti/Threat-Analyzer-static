import { motion } from "framer-motion";

interface RiskGaugeProps {
  score: number;
  level: string;
  confidence?: number;
  size?: number;
}

export function RiskGauge({ score, level, confidence = 0, size = 200 }: RiskGaugeProps) {
  const radius = size * 0.4;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  let colorClass = "text-emerald-500";
  let glowClass = "shadow-emerald-500/20";
  
  if (score > 30 && score <= 70) {
    colorClass = "text-amber-500";
    glowClass = "shadow-amber-500/20";
  } else if (score > 70) {
    colorClass = "text-rose-500";
    glowClass = "shadow-rose-500/20";
  }

  return (
    <div className="relative flex flex-col items-center justify-center" style={{ width: size, height: size }}>
      {/* Background Circle */}
      <svg className="transform -rotate-90 w-full h-full">
        <circle
          className="text-slate-800"
          strokeWidth="12"
          stroke="currentColor"
          fill="transparent"
          r={radius}
          cx={size / 2}
          cy={size / 2}
        />
        {/* Progress Circle */}
        <motion.circle
          className={colorClass}
          strokeWidth="12"
          strokeDasharray={circumference}
          strokeDashoffset={circumference} // Start empty
          animate={{ strokeDashoffset }}
          transition={{ duration: 1.5, ease: "easeOut" }}
          strokeLinecap="round"
          stroke="currentColor"
          fill="transparent"
          r={radius}
          cx={size / 2}
          cy={size / 2}
        />
      </svg>
      
      {/* Center Text */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.div 
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.5 }}
          className={`text-5xl font-bold font-mono tracking-tighter ${colorClass} drop-shadow-lg`}
        >
          {score}
        </motion.div>
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.8 }}
          className="text-xs uppercase tracking-widest text-slate-400 mt-2 font-semibold"
        >
          Risk Score
        </motion.div>
        {confidence > 0 && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.0 }}
            className="text-[10px] uppercase tracking-widest text-emerald-400 mt-3 font-mono"
          >
            {Math.round(confidence * 100)}% confident
          </motion.div>
        )}
      </div>

      {/* Decorative Glow */}
      <div className={`absolute inset-0 rounded-full blur-3xl opacity-10 bg-current pointer-events-none ${colorClass}`} />
    </div>
  );
}
