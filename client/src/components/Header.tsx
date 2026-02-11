import { Link, useLocation } from "wouter";
import { ShieldCheck, History, LayoutDashboard, Search } from "lucide-react";
import { useState } from "react";

export function Header() {
  const [location] = useLocation();

  const navItems = [
    { href: "/", label: "Dashboard", icon: LayoutDashboard },
    { href: "/analysis", label: "Analyze", icon: Search },
    { href: "/history", label: "History", icon: History },
  ];

  const [open, setOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 w-full border-b border-slate-800/60 bg-slate-950/80 backdrop-blur supports-[backdrop-filter]:bg-slate-950/60">
      <div className="container mx-auto px-4 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-3 group">
          <div className="relative">
            <ShieldCheck className="w-8 h-8 text-emerald-500 transition-transform group-hover:scale-110" />
            <div className="absolute inset-0 bg-emerald-500/20 blur-xl rounded-full opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
          <div>
            <h1 className="font-bold text-lg tracking-tight text-white group-hover:text-emerald-400 transition-colors">
              Elixir Analyzer
            </h1>
            <p className="text-[10px] uppercase tracking-widest text-slate-500 font-mono hidden sm:block">
              Threat Intelligence
            </p>
          </div>
        </Link>

        <nav className="flex items-center gap-1">
          {/* Desktop Nav */}
          <div className="hidden sm:flex items-center gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location === item.href || location.startsWith(item.href + "/");
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={isActive ? "page" : undefined}
                  className={`
                    flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200
                    ${isActive
                      ? "bg-emerald-500/10 text-emerald-400 shadow-[0_0_15px_-5px_rgba(16,185,129,0.3)]"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
                    }
                  `}
                >
                  <Icon className="w-4 h-4" />
                  <span className="hidden sm:inline">{item.label}</span>
                </Link>
              );
            })}
          </div>

          {/* Mobile menu button */}
          <button
            aria-label="Toggle menu"
            onClick={() => setOpen((v) => !v)}
            className="sm:hidden p-2 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M3 12h18M3 6h18M3 18h18"></path>
            </svg>
          </button>

          {/* Mobile menu */}
          {open && (
            <div className="absolute right-4 top-16 bg-slate-950/95 border border-slate-800/60 rounded-lg p-2 flex flex-col gap-1 sm:hidden">
              {navItems.map((item) => (
                <Link key={item.href} href={item.href} className="flex items-center gap-2 px-3 py-2 rounded text-sm text-slate-200 hover:bg-slate-800/40">
                  <item.icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </Link>
              ))}
            </div>
          )}
        </nav>
      </div>
    </header>
  );
}
