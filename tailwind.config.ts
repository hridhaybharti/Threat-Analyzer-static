import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./client/index.html", "./client/src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      borderRadius: {
        lg: ".5625rem", /* 9px */
        md: ".375rem", /* 6px */
        sm: ".1875rem", /* 3px */
      },
      colors: {
        // Flat / base colors (regular buttons) - moved from CSS variables to tokens
        background: "hsl(222 47% 11% / <alpha-value>)",
        foreground: "hsl(210 40% 98% / <alpha-value>)",
        border: "hsl(217 19% 27% / <alpha-value>)",
        input: "hsl(217 19% 27% / <alpha-value>)",
        card: {
          DEFAULT: "hsl(222 47% 11% / <alpha-value>)",
          foreground: "hsl(210 40% 98% / <alpha-value>)",
          border: "hsl(217 19% 27% / <alpha-value>)",
        },
        popover: {
          DEFAULT: "hsl(222 47% 11% / <alpha-value>)",
          foreground: "hsl(210 40% 98% / <alpha-value>)",
          border: "hsl(217 19% 27% / <alpha-value>)",
        },
        primary: {
          DEFAULT: "hsl(142 71% 45% / <alpha-value>)",
          foreground: "hsl(144 100% 97% / <alpha-value>)",
          border: "hsl(142 71% 45% / <alpha-value>)",
        },
        secondary: {
          DEFAULT: "hsl(217 19% 27% / <alpha-value>)",
          foreground: "hsl(210 40% 98% / <alpha-value>)",
          border: "hsl(217 19% 27% / <alpha-value>)",
        },
        muted: {
          DEFAULT: "hsl(217 19% 27% / <alpha-value>)",
          foreground: "hsl(215 20% 65% / <alpha-value>)",
          border: "hsl(217 19% 27% / <alpha-value>)",
        },
        accent: {
          DEFAULT: "hsl(142 71% 45% / <alpha-value>)",
          foreground: "hsl(210 40% 98% / <alpha-value>)",
          border: "hsl(217 19% 27% / <alpha-value>)",
        },
        destructive: {
          DEFAULT: "hsl(0 84% 60% / <alpha-value>)",
          foreground: "hsl(210 40% 98% / <alpha-value>)",
          border: "hsl(217 19% 27% / <alpha-value>)",
        },
        ring: "hsl(142 71% 45% / <alpha-value>)",
        chart: {
          "1": "hsl(var(--chart-1) / <alpha-value>)",
          "2": "hsl(var(--chart-2) / <alpha-value>)",
          "3": "hsl(var(--chart-3) / <alpha-value>)",
          "4": "hsl(var(--chart-4) / <alpha-value>)",
          "5": "hsl(var(--chart-5) / <alpha-value>)",
        },
        sidebar: {
          ring: "hsl(var(--sidebar-ring) / <alpha-value>)",
          DEFAULT: "hsl(var(--sidebar) / <alpha-value>)",
          foreground: "hsl(var(--sidebar-foreground) / <alpha-value>)",
          border: "hsl(var(--sidebar-border) / <alpha-value>)",
        },
        "sidebar-primary": {
          DEFAULT: "hsl(var(--sidebar-primary) / <alpha-value>)",
          foreground: "hsl(var(--sidebar-primary-foreground) / <alpha-value>)",
          border: "hsl(var(--sidebar-primary-border) / <alpha-value>)",
        },
        "sidebar-accent": {
          DEFAULT: "hsl(var(--sidebar-accent) / <alpha-value>)",
          foreground: "hsl(var(--sidebar-accent-foreground) / <alpha-value>)",
          border: "hsl(var(--sidebar-accent-border) / <alpha-value>)",
        },
        status: {
          online: "rgb(34 197 94)",
          away: "rgb(245 158 11)",
          busy: "rgb(239 68 68)",
          offline: "rgb(156 163 175)",
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)"],
        serif: ["var(--font-serif)"],
        mono: ["var(--font-mono)"],
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
      },
    },
  },
  plugins: [require("tailwindcss-animate"), require("@tailwindcss/typography")],
} satisfies Config;
