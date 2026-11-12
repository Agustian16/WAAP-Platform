import type { Config } from "tailwindcss";

const ch = (v: string) => `rgb(var(--${v}) / <alpha-value>)`;

const config: Config = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: ch("bg"),
        chrome: ch("chrome"),
        input: ch("input"),
        surface: { DEFAULT: ch("surface"), 2: ch("surface-2"), 3: ch("surface-3") },
        border: { DEFAULT: ch("border"), strong: ch("border-strong") },
        fg: { DEFAULT: ch("fg"), 2: ch("fg-2") },
        muted: ch("muted"),
        accent: { DEFAULT: ch("accent"), fg: ch("accent-fg") },
        good: ch("good"),
        warn: ch("warn"),
        serious: ch("serious"),
        crit: ch("crit"),
      },
      fontFamily: {
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
        brand: ["var(--font-brand)", "var(--font-sans)", "sans-serif"],
      },
      borderRadius: { sm: "3px", DEFAULT: "4px", md: "6px", lg: "8px" },
      boxShadow: { pop: "var(--pop-shadow)" },
    },
  },
  plugins: [require("tailwindcss-animate")],
};
export default config;
