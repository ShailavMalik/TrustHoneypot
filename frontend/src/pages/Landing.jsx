import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import {
  Shield,
  Brain,
  Radio,
  ChevronRight,
  Lock,
  Github,
  Sparkles,
  Fingerprint,
  Database,
} from "lucide-react";
import { useTheme } from "../ThemeContext";

const CYCLE_WORDS = [
  {
    text: "Engage",
    dark: "linear-gradient(to right, #60a5fa, #67e8f9)",
    light: "linear-gradient(to right, #1d4ed8, #0891b2)",
  },
  {
    text: "Extract",
    dark: "linear-gradient(to right, #c084fc, #f9a8d4)",
    light: "linear-gradient(to right, #7e22ce, #db2777)",
  },
  {
    text: "Detect",
    dark: "linear-gradient(to right, #34d399, #5eead4)",
    light: "linear-gradient(to right, #047857, #0f766e)",
  },
  {
    text: "Protect",
    dark: "linear-gradient(to right, #fbbf24, #fb923c)",
    light: "linear-gradient(to right, #d97706, #ea580c)",
  },
];

const FEATURES = [
  {
    icon: Shield,
    title: "Multi-Layer Detection",
    desc: "Pattern analysis, behavioral scoring & India-specific scam taxonomy identify threats in real-time.",
    color: "from-blue-500 to-cyan-400",
  },
  {
    icon: Brain,
    title: "Adaptive AI Agent",
    desc: "Rule-based core with Groq-powered LLM rephrasing — keeps scammers engaged while extracting intel.",
    color: "from-purple-500 to-pink-400",
  },
  {
    icon: Radio,
    title: "Intelligence Extraction",
    desc: "Automatically captures UPI IDs, bank accounts, phone numbers, Aadhaar, PAN & phishing links.",
    color: "from-emerald-500 to-teal-400",
  },
  {
    icon: Database,
    title: "Threat Intelligence DB",
    desc: "MongoDB-backed pattern storage enables continuous learning from every scam interaction.",
    color: "from-amber-500 to-orange-400",
  },
];

const STATS = [
  { label: "Scam Categories", value: "18+" },
  { label: "Detection Layers", value: "5" },
  { label: "Intel Extractors", value: "8" },
  { label: "Response Pools", value: "290+" },
];

export default function Landing() {
  const navigate = useNavigate();
  const year = new Date().getFullYear();
  const [wordIdx, setWordIdx] = useState(0);
  const [visible, setVisible] = useState(true);
  const { theme, toggle } = useTheme();

  useEffect(() => {
    const interval = setInterval(() => {
      setVisible(false);
      setTimeout(() => {
        setWordIdx((i) => (i + 1) % CYCLE_WORDS.length);
        setVisible(true);
      }, 400);
    }, 2800);
    return () => clearInterval(interval);
  }, []);

  const word = CYCLE_WORDS[wordIdx];
  const gradient = theme === "light" ? word.light : word.dark;

  return (
    <div
      className="relative min-h-screen overflow-hidden"
      style={{ background: "var(--bg-primary)" }}>
      {/* Gradient mesh background */}
      <div className="absolute inset-0">
        <div
          className="absolute inset-0"
          style={{ background: "var(--page-gradient)" }}
        />
        <div
          className="absolute top-[-25%] left-[-10%] w-[700px] h-[700px] rounded-full blur-[120px] animate-float"
          style={{ background: "var(--landing-orb1)" }}
        />
        <div
          className="absolute bottom-[-15%] right-[-5%] w-[600px] h-[600px] rounded-full blur-[100px]"
          style={{ background: "var(--landing-orb2)" }}
        />
        <div
          className="absolute top-[50%] right-[15%] w-[350px] h-[350px] rounded-full blur-[80px] animate-float"
          style={{ animationDelay: "1.5s", background: "var(--landing-orb3)" }}
        />
        <div className="absolute inset-0 bg-grid opacity-30" />
      </div>

      {/* Top bar */}
      <header className="relative z-10 flex items-center justify-between px-6 py-5 md:px-12">
        <div className="flex items-center gap-2.5">
          <img
            src="/logo.png"
            alt="TrustHoneypot Logo"
            className="w-9 h-9 rounded-xl object-contain"
          />
          <span
            className="text-lg font-bold tracking-tight"
            style={{ color: "var(--text-heading)" }}>
            Trust<span className="text-gradient">Honeypot</span>
          </span>
        </div>
        <div className="flex items-center gap-4">
          <span
            className="hidden sm:block text-xs font-mono tracking-wider"
            style={{ color: "var(--text-muted)" }}>
            SCAM INTELLIGENCE PLATFORM
          </span>
          <button
            onClick={toggle}
            className="p-2 rounded-lg transition-all hover:scale-105"
            style={{ color: "var(--text-muted)", background: "var(--bg-card)" }}
            title={
              theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
            }>
            {theme === "dark" ?
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round">
                <circle cx="12" cy="12" r="5" />
                <line x1="12" y1="1" x2="12" y2="3" />
                <line x1="12" y1="21" x2="12" y2="23" />
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                <line x1="1" y1="12" x2="3" y2="12" />
                <line x1="21" y1="12" x2="23" y2="12" />
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
              </svg>
            : <svg
                xmlns="http://www.w3.org/2000/svg"
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
              </svg>
            }
          </button>
        </div>
      </header>

      {/* Hero */}
      <main className="relative z-10 flex flex-col items-center justify-center px-6 pt-12 pb-8 md:pt-20 md:pb-12 text-center">
        {/* Badge */}
        <div
          className="mb-8 inline-flex items-center gap-2 rounded-full px-5 py-2 text-xs font-medium shadow-lg backdrop-blur-sm"
          style={{
            background: "var(--badge-bg)",
            borderColor: "var(--badge-border)",
            border: "1px solid var(--badge-border)",
            color: "var(--gradient-text-1)",
          }}>
          <Sparkles size={12} className="animate-pulse" />
          Scam Intelligence Platform — India
        </div>

        {/* Animated cycling word */}
        <div className="mb-4 h-16 md:h-[5.5rem] flex items-center justify-center overflow-hidden">
          <span
            className={`text-5xl md:text-7xl font-extrabold transition-all duration-[400ms] ease-out ${
              visible ?
                "opacity-100 translate-y-0 scale-100"
              : "opacity-0 translate-y-3 scale-95"
            }`}
            style={{
              backgroundImage: gradient,
              WebkitBackgroundClip: "text",
              backgroundClip: "text",
              WebkitTextFillColor: "transparent",
              color: "transparent",
            }}>
            {word.text}
          </span>
        </div>

        <h1
          className="max-w-3xl text-3xl md:text-5xl font-bold tracking-tight leading-tight"
          style={{ color: "var(--text-heading)" }}>
          Scam Intelligence{" "}
          <span className="text-gradient">Command Center</span>
        </h1>

        <p
          className="mt-6 max-w-2xl text-base md:text-lg leading-relaxed"
          style={{ color: "var(--text-tertiary)" }}>
          An agentic honeypot that fools scammers with believable AI
          conversations, extracts critical financial intelligence, and shields
          Indian citizens — all in real-time.
        </p>

        {/* CTA */}
        <div className="mt-10 flex flex-col sm:flex-row items-center gap-4">
          <button
            onClick={() => navigate("/dashboard/session")}
            className="group flex items-center gap-2 rounded-xl bg-gradient-to-r from-blue-600 to-purple-600 px-8 py-3.5 text-sm font-semibold text-white shadow-xl shadow-blue-600/25 transition-all hover:shadow-blue-500/40 hover:scale-[1.03] active:scale-[0.98]">
            Launch Dashboard
            <ChevronRight
              size={16}
              className="transition-transform group-hover:translate-x-0.5"
            />
          </button>
          <a
            href="https://github.com/undersolved?tab=repositories"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 rounded-xl backdrop-blur-sm px-6 py-3.5 text-sm font-medium transition-all"
            style={{
              border: "1px solid var(--border-primary)",
              background: "var(--bg-card)",
              color: "var(--text-secondary)",
            }}>
            <Github size={15} />
            View on GitHub
          </a>
        </div>
      </main>

      {/* Punchline */}
      <section className="relative z-10 py-16 md:py-24 text-center">
        <div className="max-w-3xl mx-auto px-6">
          <p
            className="text-2xl md:text-4xl font-bold leading-snug"
            style={{ color: "var(--text-secondary)" }}>
            Don't just detect scams.
          </p>
          <p className="mt-2 text-3xl md:text-5xl font-extrabold text-gradient leading-snug">
            Outsmart them.
          </p>
          <div
            className="mt-8 flex items-center justify-center gap-2 text-sm"
            style={{ color: "var(--text-muted)" }}>
            <Fingerprint size={14} className="text-blue-400/60" />
            <span>Rule-based authority · Groq LLM · zero false positives</span>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section className="relative z-10 px-6 pb-20 max-w-3xl mx-auto">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {STATS.map((s, i) => (
            <div
              key={s.label}
              className="glass rounded-2xl px-4 py-5 text-center card-hover animate-fade-in"
              style={{
                animationDelay: `${i * 100}ms`,
                animationFillMode: "both",
              }}>
              <div className="text-3xl md:text-4xl font-extrabold text-gradient">
                {s.value}
              </div>
              <div
                className="mt-1.5 text-xs font-medium"
                style={{ color: "var(--text-tertiary)" }}>
                {s.label}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section className="relative z-10 px-6 md:px-12 pb-20 max-w-5xl mx-auto">
        <h2
          className="text-center text-sm font-semibold uppercase tracking-wider mb-8"
          style={{ color: "var(--text-tertiary)" }}>
          How It Works
        </h2>
        <div className="grid sm:grid-cols-2 gap-5">
          {FEATURES.map((f, i) => (
            <div
              key={f.title}
              className="glass rounded-2xl p-6 card-hover animate-fade-in"
              style={{
                animationDelay: `${i * 120}ms`,
                animationFillMode: "both",
              }}>
              <div
                className={`inline-flex items-center justify-center w-11 h-11 rounded-xl bg-gradient-to-br ${f.color} mb-4 shadow-lg`}>
                <f.icon size={20} className="text-white" />
              </div>
              <h3
                className="text-base font-semibold mb-2"
                style={{ color: "var(--text-heading)" }}>
                {f.title}
              </h3>
              <p
                className="text-sm leading-relaxed"
                style={{ color: "var(--text-tertiary)" }}>
                {f.desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Architecture */}
      <section className="relative z-10 px-6 md:px-12 pb-20 max-w-4xl mx-auto">
        <div className="glass rounded-2xl p-8 glow-border text-center">
          <Lock size={24} className="mx-auto text-blue-400 mb-4" />
          <h3
            className="text-lg font-semibold mb-3"
            style={{ color: "var(--text-heading)" }}>
            Architecture Invariant
          </h3>
          <p
            className="text-sm max-w-lg mx-auto leading-relaxed"
            style={{ color: "var(--text-tertiary)" }}>
            The rule-based engine is the{" "}
            <span
              style={{ color: "var(--gradient-text-1)" }}
              className="font-medium">
              single authority
            </span>{" "}
            for detection and responses. LLM enhances phrasing realism only —
            never overrides detection or generates scam content. MongoDB stores
            session summaries for continuous learning.
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer
        className="relative z-10 py-6 text-center"
        style={{ borderTop: "1px solid var(--border-primary)" }}>
        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
          &copy; {year} Made by Bhupendra and Vikas — Trust
          <span className="text-gradient">Honeypot</span> v2.2 — Scam
          Intelligence Platform
        </p>
      </footer>
    </div>
  );
}
