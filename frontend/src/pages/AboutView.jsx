import { useNavigate } from "react-router-dom";
import {
  Github,
  Shield,
  ExternalLink,
  Brain,
  Radio,
  Database,
  Zap,
  Target,
  FileText,
} from "lucide-react";

const GITHUB_URL = "https://github.com/sm-code-24/TrustHoneypot";

const SOLUTION_HIGHLIGHTS = [
  {
    icon: Brain,
    title: "Agentic AI Engagement",
    desc: "An adaptive bilingual (English + Hindi) agent that role-plays as a convincing victim, using 260+ category-specific response templates with Llama 3.3 70B LLM rephrasing via Groq and circuit breaker for production reliability.",
    color: "from-purple-500 to-pink-400",
  },
  {
    icon: Shield,
    title: "5-Layer Scam Detection",
    desc: "Pattern matching, behavioral scoring, India-specific taxonomy, context analysis, and intelligence correlation work together to classify 18+ scam categories with structured detection reasoning and fraud type badges.",
    color: "from-blue-500 to-cyan-400",
  },
  {
    icon: Radio,
    title: "Intelligence Registry",
    desc: "Automatically captures and tracks UPI IDs, bank accounts, phone numbers, Aadhaar, PAN, and phishing URLs. v2.2 adds a full registry with clickable identifiers, recurring threat detection, and Excel export.",
    color: "from-emerald-500 to-teal-400",
  },
  {
    icon: Database,
    title: "Pattern Correlation Engine",
    desc: "MongoDB-backed persistence with pattern fingerprinting, similarity scoring, and cross-session correlation. Identifies repeat offenders and linked scam operations with confidence scoring.",
    color: "from-amber-500 to-orange-400",
  },
];

export default function AboutView() {
  const navigate = useNavigate();
  return (
    <div className="p-4 md:p-8 space-y-10 animate-fade-in max-w-5xl mx-auto">
      {/* Project header */}
      <div className="glass rounded-2xl p-8 md:p-10 glow-border text-center">
        <div className="flex items-center justify-center gap-3 mb-5">
          <img
            src="/logo.png"
            alt="TrustHoneypot Logo"
            className="w-14 h-14 rounded-xl object-contain"
          />
          <div className="text-left">
            <h2 className="text-2xl md:text-3xl font-bold text-gradient">
              TrustHoneypot
            </h2>
            <p
              className="text-xs mt-0.5"
              style={{ color: "var(--text-tertiary)" }}>
              Scam Intelligence Platform
            </p>
          </div>
        </div>
        <p
          className="text-sm md:text-base max-w-2xl mx-auto leading-relaxed mt-2"
          style={{ color: "var(--text-tertiary)" }}>
          <span className="font-semibold">
            Trust<span className="text-gradient">Honeypot</span>
          </span>{" "}
          is an agentic scam intelligence platform that engages fraudsters with
          believable AI conversations, extracts critical financial data like UPI
          IDs and bank accounts, and classifies 18+ scam categories — protecting
          Indian citizens from digital fraud in real-time.
        </p>
        <div className="flex items-center justify-center gap-3 mt-6">
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl border text-xs font-medium transition-all"
            style={{
              background: "var(--bg-tertiary)",
              borderColor: "var(--border-primary)",
              color: "var(--text-secondary)",
            }}>
            <Github size={14} />
            View on GitHub
            <ExternalLink size={10} className="opacity-50" />
          </a>
        </div>
      </div>

      {/* Solution Details */}
      <div>
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 mb-3 px-4 py-1.5 rounded-full bg-purple-500/[0.08] border border-purple-500/20">
            <Target size={13} className="text-purple-400" />
            <span className="text-xs font-medium text-purple-300">
              Our Solution
            </span>
          </div>
          <h3
            className="text-xl md:text-2xl font-bold"
            style={{ color: "var(--text-heading)" }}>
            How{" "}
            <span>
              Trust<span className="text-gradient">Honeypot</span>
            </span>{" "}
            Works
          </h3>
          <p
            className="mt-2 text-sm max-w-xl mx-auto"
            style={{ color: "var(--text-tertiary)" }}>
            A multi-layered approach that turns every scam interaction into
            actionable intelligence for protecting Indian citizens.
          </p>
        </div>
        <div className="grid sm:grid-cols-2 gap-5">
          {SOLUTION_HIGHLIGHTS.map((item, i) => (
            <div
              key={item.title}
              className="glass rounded-2xl p-6 card-hover animate-fade-in"
              style={{
                animationDelay: `${i * 100}ms`,
                animationFillMode: "both",
              }}>
              <div
                className={`inline-flex items-center justify-center w-11 h-11 rounded-xl bg-gradient-to-br ${item.color} mb-4 shadow-lg`}>
                <item.icon size={20} className="text-white" />
              </div>
              <h4
                className="text-sm font-semibold mb-2"
                style={{ color: "var(--text-heading)" }}>
                {item.title}
              </h4>
              <p
                className="text-xs leading-relaxed"
                style={{ color: "var(--text-tertiary)" }}>
                {item.desc}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Key numbers */}
      <div className="glass rounded-2xl p-6 md:p-8">
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-4 text-center">
          {[
            { value: "18+", label: "Scam Categories" },
            { value: "5", label: "Detection Layers" },
            { value: "8", label: "Intel Extractors" },
            { value: "260+", label: "Response Templates" },
            { value: "v2.2", label: "Current Version" },
            { value: "4", label: "DB Collections" },
          ].map((stat) => (
            <div key={stat.label}>
              <div className="text-2xl md:text-3xl font-extrabold text-gradient">
                {stat.value}
              </div>
              <div
                className="mt-1 text-xs font-medium"
                style={{ color: "var(--text-tertiary)" }}>
                {stat.label}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Problem Statement */}
      <div className="glass rounded-2xl p-6 md:p-8 text-center">
        <Zap size={20} className="mx-auto text-amber-400 mb-3" />
        <h3
          className="text-base font-semibold mb-2"
          style={{ color: "var(--text-heading)" }}>
          Project Brief
        </h3>
        <p
          className="text-sm max-w-xl mx-auto leading-relaxed"
          style={{ color: "var(--text-tertiary)" }}>
          Build an Agentic Honey-Pot for Scam Detection — create an AI agent
          that acts as a realistic target for scammers, intelligently engages
          with them to gather evidence, extracts key intelligence, and helps
          protect citizens from evolving digital fraud in India.
        </p>
      </div>

      {/* Technical Documentation Bar */}
      <div className="glass rounded-2xl p-5 md:p-6 glow-border">
        <button
          onClick={() => navigate("/dashboard/docs")}
          className="flex items-center justify-between w-full group">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-blue-500/20">
              <FileText size={18} className="text-white" />
            </div>
            <div className="text-left">
              <h4
                className="text-sm font-semibold"
                style={{ color: "var(--text-heading)" }}>
                Technical Documentation
              </h4>
              <p
                className="text-xs mt-0.5"
                style={{ color: "var(--text-tertiary)" }}>
                Architecture, API reference, detection engine, deployment &amp;
                more
              </p>
            </div>
          </div>
          <ExternalLink
            size={16}
            className="text-slate-500 group-hover:text-blue-400 transition-colors"
          />
        </button>
      </div>
    </div>
  );
}
