import { useState } from "react";
import { Routes, Route, NavLink, useNavigate, Link } from "react-router-dom";
import {
  Shield,
  MessageSquare,
  BarChart3,
  GitBranch,
  Send,
  Users,
  Menu,
  X,
  ChevronLeft,
  Sun,
  Moon,
} from "lucide-react";
import { useTheme } from "../ThemeContext";

import SessionView from "./SessionView";
import IntelligenceView from "./IntelligenceView";
import PatternsView from "./PatternsView";
import CallbacksView from "./CallbacksView";
import AboutView from "./AboutView";
import TechDocsView from "./TechDocsView";

const NAV_ITEMS = [
  { to: "session", icon: MessageSquare, label: "Session" },
  { to: "intelligence", icon: BarChart3, label: "Intelligence" },
  { to: "patterns", icon: GitBranch, label: "Patterns" },
  { to: "callbacks", icon: Send, label: "Callbacks" },
  { to: "about", icon: Users, label: "About" },
];

export default function Dashboard() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const navigate = useNavigate();
  const year = new Date().getFullYear();
  const { theme, toggle } = useTheme();

  const navLinkClass = ({ isActive }) =>
    `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
      isActive ?
        "bg-blue-500/10 text-blue-400 glow-border"
      : "th-text-muted hover:th-text hover:bg-hover"
    }`;

  const SidebarContent = () => (
    <>
      {/* Logo */}
      <div
        className="flex items-center gap-2.5 px-4 pt-5 pb-6 cursor-pointer"
        onClick={() => {
          setSidebarOpen(false);
          navigate("/");
        }}>
        <img
          src="/logo.png"
          alt="TrustHoneypot Logo"
          className="w-8 h-8 rounded-lg object-contain"
        />
        <div className="flex flex-col">
          <span
            className="text-sm font-semibold tracking-tight leading-none"
            style={{ color: "var(--text-heading)" }}>
            Trust<span className="text-gradient">Honeypot</span>
          </span>
          <span
            className="text-[10px] font-mono mt-0.5"
            style={{ color: "var(--text-muted)" }}>
            COMMAND CENTER
          </span>
        </div>
      </div>

      {/* Nav items */}
      <nav className="flex-1 px-3 space-y-1">
        {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={navLinkClass}
            onClick={() => setSidebarOpen(false)}>
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Theme toggle + Back */}
      <div className="px-3 pb-4 space-y-1">
        <button
          onClick={toggle}
          className="flex items-center gap-2 w-full px-3 py-2 rounded-lg text-xs transition-all"
          style={{ color: "var(--text-muted)" }}>
          {theme === "dark" ?
            <Sun size={14} />
          : <Moon size={14} />}
          {theme === "dark" ? "Light Mode" : "Dark Mode"}
        </button>
        <button
          onClick={() => navigate("/")}
          className="flex items-center gap-2 w-full px-3 py-2 rounded-lg text-xs transition-all"
          style={{ color: "var(--text-muted)" }}>
          <ChevronLeft size={14} />
          Back to Home
        </button>
      </div>
    </>
  );

  return (
    <div
      className="flex h-screen overflow-hidden"
      style={{ background: "var(--bg-primary)" }}>
      {/* Desktop sidebar */}
      <aside
        className="hidden md:flex flex-col w-56 border-r flex-shrink-0"
        style={{
          background: "var(--sidebar-bg)",
          borderColor: "var(--border-primary)",
        }}>
        <SidebarContent />
      </aside>

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Mobile sidebar drawer */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-60 border-r flex flex-col transform transition-transform duration-300 ease-in-out md:hidden ${
          sidebarOpen ? "translate-x-0" : "-translate-x-full"
        }`}
        style={{
          background: "var(--sidebar-bg)",
          borderColor: "var(--border-primary)",
        }}>
        <div className="absolute top-3 right-3">
          <button
            onClick={() => setSidebarOpen(false)}
            className="p-1.5 rounded-lg transition-colors"
            style={{ color: "var(--text-tertiary)" }}>
            <X size={18} />
          </button>
        </div>
        <SidebarContent />
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top header */}
        <header
          className="flex items-center justify-between px-4 md:px-6 h-12 border-b backdrop-blur-sm flex-shrink-0"
          style={{
            background: "var(--bg-card)",
            borderColor: "var(--border-primary)",
          }}>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSidebarOpen(true)}
              className="p-1.5 rounded-lg md:hidden"
              style={{ color: "var(--text-tertiary)" }}>
              <Menu size={18} />
            </button>
            <span className="text-sm font-medium hidden sm:block">
              Trust<span className="text-gradient">Honeypot</span>
            </span>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
              </span>
              <span className="text-xs text-emerald-400 font-medium">LIVE</span>
            </div>
            <span
              className="text-[11px] font-mono"
              style={{ color: "var(--text-muted)" }}>
              Scam Intelligence Platform
            </span>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto bg-grid">
          <Routes>
            <Route index element={<SessionView />} />
            <Route path="session" element={<SessionView />} />
            <Route path="intelligence" element={<IntelligenceView />} />
            <Route path="patterns" element={<PatternsView />} />
            <Route path="callbacks" element={<CallbacksView />} />
            <Route path="docs" element={<TechDocsView />} />
            <Route path="about" element={<AboutView />} />
          </Routes>
        </main>

        {/* Footer */}
        <footer
          className="flex items-center justify-center h-9 border-t flex-shrink-0"
          style={{
            background: "var(--bg-card)",
            borderColor: "var(--border-primary)",
          }}>
          <p className="text-[11px]" style={{ color: "var(--text-muted)" }}>
            &copy; {year} Made by Bhupendra and Vikas — Trust
            <span className="text-gradient">Honeypot</span> v2.2 — Scam
            Intelligence Platform
          </p>
        </footer>
      </div>
    </div>
  );
}
