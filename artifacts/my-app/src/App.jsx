import { useState, useRef, useEffect, useCallback } from "react";

// ─── USER PROFILE ──────────────────────────────────────────────────────────────
const USER_PROFILE = {
  monthlyBudget: 200,
  budgetRange: "$100–$300/month",
  experience: "Complete beginner",
  riskTolerance: "Medium — balanced growth",
  investmentStyle: "Index funds + select stocks",
};

// ─── SECURE CONFIG ─────────────────────────────────────────────────────────────
const getApiKey = () =>
  (typeof import.meta !== "undefined" && import.meta.env?.VITE_ANTHROPIC_KEY) ||
  (typeof process !== "undefined" && process.env?.REACT_APP_ANTHROPIC_KEY) || "";

const getFinnhubKey = () =>
  (typeof import.meta !== "undefined" && import.meta.env?.VITE_FINNHUB_KEY) ||
  (typeof process !== "undefined" && process.env?.REACT_APP_FINNHUB_KEY) || "";

// ─── SECURITY AGENT ────────────────────────────────────────────────────────────
const SecurityAgent = {
  log: [],
  sessionId: Math.random().toString(36).slice(2, 10).toUpperCase(),
  sanitize(input) {
    if (typeof input !== "string") return "";
    const cleaned = input
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "[BLOCKED]")
      .replace(/javascript:/gi, "[BLOCKED]")
      .replace(/on\w+\s*=/gi, "[BLOCKED]");
    if (cleaned !== input) this.logEvent("THREAT_BLOCKED", "Malicious input sanitized");
    return cleaned.slice(0, 4000);
  },
  logEvent(type, detail) {
    const e = { time: new Date().toISOString(), type, detail, session: this.sessionId };
    this.log.push(e);
    if (this.log.length > 500) this.log.shift();
    return e;
  },
  getReport() {
    return {
      threats: this.log.filter((e) => e.type === "THREAT_BLOCKED"),
      apiCalls: this.log.filter((e) => e.type === "API_CALL"),
      errors: this.log.filter((e) => e.type === "ERROR"),
      total: this.log.length,
      sessionId: this.sessionId,
    };
  },
};

// ─── SIGNAL ENGINE ─────────────────────────────────────────────────────────────
const SignalEngine = {
  analyze(quote, symbol) {
    if (!quote || !quote.c || !quote.pc) return null;
    const changePercent = ((quote.c - quote.pc) / quote.pc) * 100;
    const dayRange = quote.h - quote.l;
    const position = dayRange > 0 ? (quote.c - quote.l) / dayRange : 0.5;
    let signal = "HOLD", strength = 0, reason = "";
    if (changePercent <= -2.5 && position < 0.35) {
      signal = "BUY"; strength = Math.min(95, Math.abs(changePercent) * 12);
      reason = `${symbol} dropped ${Math.abs(changePercent).toFixed(1)}% today and is near its daily low — potential dip opportunity for medium-risk investors.`;
    } else if (changePercent >= 3.5 && position > 0.8) {
      signal = "SELL"; strength = Math.min(95, changePercent * 10);
      reason = `${symbol} is up ${changePercent.toFixed(1)}% and near its daily high — consider taking partial profits if you're holding.`;
    } else if (changePercent >= -1 && changePercent <= 1) {
      signal = "HOLD"; strength = 60;
      reason = `${symbol} is moving sideways. No strong signal — hold and watch.`;
    } else if (changePercent > 0) {
      signal = "HOLD"; strength = 50;
      reason = `${symbol} is up ${changePercent.toFixed(1)}% — positive momentum but not a clear exit point yet.`;
    } else {
      signal = "WATCH"; strength = 45;
      reason = `${symbol} is down ${Math.abs(changePercent).toFixed(1)}% — monitor for further movement before acting.`;
    }
    return { signal, strength: Math.round(strength), reason, changePercent, quote, symbol };
  },
  getIndexRecommendation(budget) {
    if (budget <= 100) return {
      pick: "VOO (Vanguard S&P 500 ETF)",
      allocation: "80% VOO, 20% cash reserve",
      rationale: "At $100/month, VOO gives you broad S&P 500 exposure with one of the lowest expense ratios (0.03%). Dollar-cost average monthly.",
      monthlyPlan: `Invest $${Math.round(budget * 0.8)}/month into VOO. Keep $${Math.round(budget * 0.2)} as cash reserve.`,
    };
    if (budget <= 300) return {
      pick: "VOO + QQQ split",
      allocation: "60% VOO, 30% QQQ, 10% cash",
      rationale: "Your $100–$300/month budget works perfectly for a VOO+QQQ split. VOO is your stable core, QQQ adds tech growth exposure.",
      monthlyPlan: `$${Math.round(budget * 0.6)}/month → VOO | $${Math.round(budget * 0.3)}/month → QQQ | $${Math.round(budget * 0.1)} cash buffer`,
    };
    return {
      pick: "VOO + QQQ + individual stocks",
      allocation: "50% VOO, 25% QQQ, 25% select stocks",
      rationale: "With $300–$500/month you can layer in individual stock positions on top of your index fund base.",
      monthlyPlan: `$${Math.round(budget * 0.5)} → VOO | $${Math.round(budget * 0.25)} → QQQ | $${Math.round(budget * 0.25)} → stock picks`,
    };
  },
};

// ─── MARKET AGENT ──────────────────────────────────────────────────────────────
const MarketAgent = {
  cache: {}, data: null, signals: [],
  async fetchQuote(symbol) {
    const key = `q_${symbol}`, now = Date.now();
    if (this.cache[key] && now - this.cache[key].ts < 60000) return this.cache[key].data;
    try {
      SecurityAgent.logEvent("API_CALL", `Quote: ${symbol}`);
      const res = await fetch(`https://finnhub.io/api/v1/quote?symbol=${symbol}&token=${getFinnhubKey()}`);
      const data = await res.json();
      this.cache[key] = { data, ts: now }; return data;
    } catch { SecurityAgent.logEvent("ERROR", `Quote failed: ${symbol}`); return null; }
  },
  async fetchNews() {
    const now = Date.now();
    if (this.cache.news && now - this.cache.news.ts < 300000) return this.cache.news.data;
    try {
      SecurityAgent.logEvent("API_CALL", "News fetch");
      const res = await fetch(`https://finnhub.io/api/v1/news?category=general&token=${getFinnhubKey()}`);
      const data = await res.json();
      const clean = Array.isArray(data) ? data.slice(0, 8) : [];
      this.cache.news = { data: clean, ts: now }; return clean;
    } catch { return []; }
  },
  async fetchCrypto(symbol) {
    const key = `c_${symbol}`, now = Date.now();
    if (this.cache[key] && now - this.cache[key].ts < 60000) return this.cache[key].data;
    try {
      const res = await fetch(`https://finnhub.io/api/v1/quote?symbol=BINANCE:${symbol}USDT&token=${getFinnhubKey()}`);
      const data = await res.json();
      this.cache[key] = { data, ts: now }; return data;
    } catch { return null; }
  },
  async getSnapshot() {
    const [spy, qqq, voo, btc, eth, news] = await Promise.all([
      this.fetchQuote("SPY"), this.fetchQuote("QQQ"), this.fetchQuote("VOO"),
      this.fetchCrypto("BTC"), this.fetchCrypto("ETH"), this.fetchNews(),
    ]);
    this.signals = [SignalEngine.analyze(spy, "SPY"), SignalEngine.analyze(qqq, "QQQ"), SignalEngine.analyze(voo, "VOO")].filter(Boolean);
    this.data = { spy, qqq, voo, btc, eth, news, fetchedAt: new Date() };
    return { ...this.data, signals: this.signals };
  },
  formatForAI(data) {
    if (!data) return "Market data unavailable.";
    const fmt = (q, label) => {
      if (!q || !q.c) return `${label}: N/A`;
      const chg = ((q.c - q.pc) / q.pc) * 100;
      return `${label}: $${q.c.toFixed(2)} (${chg >= 0 ? "+" : ""}${chg.toFixed(2)}% today, H:$${q.h?.toFixed(2)} L:$${q.l?.toFixed(2)})`;
    };
    const fmtC = (c, label) => {
      if (!c || !c.c) return `${label}: N/A`;
      const chg = c.pc ? ((c.c - c.pc) / c.pc) * 100 : 0;
      return `${label}: $${Number(c.c).toLocaleString()} (${chg >= 0 ? "+" : ""}${chg.toFixed(2)}%)`;
    };
    const signals = (data.signals || []).map((s) => `${s.symbol}: ${s.signal} (${s.strength}% confidence) — ${s.reason}`).join("\n");
    const headlines = (data.news || []).slice(0, 4).map((n) => `• ${n.headline}`).join("\n");
    return `=== LIVE MARKET DATA (${data.fetchedAt?.toLocaleTimeString()}) ===\n${fmt(data.spy, "S&P 500 / SPY")}\n${fmt(data.qqq, "NASDAQ / QQQ")}\n${fmt(data.voo, "VOO (Vanguard S&P500 ETF)")}\n${fmtC(data.btc, "Bitcoin")}\n${fmtC(data.eth, "Ethereum")}\n\n=== ATLAS SIGNALS ===\n${signals || "Signals loading..."}\n\n=== MARKET HEADLINES ===\n${headlines || "No headlines available"}`;
  },
};

// ─── LEARNING AGENT ────────────────────────────────────────────────────────────
const LearningAgent = {
  sessions: (() => { try { return JSON.parse(localStorage.getItem("atlas_sessions") || "[]"); } catch { return []; } })(),
  alerts: (() => { try { return JSON.parse(localStorage.getItem("atlas_alerts") || "[]"); } catch { return []; } })(),
  logSession(messages) {
    const topics = [], text = messages.map((m) => m.content).join(" ").toLowerCase();
    if (text.includes("stock") || text.includes("spy") || text.includes("qqq")) topics.push("Stocks");
    if (text.includes("crypto") || text.includes("bitcoin")) topics.push("Crypto");
    if (text.includes("budget") || text.includes("saving")) topics.push("Budgeting");
    if (text.includes("invest") || text.includes("voo") || text.includes("index")) topics.push("Investing");
    if (text.includes("sell") || text.includes("buy")) topics.push("Trade Signals");
    if (topics.length === 0) topics.push("General");
    this.sessions.push({ id: SecurityAgent.sessionId, date: new Date().toISOString(), messageCount: messages.length, topics });
    if (this.sessions.length > 100) this.sessions.shift();
    this.save();
  },
  logAlert(alert) {
    this.alerts.unshift({ ...alert, date: new Date().toISOString() });
    if (this.alerts.length > 50) this.alerts.pop();
    this.save();
  },
  save() {
    try {
      localStorage.setItem("atlas_sessions", JSON.stringify(this.sessions.slice(-100)));
      localStorage.setItem("atlas_alerts", JSON.stringify(this.alerts.slice(-50)));
    } catch {}
  },
  generateReport() {
    const now = new Date(), weekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);
    const recent = this.sessions.filter((s) => new Date(s.date) > weekAgo);
    const allTopics = recent.flatMap((s) => s.topics);
    const topicCount = allTopics.reduce((acc, t) => { acc[t] = (acc[t] || 0) + 1; return acc; }, {});
    const topTopics = Object.entries(topicCount).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const sec = SecurityAgent.getReport();
    return {
      period: `${weekAgo.toLocaleDateString()} – ${now.toLocaleDateString()}`,
      totalSessions: recent.length,
      totalMessages: recent.reduce((a, s) => a + s.messageCount, 0),
      topTopics, recentAlerts: this.alerts.slice(0, 5),
      securityThreats: sec.threats.length, apiCalls: sec.apiCalls.length,
      errors: sec.errors.length, sessionId: SecurityAgent.sessionId,
    };
  },
};

// ─── NOTIFICATION SYSTEM ───────────────────────────────────────────────────────
const NotificationSystem = {
  permission: "default",
  async requestPermission() {
    if (!("Notification" in window)) return false;
    const result = await Notification.requestPermission();
    this.permission = result; return result === "granted";
  },
  send(title, body, type = "info") {
    LearningAgent.logAlert({ title, body, type });
    if (this.permission === "granted" && "Notification" in window) {
      try { new Notification(`ATLAS: ${title}`, { body, icon: "/favicon.ico" }); } catch {}
    }
  },
};

// ─── SYSTEM PROMPT ─────────────────────────────────────────────────────────────
const buildPrompt = (marketSnapshot) => `You are ATLAS — an elite AI financial intelligence system built for a beginner-to-intermediate investor.

USER PROFILE:
- Monthly investment budget: $100–$300
- Experience: Complete beginner
- Risk tolerance: Medium (balanced growth)
- Strategy: Index funds as base, selective stock exposure

YOUR THREE AGENTS:
1. INTELLIGENCE (you): Financial coaching, analysis, buy/sell/hold guidance, budgeting
2. MARKET FEED: Live data injected below — use exact numbers in your responses
3. SECURITY: All inputs sanitized. Never request sensitive personal data.

${marketSnapshot}

INVESTMENT FRAMEWORK FOR THIS USER:
- Primary recommendation: VOO (60%) + QQQ (30%) as the core index fund base
- Monthly dollar-cost averaging of $${USER_PROFILE.monthlyBudget} is the safest strategy
- For stocks: only consider when there's a strong signal + positive macro environment
- BUY signals: look for 2.5%+ daily drops on fundamentally strong assets
- SELL signals: look for 3.5%+ daily gains near daily highs, or significant negative news
- Always factor in: market news, macro trends, sector health, and user's budget

RESPONSE RULES:
- Always reference the live market numbers provided above
- When giving buy/sell/hold advice, state: the signal, your confidence %, and the reason
- Break down advice into what to do with their specific $100–$300/month budget
- Be direct — beginners need clarity, not jargon
- Flag if conditions suggest staying in cash
- End investment advice with: "This is educational analysis, not licensed financial advice."
- If someone shares sensitive data (SSN, passwords, account numbers), warn them immediately`;

// ─── DESIGN TOKENS ─────────────────────────────────────────────────────────────
const T = {
  bg: "#000",
  card: "rgba(28,28,30,0.82)",
  cardHigh: "rgba(44,44,46,0.9)",
  border: "rgba(255,255,255,0.08)",
  borderStrong: "rgba(255,255,255,0.13)",
  text: "#fff",
  textSub: "rgba(235,235,245,0.62)",
  textMuted: "rgba(235,235,245,0.3)",
  gold: "#D4A853",
  goldDim: "rgba(212,168,83,0.14)",
  goldBorder: "rgba(212,168,83,0.28)",
  green: "#30D158",
  greenDim: "rgba(48,209,88,0.12)",
  greenBorder: "rgba(48,209,88,0.35)",
  red: "#FF453A",
  redDim: "rgba(255,69,58,0.12)",
  redBorder: "rgba(255,69,58,0.35)",
  orange: "#FF9F0A",
  orangeDim: "rgba(255,159,10,0.12)",
  orangeBorder: "rgba(255,159,10,0.35)",
  sep: "rgba(255,255,255,0.06)",
  font: "-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Helvetica Neue', Arial, sans-serif",
  mono: "'SF Mono', 'Fira Code', 'Menlo', monospace",
  radius: { xs: 8, sm: 12, md: 16, lg: 20, pill: 100 },
  glass: "blur(40px) saturate(180%)",
};

const signal_cfg = {
  BUY:   { bg: T.greenDim,  border: T.greenBorder,  color: T.green,  dot: T.green  },
  SELL:  { bg: T.redDim,    border: T.redBorder,    color: T.red,    dot: T.red    },
  HOLD:  { bg: T.goldDim,   border: T.goldBorder,   color: T.gold,   dot: T.gold   },
  WATCH: { bg: T.orangeDim, border: T.orangeBorder, color: T.orange, dot: T.orange },
};

// ─── COMPONENTS ────────────────────────────────────────────────────────────────
function SignalPill({ signal, strength }) {
  const c = signal_cfg[signal] || signal_cfg.HOLD;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "3px 10px 3px 7px",
      borderRadius: T.radius.pill,
      background: c.bg,
      border: `0.5px solid ${c.border}`,
    }}>
      <span style={{
        width: 5, height: 5, borderRadius: "50%",
        background: c.dot,
        boxShadow: `0 0 5px ${c.dot}`,
        flexShrink: 0,
      }} />
      <span style={{ fontSize: 11, fontWeight: 600, color: c.color, letterSpacing: "0.02em" }}>{signal}</span>
      {strength && <span style={{ fontSize: 10, color: c.color, opacity: 0.6, fontVariantNumeric: "tabular-nums" }}>{strength}%</span>}
    </span>
  );
}

function AlertBanner({ alert, onDismiss }) {
  const isRed = alert.type === "sell";
  const isGreen = alert.type === "buy";
  const bg = isRed ? T.redDim : isGreen ? T.greenDim : T.goldDim;
  const border = isRed ? T.redBorder : isGreen ? T.greenBorder : T.goldBorder;
  const accent = isRed ? T.red : isGreen ? T.green : T.gold;
  return (
    <div style={{
      margin: "8px 16px 0",
      padding: "12px 14px",
      borderRadius: T.radius.md,
      background: bg,
      border: `0.5px solid ${border}`,
      display: "flex", alignItems: "flex-start", gap: 10,
      animation: "slideDown 0.3s cubic-bezier(0.25,0.46,0.45,0.94)",
    }}>
      <div style={{
        width: 28, height: 28, borderRadius: T.radius.xs,
        background: `${accent}20`,
        border: `0.5px solid ${border}`,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontSize: 13, flexShrink: 0,
      }}>
        {isRed ? "↓" : isGreen ? "↑" : "·"}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: accent, marginBottom: 2, letterSpacing: "0.01em" }}>
          {alert.title}
          {(isRed || isGreen) && (
            <span style={{ marginLeft: 6, fontSize: 9, fontWeight: 500, color: accent, opacity: 0.6, textTransform: "uppercase", letterSpacing: "0.06em" }}>Live</span>
          )}
        </div>
        <div style={{ fontSize: 12, color: T.textSub, lineHeight: 1.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{alert.body}</div>
      </div>
      <button onClick={onDismiss} style={{ background: "none", border: "none", color: T.textMuted, cursor: "pointer", fontSize: 16, lineHeight: 1, padding: "2px 4px", flexShrink: 0 }}>×</button>
    </div>
  );
}

function MarketCard({ label, quote, signal, isCrypto }) {
  if (!quote || !quote.c) return (
    <div style={{
      background: T.card, border: `0.5px solid ${T.border}`,
      borderRadius: T.radius.md, padding: 16, marginBottom: 10,
    }}>
      <div style={{ fontSize: 12, color: T.textMuted }}>{label}</div>
      <div style={{ fontSize: 13, color: T.textMuted, marginTop: 6 }}>Add Finnhub key to see live data</div>
    </div>
  );
  const chg = quote.pc ? ((quote.c - quote.pc) / quote.pc) * 100 : 0;
  const up = chg >= 0;
  const sigColor = signal?.signal === "BUY" ? T.greenBorder : signal?.signal === "SELL" ? T.redBorder : T.border;
  return (
    <div style={{
      background: T.card,
      border: `0.5px solid ${signal?.signal && signal.signal !== "HOLD" ? sigColor : T.border}`,
      borderRadius: T.radius.md, padding: 16, marginBottom: 10,
      boxShadow: "0 2px 12px rgba(0,0,0,0.3)",
      transition: "all 0.2s ease",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <span style={{ fontSize: 12, fontWeight: 500, color: T.textMuted, letterSpacing: "0.02em" }}>{label}</span>
        {signal && <SignalPill signal={signal.signal} strength={signal.strength} />}
      </div>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 10, marginBottom: 8 }}>
        <span style={{
          fontSize: 28, fontWeight: 700, color: isCrypto ? T.gold : T.text,
          letterSpacing: "-0.02em", fontVariantNumeric: "tabular-nums",
          fontFamily: T.font,
        }}>
          ${Number(quote.c).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
        </span>
        <span style={{
          fontSize: 13, fontWeight: 500,
          color: up ? T.green : T.red,
          marginBottom: 3,
        }}>
          {up ? "+" : ""}{chg.toFixed(2)}%
        </span>
      </div>
      {!isCrypto && quote.h && (
        <div style={{ display: "flex", gap: 16, paddingTop: 10, borderTop: `0.5px solid ${T.sep}` }}>
          {[["O", quote.o], ["H", quote.h], ["L", quote.l], ["C", quote.pc]].map(([lbl, val]) => (
            <div key={lbl}>
              <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 2, letterSpacing: "0.06em" }}>{lbl}</div>
              <div style={{ fontSize: 12, color: T.textSub, fontVariantNumeric: "tabular-nums" }}>${Number(val).toFixed(2)}</div>
            </div>
          ))}
        </div>
      )}
      {signal && signal.reason && (
        <div style={{
          marginTop: 10, paddingTop: 10, borderTop: `0.5px solid ${T.sep}`,
          fontSize: 12, color: T.textSub, lineHeight: 1.55,
        }}>
          {signal.reason}
        </div>
      )}
    </div>
  );
}

function WeeklyReport({ onClose }) {
  const r = LearningAgent.generateReport();
  return (
    <div style={{
      position: "absolute", inset: 0, zIndex: 60,
      background: "rgba(0,0,0,0.6)",
      backdropFilter: T.glass,
      WebkitBackdropFilter: T.glass,
      display: "flex", flexDirection: "column",
      animation: "fadeUp 0.35s cubic-bezier(0.25,0.46,0.45,0.94)",
    }}>
      <div style={{
        flex: 1, display: "flex", flexDirection: "column",
        background: "#111114",
        borderRadius: `${T.radius.lg}px ${T.radius.lg}px 0 0`,
        marginTop: 44,
        overflow: "hidden",
      }}>
        <div style={{
          padding: "16px 20px",
          borderBottom: `0.5px solid ${T.sep}`,
          display: "flex", justifyContent: "space-between", alignItems: "center",
          flexShrink: 0,
        }}>
          <div>
            <div style={{ fontSize: 17, fontWeight: 600, color: T.text }}>Weekly Report</div>
            <div style={{ fontSize: 12, color: T.textMuted, marginTop: 1 }}>{r.period}</div>
          </div>
          <button onClick={onClose} style={{
            background: "rgba(255,255,255,0.08)", border: `0.5px solid ${T.border}`,
            borderRadius: T.radius.pill, padding: "6px 16px",
            color: T.textSub, cursor: "pointer", fontSize: 14, fontFamily: T.font,
          }}>Done</button>
        </div>
        <div style={{ flex: 1, overflowY: "auto", padding: "20px 16px" }}>
          {/* Profile Card */}
          <div style={{ marginBottom: 8, fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", paddingLeft: 4 }}>Your Profile</div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, overflow: "hidden", marginBottom: 20 }}>
            {[["Monthly Budget", USER_PROFILE.budgetRange], ["Risk Level", "Medium"], ["Strategy", "Index-first"], ["Split", "60% VOO / 30% QQQ / 10% cash"]].map(([k, v], i, arr) => (
              <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "12px 16px", borderBottom: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none", alignItems: "center" }}>
                <span style={{ fontSize: 14, color: T.textSub }}>{k}</span>
                <span style={{ fontSize: 14, fontWeight: 500, color: T.gold }}>{v}</span>
              </div>
            ))}
          </div>
          {/* Usage */}
          <div style={{ marginBottom: 8, fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", paddingLeft: 4 }}>This Week</div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, overflow: "hidden", marginBottom: 20 }}>
            {[["Sessions", r.totalSessions, T.green], ["Messages", r.totalMessages, T.green], ["Avg per Session", r.totalSessions > 0 ? (r.totalMessages / r.totalSessions).toFixed(1) : 0, T.green]].map(([k, v, c], i, arr) => (
              <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "12px 16px", borderBottom: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none", alignItems: "center" }}>
                <span style={{ fontSize: 14, color: T.textSub }}>{k}</span>
                <span style={{ fontSize: 14, fontWeight: 600, color: c, fontVariantNumeric: "tabular-nums" }}>{v}</span>
              </div>
            ))}
          </div>
          {/* Topics */}
          {r.topTopics.length > 0 && (
            <>
              <div style={{ marginBottom: 8, fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", paddingLeft: 4 }}>Top Topics</div>
              <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, overflow: "hidden", marginBottom: 20 }}>
                {r.topTopics.map(([topic, count], i, arr) => (
                  <div key={topic} style={{ padding: "12px 16px", borderBottom: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                      <span style={{ fontSize: 14, color: T.textSub }}>{topic}</span>
                      <span style={{ fontSize: 13, color: T.textMuted, fontVariantNumeric: "tabular-nums" }}>{count}</span>
                    </div>
                    <div style={{ height: 3, background: "rgba(255,255,255,0.06)", borderRadius: 2 }}>
                      <div style={{ width: `${(count / (r.topTopics[0]?.[1] || 1)) * 100}%`, height: "100%", background: T.gold, borderRadius: 2, transition: "width 0.6s ease" }} />
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
          {/* Security */}
          <div style={{ marginBottom: 8, fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", paddingLeft: 4 }}>Security</div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, overflow: "hidden", marginBottom: 32 }}>
            {[["Threats Blocked", r.securityThreats, r.securityThreats > 0 ? T.red : T.green], ["API Calls", r.apiCalls, T.gold], ["Errors", r.errors, r.errors > 0 ? T.red : T.green], ["Session ID", r.sessionId, T.textMuted]].map(([k, v, c], i, arr) => (
              <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "12px 16px", borderBottom: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none", alignItems: "center" }}>
                <span style={{ fontSize: 14, color: T.textSub }}>{k}</span>
                <span style={{ fontSize: 13, fontWeight: 500, color: c, fontVariantNumeric: "tabular-nums" }}>{v}</span>
              </div>
            ))}
          </div>
          <div style={{ textAlign: "center", fontSize: 11, color: T.textMuted, marginBottom: 8 }}>For educational use only · Not financial advice</div>
        </div>
      </div>
    </div>
  );
}

// ─── MAIN ──────────────────────────────────────────────────────────────────────
export default function ATLASv3() {
  const [tab, setTab] = useState("chat");
  const [messages, setMessages] = useState([{
    role: "assistant",
    content: "ATLAS online. Your profile is loaded.\n\n• Budget: $100–$300/month\n• Strategy: VOO + QQQ core\n• Risk: Medium — balanced growth\n\nPulling live market data now. I'll surface buy and sell signals as conditions change.\n\nWhat do you want to know?",
  }]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [marketData, setMarketData] = useState(null);
  const [marketLoading, setMarketLoading] = useState(true);
  const [alerts, setAlerts] = useState([]);
  const [showReport, setShowReport] = useState(false);
  const [notifGranted, setNotifGranted] = useState(false);
  const [agentActive, setAgentActive] = useState({ intel: false, market: false });
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);
  const recommendation = SignalEngine.getIndexRecommendation(USER_PROFILE.monthlyBudget);

  useEffect(() => { NotificationSystem.requestPermission().then(setNotifGranted); }, []);

  const fetchMarket = useCallback(async () => {
    setMarketLoading(true);
    setAgentActive((s) => ({ ...s, market: true }));
    const data = await MarketAgent.getSnapshot();
    setMarketData(data);
    setMarketLoading(false);
    setAgentActive((s) => ({ ...s, market: false }));
    if (data.signals) {
      const newAlerts = [];
      data.signals.forEach((sig) => {
        if (sig.signal === "SELL") {
          const a = { type: "sell", title: `Sell Signal — ${sig.symbol}`, body: sig.reason };
          NotificationSystem.send(a.title, a.body, "sell"); newAlerts.push(a);
        } else if (sig.signal === "BUY") {
          const a = { type: "buy", title: `Buy Opportunity — ${sig.symbol}`, body: sig.reason };
          NotificationSystem.send(a.title, a.body, "buy"); newAlerts.push(a);
        }
      });
      if (newAlerts.length > 0) setAlerts((prev) => [...newAlerts, ...prev].slice(0, 5));
    }
  }, []);

  useEffect(() => {
    fetchMarket();
    const interval = setInterval(fetchMarket, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, [fetchMarket]);

  useEffect(() => { messagesEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const sendMessage = useCallback(async (text) => {
    const raw = text || input.trim();
    if (!raw || loading) return;
    const userText = SecurityAgent.sanitize(raw);
    setInput("");
    const newMessages = [...messages, { role: "user", content: userText }];
    setMessages(newMessages);
    setLoading(true);
    setAgentActive((s) => ({ ...s, intel: true }));
    setMessages((prev) => [...prev, { role: "assistant", content: "", typing: true }]);
    try {
      SecurityAgent.logEvent("API_CALL", "Chat");
      const snapshot = MarketAgent.formatForAI(marketData);
      const apiMsgs = newMessages.map((m) => ({ role: m.role, content: m.content }));
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": getApiKey(), "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" },
        body: JSON.stringify({ model: "claude-sonnet-4-20250514", max_tokens: 1000, system: buildPrompt(snapshot), tools: [{ type: "web_search_20250305", name: "web_search" }], messages: apiMsgs }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error.message);
      let finalText = "";
      if (data.content?.some((b) => b.type === "tool_use")) {
        setMessages((prev) => { const u = [...prev]; u[u.length - 1] = { role: "assistant", content: "Searching live data…", searching: true }; return u; });
        const res2 = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-api-key": getApiKey(), "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" },
          body: JSON.stringify({ model: "claude-sonnet-4-20250514", max_tokens: 1000, system: buildPrompt(snapshot), tools: [{ type: "web_search_20250305", name: "web_search" }], messages: [...apiMsgs, { role: "assistant", content: data.content }] }),
        });
        const d2 = await res2.json();
        finalText = (d2.content || []).filter((b) => b.type === "text").map((b) => b.text).join("");
      } else {
        finalText = (data.content || []).filter((b) => b.type === "text").map((b) => b.text).join("");
      }
      const lower = finalText.toLowerCase();
      if (lower.includes("sell") && lower.includes("recommend")) {
        const a = { type: "sell", title: "ATLAS recommends considering a sell", body: finalText.slice(0, 120) + "…" };
        NotificationSystem.send(a.title, a.body, "sell"); setAlerts((prev) => [a, ...prev].slice(0, 5));
      } else if (lower.includes("strong buy") || (lower.includes("buy") && lower.includes("opportunity"))) {
        const a = { type: "buy", title: "ATLAS identified a buy opportunity", body: finalText.slice(0, 120) + "…" };
        NotificationSystem.send(a.title, a.body, "buy"); setAlerts((prev) => [a, ...prev].slice(0, 5));
      }
      LearningAgent.logSession([...newMessages, { role: "assistant", content: finalText }]);
      setMessages((prev) => { const u = [...prev]; u[u.length - 1] = { role: "assistant", content: finalText || "No response." }; return u; });
    } catch (err) {
      SecurityAgent.logEvent("ERROR", err.message);
      setMessages((prev) => { const u = [...prev]; u[u.length - 1] = { role: "assistant", content: !getApiKey() ? "Add VITE_ANTHROPIC_KEY to Secrets to activate ATLAS." : `Error: ${err.message}` }; return u; });
    }
    setLoading(false);
    setAgentActive((s) => ({ ...s, intel: false }));
  }, [input, loading, messages, marketData]);

  const quickPrompts = ["Should I invest now?", "VOO vs QQQ today?", "Bitcoin outlook?", "Build my $200 plan", "Any sell signals?"];
  const TABS = ["chat", "market", "plan"];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", background: T.bg, fontFamily: T.font, overflow: "hidden", color: T.text }}>
      <style>{`
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        @keyframes pulse { 0%,100%{opacity:.35;transform:scale(.8)} 50%{opacity:1;transform:scale(1)} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(30px)} to{opacity:1;transform:translateY(0)} }
        @keyframes slideDown { from{opacity:0;transform:translateY(-6px)} to{opacity:1;transform:translateY(0)} }
        @keyframes blink { 0%,100%{opacity:.3} 50%{opacity:1} }
        ::-webkit-scrollbar { width: 0; }
        textarea { resize: none; }
        textarea::placeholder { color: rgba(235,235,245,0.25); }
        button { font-family: inherit; }
      `}</style>

      {showReport && <WeeklyReport onClose={() => setShowReport(false)} />}

      {/* ── NAVIGATION BAR ── */}
      <div style={{
        padding: "12px 16px 10px",
        borderBottom: `0.5px solid ${T.sep}`,
        background: "rgba(0,0,0,0.72)",
        backdropFilter: T.glass,
        WebkitBackdropFilter: T.glass,
        zIndex: 20, flexShrink: 0,
        display: "flex", alignItems: "center", gap: 12,
      }}>
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 9, flex: 1 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 9,
            background: `linear-gradient(145deg, ${T.gold}, #8b5e12)`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 13, fontWeight: 700, color: "#000",
            boxShadow: `0 0 0 0.5px rgba(255,255,255,0.1), 0 4px 12px rgba(212,168,83,0.3)`,
            flexShrink: 0,
          }}>A</div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600, color: T.text, letterSpacing: "-0.01em" }}>ATLAS</div>
            <div style={{ fontSize: 10, color: T.textMuted, letterSpacing: "0.01em" }}>Financial Intelligence</div>
          </div>
        </div>
        {/* Segmented Control */}
        <div style={{
          display: "flex",
          background: "rgba(118,118,128,0.18)",
          borderRadius: T.radius.sm,
          padding: 2, gap: 1,
        }}>
          {TABS.map((t) => (
            <button key={t} onClick={() => setTab(t)} style={{
              padding: "5px 12px",
              borderRadius: T.radius.xs,
              fontSize: 12, fontWeight: tab === t ? 600 : 400,
              color: tab === t ? T.text : T.textMuted,
              background: tab === t ? "rgba(255,255,255,0.14)" : "transparent",
              border: "none", cursor: "pointer",
              boxShadow: tab === t ? "0 1px 4px rgba(0,0,0,0.5)" : "none",
              transition: "all 0.18s ease",
              textTransform: "capitalize",
            }}>{t}</button>
          ))}
        </div>
        <button onClick={() => setShowReport(true)} style={{
          background: "rgba(255,255,255,0.06)",
          border: `0.5px solid ${T.border}`,
          borderRadius: T.radius.xs,
          padding: "5px 10px",
          color: T.textMuted, cursor: "pointer", fontSize: 11,
        }}>Report</button>
      </div>

      {/* ── STATUS ROW ── */}
      <div style={{
        display: "flex", gap: 6, padding: "6px 16px",
        background: "rgba(0,0,0,0.5)",
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
        borderBottom: `0.5px solid ${T.sep}`,
        flexShrink: 0, overflowX: "auto",
      }}>
        {[
          { label: "Intelligence", color: T.gold, active: agentActive.intel },
          { label: "Market Feed",  color: T.green, active: agentActive.market || marketLoading },
          { label: "Security",     color: "#6E7BF0", active: true },
          {
            label: notifGranted ? "Alerts On" : "Enable Alerts",
            color: notifGranted ? T.green : T.red,
            active: notifGranted,
            onClick: !notifGranted ? () => NotificationSystem.requestPermission().then(setNotifGranted) : undefined,
          },
        ].map((a) => (
          <div key={a.label} onClick={a.onClick} style={{
            display: "flex", alignItems: "center", gap: 5,
            padding: "3px 10px", borderRadius: T.radius.pill, flexShrink: 0,
            border: `0.5px solid ${a.active ? `${a.color}30` : "rgba(255,255,255,0.04)"}`,
            background: a.active ? `${a.color}0D` : "transparent",
            cursor: a.onClick ? "pointer" : "default",
            transition: "all 0.25s ease",
          }}>
            <div style={{
              width: 5, height: 5, borderRadius: "50%",
              background: a.active ? a.color : "rgba(255,255,255,0.1)",
              boxShadow: a.active ? `0 0 6px ${a.color}` : "none",
              animation: a.active ? "pulse 2.5s ease infinite" : "none",
            }} />
            <span style={{ fontSize: 10, color: a.active ? a.color : T.textMuted, fontWeight: 500 }}>{a.label}</span>
          </div>
        ))}
      </div>

      {/* ── LIVE TICKER ── */}
      {marketData && (
        <div style={{
          display: "flex", gap: 0,
          padding: "0 16px",
          borderBottom: `0.5px solid ${T.sep}`,
          background: "rgba(0,0,0,0.4)",
          flexShrink: 0, overflowX: "auto",
        }}>
          {[
            { label: "SPY", q: marketData.spy },
            { label: "QQQ", q: marketData.qqq },
            { label: "VOO", q: marketData.voo },
            { label: "BTC", q: marketData.btc, crypto: true },
            { label: "ETH", q: marketData.eth, crypto: true },
          ].map(({ label, q, crypto }, i, arr) => {
            if (!q || !q.c) return null;
            const chg = q.pc ? ((q.c - q.pc) / q.pc) * 100 : 0;
            const sig = marketData.signals?.find((s) => s.symbol === label);
            return (
              <div key={label} style={{
                display: "flex", alignItems: "center", gap: 6,
                padding: "7px 14px",
                borderRight: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none",
                flexShrink: 0,
              }}>
                <span style={{ fontSize: 10, fontWeight: 600, color: T.textMuted, letterSpacing: "0.04em" }}>{label}</span>
                <span style={{
                  fontSize: 11, color: crypto ? T.gold : T.text,
                  fontVariantNumeric: "tabular-nums", fontWeight: 500,
                }}>
                  ${Number(q.c).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
                </span>
                <span style={{ fontSize: 10, color: chg >= 0 ? T.green : T.red, fontVariantNumeric: "tabular-nums" }}>
                  {chg >= 0 ? "+" : ""}{chg.toFixed(2)}%
                </span>
                {sig && sig.signal !== "HOLD" && <SignalPill signal={sig.signal} />}
              </div>
            );
          })}
        </div>
      )}

      {/* ── ALERTS ── */}
      {alerts.length > 0 && tab === "chat" && (
        <div style={{ flexShrink: 0 }}>
          {alerts.slice(0, 2).map((a, i) => (
            <AlertBanner key={i} alert={a} onDismiss={() => setAlerts((prev) => prev.filter((_, j) => j !== i))} />
          ))}
        </div>
      )}

      {/* ── CHAT TAB ── */}
      {tab === "chat" && (
        <>
          <div style={{ flex: 1, overflowY: "auto", paddingTop: 16, paddingBottom: 8 }}>
            {messages.map((msg, i) => {
              const isUser = msg.role === "user";
              return (
                <div key={i} style={{
                  display: "flex",
                  justifyContent: isUser ? "flex-end" : "flex-start",
                  padding: "0 16px",
                  marginBottom: 10,
                  animation: "fadeIn 0.25s cubic-bezier(0.25,0.46,0.45,0.94)",
                  alignItems: "flex-end", gap: 8,
                }}>
                  {!isUser && !msg.typing && (
                    <div style={{
                      width: 24, height: 24, borderRadius: 7, flexShrink: 0,
                      background: `linear-gradient(145deg, ${T.gold}, #8b5e12)`,
                      display: "flex", alignItems: "center", justifyContent: "center",
                      fontSize: 10, fontWeight: 700, color: "#000",
                      marginBottom: 2,
                    }}>A</div>
                  )}
                  {msg.typing ? (
                    <div style={{
                      display: "flex", alignItems: "center", gap: 5,
                      background: T.card,
                      border: `0.5px solid ${T.border}`,
                      borderRadius: "4px 16px 16px 16px",
                      padding: "12px 16px",
                      marginLeft: 32,
                    }}>
                      {[0, 1, 2].map((j) => (
                        <div key={j} style={{
                          width: 6, height: 6, borderRadius: "50%",
                          background: T.gold,
                          animation: `pulse 1.4s ease ${j * 0.18}s infinite`,
                        }} />
                      ))}
                    </div>
                  ) : (
                    <div style={{
                      maxWidth: "78%",
                      padding: "11px 14px",
                      borderRadius: isUser
                        ? "16px 16px 4px 16px"
                        : i === 0 ? "16px 16px 16px 4px" : "4px 16px 16px 16px",
                      background: isUser ? T.goldDim : T.card,
                      border: `0.5px solid ${isUser ? T.goldBorder : T.border}`,
                      boxShadow: "0 1px 6px rgba(0,0,0,0.25)",
                      fontSize: 14, lineHeight: 1.6,
                      color: T.text,
                      whiteSpace: "pre-wrap", wordBreak: "break-word",
                    }}>
                      {msg.content}
                      {msg.searching && (
                        <div style={{
                          marginTop: 6, display: "flex", alignItems: "center", gap: 5,
                          fontSize: 11, color: T.gold,
                          animation: "blink 1.2s ease infinite",
                        }}>
                          <div style={{ width: 5, height: 5, borderRadius: "50%", background: T.gold }} />
                          Searching live data…
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Prompts */}
          {messages.length <= 1 && (
            <div style={{
              padding: "6px 0 6px 16px",
              display: "flex", gap: 7, overflowX: "auto",
              flexShrink: 0,
            }}>
              {quickPrompts.map((p) => (
                <button key={p} onClick={() => sendMessage(p)} style={{
                  background: T.card,
                  border: `0.5px solid ${T.border}`,
                  borderRadius: T.radius.pill,
                  padding: "7px 14px",
                  color: T.textSub, fontSize: 12, fontWeight: 500,
                  cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0,
                  transition: "all 0.18s ease",
                }}>{p}</button>
              ))}
            </div>
          )}

          {/* Input Bar */}
          <div style={{
            padding: "10px 16px 22px",
            borderTop: `0.5px solid ${T.sep}`,
            background: "rgba(0,0,0,0.6)",
            backdropFilter: "blur(30px)",
            WebkitBackdropFilter: "blur(30px)",
            flexShrink: 0,
          }}>
            <div style={{
              display: "flex", gap: 10, alignItems: "flex-end",
              background: "rgba(28,28,30,0.9)",
              border: `0.5px solid ${T.borderStrong}`,
              borderRadius: 20,
              padding: "10px 10px 10px 16px",
              boxShadow: "0 2px 12px rgba(0,0,0,0.3)",
            }}>
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
                placeholder="Ask about markets, budget, investments…"
                rows={1}
                style={{
                  flex: 1, background: "transparent", border: "none", outline: "none",
                  color: T.text, fontSize: 14, fontFamily: T.font,
                  lineHeight: 1.5, maxHeight: 100, overflowY: "auto",
                }}
                onInput={(e) => {
                  e.target.style.height = "auto";
                  e.target.style.height = Math.min(e.target.scrollHeight, 100) + "px";
                }}
              />
              <button
                onClick={() => sendMessage()}
                disabled={loading || !input.trim()}
                style={{
                  width: 34, height: 34, borderRadius: "50%", border: "none",
                  background: !loading && input.trim()
                    ? `linear-gradient(145deg, ${T.gold}, #8b5e12)`
                    : "rgba(255,255,255,0.07)",
                  cursor: !loading && input.trim() ? "pointer" : "not-allowed",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  flexShrink: 0, transition: "all 0.2s ease",
                  boxShadow: !loading && input.trim() ? `0 2px 10px rgba(212,168,83,0.35)` : "none",
                }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                  stroke={!loading && input.trim() ? "#000" : "rgba(255,255,255,0.25)"}
                  strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="22" y1="2" x2="11" y2="13" />
                  <polygon points="22 2 15 22 11 13 2 9 22 2" />
                </svg>
              </button>
            </div>
            <div style={{ textAlign: "center", fontSize: 10, color: "rgba(255,255,255,0.12)", marginTop: 6, letterSpacing: "0.03em" }}>
              Educational use only · Not financial advice
            </div>
          </div>
        </>
      )}

      {/* ── MARKET TAB ── */}
      {tab === "market" && (
        <div style={{ flex: 1, overflowY: "auto", padding: "16px 16px 32px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
            <span style={{ fontSize: 11, color: T.textMuted }}>
              {marketData ? `Updated ${marketData.fetchedAt?.toLocaleTimeString()}` : "Loading…"}
            </span>
            <button onClick={fetchMarket} style={{
              background: T.card, border: `0.5px solid ${T.border}`,
              borderRadius: T.radius.xs, padding: "4px 10px",
              color: T.gold, cursor: "pointer", fontSize: 11, fontWeight: 500,
            }}>↻ Refresh</button>
          </div>

          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Indices & ETFs</div>
          {[
            { label: "S&P 500 — SPY", q: marketData?.spy, sig: marketData?.signals?.find((s) => s.symbol === "SPY") },
            { label: "NASDAQ — QQQ", q: marketData?.qqq, sig: marketData?.signals?.find((s) => s.symbol === "QQQ") },
            { label: "Vanguard S&P 500 — VOO", q: marketData?.voo, sig: marketData?.signals?.find((s) => s.symbol === "VOO") },
          ].map((item) => <MarketCard key={item.label} quote={item.q} label={item.label} signal={item.sig} />)}

          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", margin: "16px 0 8px" }}>Crypto</div>
          {[{ label: "Bitcoin", q: marketData?.btc }, { label: "Ethereum", q: marketData?.eth }].map((item) => (
            <MarketCard key={item.label} quote={item.q} label={item.label} isCrypto />
          ))}

          {marketData?.news?.length > 0 && (
            <>
              <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", margin: "16px 0 8px" }}>Headlines</div>
              {marketData.news.map((n, i) => (
                <div key={i} style={{
                  background: T.card, border: `0.5px solid ${T.border}`,
                  borderRadius: T.radius.md, padding: "12px 14px", marginBottom: 8,
                }}>
                  <div style={{ fontSize: 13, color: T.text, lineHeight: 1.5, marginBottom: 5 }}>{n.headline}</div>
                  <div style={{ fontSize: 11, color: T.textMuted }}>
                    {n.source} · {new Date(n.datetime * 1000).toLocaleDateString()}
                  </div>
                </div>
              ))}
            </>
          )}
        </div>
      )}

      {/* ── PLAN TAB ── */}
      {tab === "plan" && (
        <div style={{ flex: 1, overflowY: "auto", padding: "16px 16px 40px" }}>
          {/* Hero Card */}
          <div style={{
            background: `linear-gradient(145deg, rgba(212,168,83,0.12), rgba(212,168,83,0.04))`,
            border: `0.5px solid ${T.goldBorder}`,
            borderRadius: T.radius.lg, padding: 20, marginBottom: 20,
            boxShadow: "0 4px 24px rgba(212,168,83,0.08)",
          }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: T.gold, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>Your Investment Plan</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: T.text, marginBottom: 8, letterSpacing: "-0.01em" }}>{recommendation.pick}</div>
            <div style={{ fontSize: 13, color: T.textSub, lineHeight: 1.6, marginBottom: 16 }}>{recommendation.rationale}</div>
            <div style={{ background: "rgba(0,0,0,0.3)", borderRadius: T.radius.sm, padding: "12px 14px" }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Monthly Breakdown</div>
              <div style={{ fontSize: 13, color: T.gold, lineHeight: 1.9, fontVariantNumeric: "tabular-nums" }}>{recommendation.monthlyPlan}</div>
            </div>
          </div>

          {/* Allocation */}
          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Allocation</div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: "14px 16px", marginBottom: 20 }}>
            {recommendation.allocation.split(", ").map((item, i) => {
              const [pct, ...rest] = item.split(" ");
              const num = parseInt(pct);
              const colors = [T.gold, "#6E7BF0", T.green];
              return (
                <div key={i} style={{ marginBottom: i < 2 ? 14 : 0 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <span style={{ fontSize: 14, color: T.textSub }}>{rest.join(" ")}</span>
                    <span style={{ fontSize: 14, fontWeight: 600, color: colors[i], fontVariantNumeric: "tabular-nums" }}>{pct}</span>
                  </div>
                  <div style={{ height: 3, background: "rgba(255,255,255,0.06)", borderRadius: 100 }}>
                    <div style={{ width: `${num}%`, height: "100%", background: colors[i], borderRadius: 100, transition: "width 0.7s cubic-bezier(0.25,0.46,0.45,0.94)" }} />
                  </div>
                </div>
              );
            })}
          </div>

          {/* DCA Strategy */}
          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Strategy</div>
          <div style={{
            background: T.greenDim, border: `0.5px solid ${T.greenBorder}`,
            borderRadius: T.radius.md, padding: 16, marginBottom: 20,
          }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: T.green, marginBottom: 8 }}>Dollar-Cost Averaging</div>
            <div style={{ fontSize: 13, color: T.textSub, lineHeight: 1.6, marginBottom: 12 }}>
              Invest your $100–$300 on the same day every month — regardless of market conditions. This removes emotion from investing and builds wealth steadily over time. Don't try to time the market.
            </div>
            <div style={{ background: "rgba(0,0,0,0.25)", borderRadius: T.radius.xs, padding: "8px 12px", fontSize: 12, color: T.green, fontWeight: 500 }}>
              Set a recurring buy on the 1st of each month
            </div>
          </div>

          {/* Sell Rules */}
          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>When To Sell</div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, overflow: "hidden", marginBottom: 8 }}>
            {[
              "A position is up 20%+ and the market shows overbought signals",
              "You need the money within 12 months — don't keep it invested",
              "Fundamental news changes (company scandal, index delisting)",
              "ATLAS fires a SELL signal with 70%+ confidence",
            ].map((rule, i, arr) => (
              <div key={i} style={{
                display: "flex", gap: 12, padding: "13px 16px",
                borderBottom: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none",
                alignItems: "flex-start",
              }}>
                <div style={{
                  width: 20, height: 20, borderRadius: 6, flexShrink: 0,
                  background: T.redDim, border: `0.5px solid ${T.redBorder}`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 10, fontWeight: 700, color: T.red, marginTop: 1,
                }}>{i + 1}</div>
                <div style={{ fontSize: 13, color: T.textSub, lineHeight: 1.55 }}>{rule}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
