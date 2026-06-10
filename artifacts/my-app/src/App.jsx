import { useState, useRef, useEffect, useCallback } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip,
  ResponsiveContainer, ReferenceLine, CartesianGrid,
} from "recharts";

// ─── CONFIG ────────────────────────────────────────────────────────────────────
const getFinnhubKey = () => (typeof import.meta !== "undefined" && import.meta.env?.VITE_FINNHUB_KEY) || "";
const API_BASE = "/api";

// ─── SECURITY GUARDIAN ─────────────────────────────────────────────────────────
const SecurityAgent = {
  log: [],
  sessionId: Math.random().toString(36).slice(2, 10).toUpperCase(),
  _requestTimestamps: [],
  RATE_LIMIT: { maxRequests: 20, windowMs: 60_000 },
  THREAT_PATTERNS: [
    /(<script|javascript:|on\w+\s*=|<iframe|<object|eval\s*\(|document\.cookie|window\.location)/gi,
    /(union\s+select|drop\s+table|insert\s+into|delete\s+from|exec\s*\()/gi,
    /(\.\.\/|\.\.\\|%2e%2e|%252e)/gi,
  ],
  sanitize(input) {
    if (typeof input !== "string") return "";
    let cleaned = input;
    let blocked = false;
    this.THREAT_PATTERNS.forEach(pattern => {
      if (pattern.test(cleaned)) { cleaned = cleaned.replace(pattern, "[BLOCKED]"); blocked = true; }
    });
    if (blocked) this.logEvent("THREAT_BLOCKED", `Malicious pattern in input: ${input.slice(0, 60)}`);
    return cleaned.slice(0, 4000);
  },
  checkRateLimit() {
    const now = Date.now();
    this._requestTimestamps = this._requestTimestamps.filter(t => now - t < this.RATE_LIMIT.windowMs);
    if (this._requestTimestamps.length >= this.RATE_LIMIT.maxRequests) {
      this.logEvent("RATE_LIMITED", `${this._requestTimestamps.length} requests in 60s`);
      return false;
    }
    this._requestTimestamps.push(now);
    return true;
  },
  validateApiResponse(data) {
    if (typeof data !== "object" || data === null) return false;
    if (data.content && typeof data.content !== "string") return false;
    return true;
  },
  logEvent(type, detail) {
    const e = { time: new Date().toISOString(), type, detail, session: this.sessionId };
    this.log.push(e);
    if (this.log.length > 500) this.log.shift();
    return e;
  },
  getReport() {
    return {
      threats: this.log.filter(e => e.type === "THREAT_BLOCKED"),
      rateLimited: this.log.filter(e => e.type === "RATE_LIMITED"),
      apiCalls: this.log.filter(e => e.type === "API_CALL"),
      errors: this.log.filter(e => e.type === "ERROR"),
      total: this.log.length,
      sessionId: this.sessionId,
    };
  },
};

// ─── ERROR RECOVERY AGENT ──────────────────────────────────────────────────────
const ErrorRecoveryAgent = {
  MAX_RETRIES: 3,
  BACKOFF_MS: [1200, 2500, 4000],
  errorLog: [],
  friendlyMessage(err) {
    const msg = err?.message || String(err);
    if (msg.includes("404")) return "ATLAS couldn't reach the AI service. The route is misconfigured — auto-retrying…";
    if (msg.includes("429") || msg.includes("rate")) return "Too many requests. Waiting a moment before retrying…";
    if (msg.includes("500") || msg.includes("502") || msg.includes("503")) return "The AI server had a hiccup. Retrying automatically…";
    if (msg.includes("Failed to fetch") || msg.includes("NetworkError") || msg.includes("ECONNREFUSED")) return "Network connection lost. Retrying when connection restores…";
    if (msg.includes("timeout") || msg.includes("AbortError")) return "Request timed out. Retrying with a fresh connection…";
    if (msg.includes("GEMINI_API_KEY")) return "AI service key not configured on server. Please check environment variables.";
    return `Something went wrong: ${msg.slice(0, 120)}`;
  },
  async withRetry(fn, onRetry) {
    for (let attempt = 1; attempt <= this.MAX_RETRIES; attempt++) {
      try {
        return await fn(attempt);
      } catch (err) {
        const isLast = attempt === this.MAX_RETRIES;
        this.errorLog.push({ time: new Date().toISOString(), attempt, error: err.message });
        if (this.errorLog.length > 200) this.errorLog.shift();
        SecurityAgent.logEvent("ERROR", `Attempt ${attempt}/${this.MAX_RETRIES}: ${err.message}`);
        if (isLast) throw err;
        if (onRetry) onRetry(attempt, this.BACKOFF_MS[attempt - 1]);
        await new Promise(r => setTimeout(r, this.BACKOFF_MS[attempt - 1]));
      }
    }
  },
};

// ─── PRICE ALERT MANAGER ───────────────────────────────────────────────────────
const PriceAlertManager = {
  _key: "atlas_price_alerts",
  load() {
    try { return JSON.parse(localStorage.getItem(this._key) || "[]"); } catch { return []; }
  },
  save(alerts) { localStorage.setItem(this._key, JSON.stringify(alerts)); },
  add(symbol, targetPrice, direction) {
    const alerts = this.load();
    const id = Date.now();
    alerts.push({ id, symbol: symbol.toUpperCase(), targetPrice: +targetPrice, direction, triggered: false, createdAt: new Date().toISOString() });
    this.save(alerts);
    return id;
  },
  remove(id) {
    const alerts = this.load().filter(a => a.id !== id);
    this.save(alerts);
  },
  markTriggered(id) {
    const alerts = this.load().map(a => a.id === id ? { ...a, triggered: true, triggeredAt: new Date().toISOString() } : a);
    this.save(alerts);
  },
  check(prices) {
    const alerts = this.load();
    let fired = 0;
    alerts.forEach(alert => {
      if (alert.triggered) return;
      const cur = prices[alert.symbol];
      if (!cur) return;
      const hit = alert.direction === "above" ? cur >= alert.targetPrice : cur <= alert.targetPrice;
      if (hit) {
        const title = `🔔 ATLAS Alert: ${alert.symbol} ${alert.direction === "above" ? "reached" : "dropped to"} $${cur.toFixed(2)}`;
        const body = `Your target was $${alert.targetPrice}. ${alert.direction === "above" ? "Consider taking profit." : "Consider your stop-loss plan."}`;
        NotificationSystem.send(title, body);
        this.markTriggered(alert.id);
        fired++;
      }
    });
    return fired;
  },
  getActive() { return this.load().filter(a => !a.triggered); },
  getAll() { return this.load(); },
};

// ─── TECHNICAL ANALYSIS ENGINE ─────────────────────────────────────────────────
const TA = {
  sma(prices, period) {
    if (!prices || prices.length < period) return null;
    return prices.slice(-period).reduce((a, b) => a + b, 0) / period;
  },
  ema(prices, period) {
    if (!prices || prices.length < period) return null;
    const k = 2 / (period + 1);
    let val = prices.slice(0, period).reduce((a, b) => a + b, 0) / period;
    for (let i = period; i < prices.length; i++) val = prices[i] * k + val * (1 - k);
    return val;
  },
  rsi(prices, period = 14) {
    if (!prices || prices.length < period + 2) return null;
    const changes = prices.slice(-period - 1).map((p, i, a) => i === 0 ? 0 : p - a[i - 1]).slice(1);
    let avgGain = changes.map(c => Math.max(0, c)).reduce((a, b) => a + b, 0) / period;
    let avgLoss = changes.map(c => Math.max(0, -c)).reduce((a, b) => a + b, 0) / period;
    if (avgLoss === 0) return 100;
    return Math.round((100 - 100 / (1 + avgGain / avgLoss)) * 10) / 10;
  },
  macd(prices) {
    const ema12 = this.ema(prices, 12);
    const ema26 = this.ema(prices, 26);
    if (ema12 === null || ema26 === null) return null;
    const line = ema12 - ema26;
    const ema12Prev = this.ema(prices.slice(0, -1), 12);
    const ema26Prev = this.ema(prices.slice(0, -1), 26);
    const linePrev = ema12Prev && ema26Prev ? ema12Prev - ema26Prev : line;
    const signal = linePrev * 0.75 + line * 0.25;
    return { line, signal, histogram: line - signal, bullish: line > signal };
  },
  bollingerBands(prices, period = 20, mult = 2) {
    if (!prices || prices.length < period) return null;
    const slice = prices.slice(-period);
    const mean = slice.reduce((a, b) => a + b, 0) / period;
    const std = Math.sqrt(slice.reduce((s, p) => s + (p - mean) ** 2, 0) / period);
    const bandwidth = (mult * 2 * std) / mean;
    return { upper: mean + mult * std, middle: mean, lower: mean - mult * std, std, bandwidth };
  },
  percentChange(prices, days) {
    if (!prices || prices.length < 2) return null;
    const slice = prices.slice(-Math.min(days + 1, prices.length));
    return ((slice[slice.length - 1] - slice[0]) / slice[0]) * 100;
  },
  atr(highs, lows, closes, period = 14) {
    if (!highs || highs.length < period + 1) return null;
    const trs = highs.slice(-period).map((h, i) => {
      const l = lows.slice(-period)[i];
      const pc = closes.slice(-period - 1)[i];
      return Math.max(h - l, Math.abs(h - pc), Math.abs(l - pc));
    });
    return trs.reduce((a, b) => a + b, 0) / period;
  },
};

// ─── RISK ENGINE ───────────────────────────────────────────────────────────────
const RiskEngine = {
  compute(tech, quote) {
    if (!tech || !quote?.c) return { level: "Unknown", score: 0, color: "gray", detail: "" };
    const price = quote.c;
    let score = 0;
    const factors = [];

    if (tech.atr) {
      const atrPct = (tech.atr / price) * 100;
      if (atrPct > 4)      { score += 40; factors.push(`High daily swing (ATR ${atrPct.toFixed(1)}%)`); }
      else if (atrPct > 2) { score += 25; factors.push(`Moderate swing (ATR ${atrPct.toFixed(1)}%)`); }
      else if (atrPct > 1) { score += 12; factors.push(`Low-moderate swing (ATR ${atrPct.toFixed(1)}%)`); }
      else                 { score += 4;  factors.push(`Low swing (ATR ${atrPct.toFixed(1)}%)`); }
    }

    if (tech.bb?.bandwidth) {
      const bw = tech.bb.bandwidth * 100;
      if (bw > 10)      { score += 25; factors.push(`High volatility (BB ${bw.toFixed(1)}%)`); }
      else if (bw > 5)  { score += 15; factors.push(`Medium volatility`); }
      else if (bw > 2)  { score += 7; }
    }

    if (tech.rsi !== null) {
      if (tech.rsi < 25 || tech.rsi > 80) { score += 20; factors.push(`Extreme RSI (${tech.rsi.toFixed(0)})`); }
      else if (tech.rsi < 35 || tech.rsi > 70) { score += 10; }
    }

    if (tech.compositeSignal === "BEARISH") score += 15;

    const level = score >= 65 ? "Very High" : score >= 40 ? "High" : score >= 20 ? "Medium" : "Low";
    const color = score >= 65 ? "#FF453A" : score >= 40 ? "#FF9F0A" : score >= 20 ? "#D4A853" : "#30D158";
    return { level, score, color, detail: factors.join(" · ") || "Stable conditions" };
  },
};

// ─── PREDICTION ENGINE (Monte Carlo) ──────────────────────────────────────────
const PredictionEngine = {
  generate(closes, days = 30) {
    if (!closes || closes.length < 10) return null;
    const returns = closes.slice(1).map((c, i) => Math.log(c / closes[i]));
    const mean = returns.reduce((a, b) => a + b, 0) / returns.length;
    const variance = returns.map(r => (r - mean) ** 2).reduce((a, b) => a + b, 0) / returns.length;
    const std = Math.sqrt(variance);
    const last = closes[closes.length - 1];

    const data = [{ day: 0, label: "Now", base: last, high: last, low: last, optimistic: last, pessimistic: last }];
    let base = last, high = last, low = last, opt = last, pess = last;

    for (let i = 1; i <= days; i++) {
      base  *= Math.exp(mean);
      high  *= Math.exp(mean + std * 0.5);
      low   *= Math.exp(mean - std * 0.5);
      opt   *= Math.exp(mean + std * 1.5);
      pess  *= Math.exp(mean - std * 1.5);

      const round = v => Math.round(v * 100) / 100;
      data.push({
        day: i,
        label: `Day ${i}`,
        base: round(base),
        high: round(high),
        low: round(low),
        optimistic: round(opt),
        pessimistic: round(pess),
        range: [round(pess), round(opt)],
      });
    }

    const baseReturn = ((base - last) / last) * 100;
    const optReturn  = ((opt  - last) / last) * 100;
    const pessReturn = ((pess - last) / last) * 100;
    return { data, baseReturn, optReturn, pessReturn, currentPrice: last, projectedPrice: base };
  },
};

// ─── PATTERN RECOGNIZER ────────────────────────────────────────────────────────
const PatternRecognizer = {
  detect(closes, highs, lows) {
    const patterns = [];
    if (!closes || closes.length < 20) return patterns;
    const n = closes.length;
    const cur = closes[n - 1];
    const sma50  = TA.sma(closes, Math.min(50, n));
    const sma200 = TA.sma(closes, Math.min(200, n));
    const sma50p = TA.sma(closes.slice(0, -1), Math.min(50, n - 1));
    const sma200p= TA.sma(closes.slice(0, -1), Math.min(200, n - 1));
    const sma20  = TA.sma(closes, Math.min(20, n));
    const rsi    = TA.rsi(closes);
    const macd   = TA.macd(closes);
    const bb     = TA.bollingerBands(closes);

    if (sma50 && sma200 && sma50p && sma200p && sma50 > sma200 && sma50p <= sma200p)
      patterns.push({ name: "Golden Cross 🟢", type: "bullish", strength: 92, desc: `50-day SMA ($${sma50.toFixed(2)}) just crossed above 200-day SMA ($${sma200.toFixed(2)}). Strong long-term buy signal.` });
    if (sma50 && sma200 && sma50p && sma200p && sma50 < sma200 && sma50p >= sma200p)
      patterns.push({ name: "Death Cross 🔴", type: "bearish", strength: 90, desc: `50-day SMA ($${sma50.toFixed(2)}) crossed below 200-day SMA ($${sma200.toFixed(2)}). Major bearish signal.` });
    if (sma20 && sma50 && sma200 && cur > sma20 && sma20 > sma50 && sma50 > sma200)
      patterns.push({ name: "Perfect Uptrend 🟢", type: "bullish", strength: 80, desc: `Price > 20d > 50d > 200d MA. Textbook bull trend.` });
    if (rsi !== null && rsi < 30)
      patterns.push({ name: `Oversold RSI ${rsi.toFixed(0)} ⚡`, type: "bullish", strength: 72, desc: `RSI ${rsi.toFixed(1)} — deep oversold. 73% historical recovery within 5–10 days.` });
    if (rsi !== null && rsi > 75)
      patterns.push({ name: `Overbought RSI ${rsi.toFixed(0)} ⚠️`, type: "bearish", strength: 68, desc: `RSI ${rsi.toFixed(1)} — overbought. Momentum slowdown likely.` });
    if (macd && macd.bullish && macd.histogram > 0)
      patterns.push({ name: "MACD Bullish ↑", type: "bullish", strength: 65, desc: `MACD line (${macd.line.toFixed(2)}) above signal. Bullish momentum.` });
    if (macd && !macd.bullish && macd.histogram < 0)
      patterns.push({ name: "MACD Bearish ↓", type: "bearish", strength: 60, desc: `MACD line (${macd.line.toFixed(2)}) below signal. Bearish momentum.` });
    if (bb && cur <= bb.lower)
      patterns.push({ name: "BB Lower Band", type: "bullish", strength: 64, desc: `Price at lower Bollinger Band. Mean-reversion to $${bb.middle.toFixed(2)} expected.` });
    if (bb && cur >= bb.upper)
      patterns.push({ name: "BB Upper Band", type: "bearish", strength: 60, desc: `Price at upper Bollinger Band. Pullback toward $${bb.middle.toFixed(2)} likely.` });
    if (bb && bb.bandwidth < 0.04)
      patterns.push({ name: "Volatility Squeeze ⚡", type: "neutral", strength: 70, desc: `Bands compressed — explosive move brewing.` });
    return patterns.slice(0, 5);
  },
};

// ─── HISTORICAL + TECHNICALS AGENT ────────────────────────────────────────────
const HistoricalAgent = {
  cache: {},

  async _fetchYahoo(symbol) {
    const ySymbol = { BTC: "BTC-USD", ETH: "ETH-USD" }[symbol] || symbol;
    const url = `https://query1.finance.yahoo.com/v8/finance/chart/${ySymbol}?range=6mo&interval=1d`;
    const proxies = [
      `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
      `https://corsproxy.io/?${encodeURIComponent(url)}`,
    ];
    for (const proxy of proxies) {
      try {
        const res = await fetch(proxy);
        if (!res.ok) continue;
        const json = await res.json();
        const result = json.chart?.result?.[0];
        const quotes = result?.indicators?.quote?.[0];
        if (!result || !quotes) continue;
        const closes = [], highs = [], lows = [], opens = [], timestamps = [];
        (result.timestamp || []).forEach((ts, i) => {
          const c = quotes.close?.[i], h = quotes.high?.[i], l = quotes.low?.[i], o = quotes.open?.[i];
          if (c != null) { closes.push(c); highs.push(h ?? c); lows.push(l ?? c); opens.push(o ?? c); timestamps.push(ts); }
        });
        if (closes.length >= 14) return { closes, highs, lows, opens, timestamps, volumes: [] };
      } catch {}
    }
    return null;
  },

  async fetchCandles(symbol) {
    const key = `candles_${symbol}`;
    const now = Date.now();
    if (this.cache[key] && now - this.cache[key].ts < 3_600_000) return this.cache[key].data;
    SecurityAgent.logEvent("API_CALL", `Historical: ${symbol}`);
    const result = await this._fetchYahoo(symbol);
    if (result) this.cache[key] = { data: result, ts: now };
    return result;
  },

  async searchSymbols(query) {
    if (!query || query.length < 1) return [];
    const key = `search_${query.toLowerCase()}`;
    const now = Date.now();
    if (this.cache[key] && now - this.cache[key].ts < 300_000) return this.cache[key].data;
    try {
      const finnhubKey = getFinnhubKey();
      if (finnhubKey) {
        const res = await fetch(`https://finnhub.io/api/v1/search?q=${encodeURIComponent(query)}&token=${finnhubKey}`);
        if (res.ok) {
          const data = await res.json();
          const results = (data.result || []).filter(r => r.type === "Common Stock" || r.type === "ETP").slice(0, 8).map(r => ({ symbol: r.symbol, name: r.description, type: r.type }));
          this.cache[key] = { data: results, ts: now };
          return results;
        }
      }
      // Fallback: Yahoo Finance autocomplete
      const url = `https://query1.finance.yahoo.com/v1/finance/search?q=${encodeURIComponent(query)}&quotesCount=8&newsCount=0`;
      const proxies = [
        `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
        `https://corsproxy.io/?${encodeURIComponent(url)}`,
      ];
      for (const proxy of proxies) {
        try {
          const res = await fetch(proxy);
          if (!res.ok) continue;
          const json = await res.json();
          const quotes = json.quotes || [];
          const results = quotes.filter(q => q.quoteType === "EQUITY" || q.quoteType === "ETF").slice(0, 8).map(q => ({ symbol: q.symbol, name: q.longname || q.shortname || q.symbol, type: q.quoteType }));
          if (results.length > 0) {
            this.cache[key] = { data: results, ts: now };
            return results;
          }
        } catch {}
      }
    } catch {}
    return [];
  },

  async fetchRecommendations(symbol) {
    const key = `rec_${symbol}`;
    const now = Date.now();
    if (this.cache[key] && now - this.cache[key].ts < 3_600_000) return this.cache[key].data;
    const finnhubKey = getFinnhubKey();
    if (!finnhubKey) return null;
    try {
      SecurityAgent.logEvent("API_CALL", `Recommendations: ${symbol}`);
      const res = await fetch(`https://finnhub.io/api/v1/recommendation?symbol=${symbol}&token=${finnhubKey}`);
      if (!res.ok) return null;
      const data = await res.json();
      if (!Array.isArray(data) || data.length === 0) return null;
      const d = data[0];
      const total = (d.buy || 0) + (d.hold || 0) + (d.sell || 0) + (d.strongBuy || 0) + (d.strongSell || 0);
      if (total === 0) return null;
      const bullishPct = Math.round(((d.strongBuy || 0) + (d.buy || 0)) / total * 100);
      const bearishPct = Math.round(((d.strongSell || 0) + (d.sell || 0)) / total * 100);
      const result = { period: d.period, strongBuy: d.strongBuy || 0, buy: d.buy || 0, hold: d.hold || 0, sell: d.sell || 0, strongSell: d.strongSell || 0, total, bullishPct, bearishPct, consensus: bullishPct > 55 ? "BUY" : bearishPct > 35 ? "SELL" : "HOLD" };
      this.cache[key] = { data: result, ts: now };
      return result;
    } catch { return null; }
  },

  computeTechnicals(candles) {
    if (!candles) return null;
    const { closes, highs, lows } = candles;
    const n = closes.length;
    if (n < 15) return null;
    const cur    = closes[n - 1];
    const rsi    = TA.rsi(closes);
    const macd   = TA.macd(closes);
    const sma20  = TA.sma(closes, Math.min(20, n));
    const sma50  = TA.sma(closes, Math.min(50, n));
    const sma200 = TA.sma(closes, Math.min(200, n));
    const bb     = TA.bollingerBands(closes);
    const atr    = TA.atr(highs, lows, closes);
    const ch30   = TA.percentChange(closes, 30);
    const ch60   = TA.percentChange(closes, 60);
    const ch90   = TA.percentChange(closes, Math.min(90, n - 1));
    const patterns = PatternRecognizer.detect(closes, highs, lows);

    let score = 0, count = 0;
    if (rsi !== null) { score += rsi < 30 ? 1 : rsi > 70 ? -1 : (50 - rsi) / 50 * 0.6; count++; }
    if (macd)         { score += macd.bullish ? 0.6 : -0.6; count++; }
    if (sma50)        { score += cur > sma50  ? 0.7 : -0.7; count++; }
    if (sma200)       { score += cur > sma200 ? 0.5 : -0.5; count++; }
    if (sma50 && sma200) { score += sma50 > sma200 ? 0.5 : -0.5; count++; }
    if (ch30 !== null){ score += ch30 > 0 ? 0.3 : -0.3; count++; }

    const composite = count > 0 ? score / count : 0;
    const compositeSignal = composite > 0.25 ? "BULLISH" : composite < -0.25 ? "BEARISH" : "NEUTRAL";
    const confidence = Math.round(Math.min(94, 45 + Math.abs(composite) * 60 + patterns.filter(p => p.type === (compositeSignal === "BULLISH" ? "bullish" : "bearish")).length * 5));
    const bbPosition = bb ? (cur - bb.lower) / (bb.upper - bb.lower) : null;
    const prediction = PredictionEngine.generate(closes);

    return { cur, rsi, macd, sma20, sma50, sma200, bb, bbPosition, atr, ch30, ch60, ch90, patterns, compositeSignal, composite, confidence, prediction, closes };
  },
};

// ─── SIGNAL ENGINE ─────────────────────────────────────────────────────────────
const SignalEngine = {
  analyze(quote, symbol, tech) {
    if (!quote || !quote.c || !quote.pc) return null;
    const chgPct = ((quote.c - quote.pc) / quote.pc) * 100;
    let signal = "HOLD", strength = 55, reason = "", buyAt = null, sellAt = null, holdDays = null;

    if (tech) {
      const { compositeSignal, confidence, rsi, macd, sma50, sma200, bb, patterns, ch30, ch90 } = tech;
      if (compositeSignal === "BULLISH") signal = "BUY";
      else if (compositeSignal === "BEARISH") signal = "SELL";
      else signal = chgPct <= -2.5 ? "BUY" : chgPct >= 3.5 ? "SELL" : "HOLD";

      strength = confidence;
      if (chgPct <= -2.5 && signal === "BUY")  strength = Math.min(94, strength + 10);
      if (chgPct >= 3.5  && signal === "SELL") strength = Math.min(94, strength + 10);

      // Compute buy/sell targets
      if (signal === "BUY" && sma50) {
        buyAt = quote.c;
        sellAt = bb ? bb.upper : (sma50 * 1.08);
        const dailyReturn = ch30 ? ch30 / 30 : 0.1;
        holdDays = dailyReturn > 0 ? Math.round(((sellAt - buyAt) / buyAt * 100) / dailyReturn) : 30;
        holdDays = Math.min(Math.max(holdDays, 3), 90);
      }
      if (signal === "SELL" && bb) {
        sellAt = quote.c;
        buyAt = bb.lower;
      }

      const bullets = [];
      if (rsi !== null) bullets.push(`RSI ${rsi.toFixed(0)} (${rsi < 30 ? "oversold" : rsi > 70 ? "overbought" : "neutral"})`);
      if (macd) bullets.push(`MACD ${macd.bullish ? "▲ bullish" : "▼ bearish"}`);
      if (sma50) bullets.push(`Price ${quote.c > sma50 ? "above" : "below"} 50-MA $${sma50.toFixed(2)}`);
      if (sma200) bullets.push(`${quote.c > sma200 ? "above" : "below"} 200-MA $${sma200.toFixed(2)}`);
      if (ch30 !== null) bullets.push(`30d: ${ch30 >= 0 ? "+" : ""}${ch30.toFixed(1)}%`);
      if (ch90 !== null) bullets.push(`90d: ${ch90 >= 0 ? "+" : ""}${ch90.toFixed(1)}%`);
      if (patterns[0]) bullets.push(`Pattern: ${patterns[0].name}`);
      reason = `${signal} ${strength}% · ${bullets.join(" · ")}`;
    } else {
      if (chgPct <= -2.5) { signal = "BUY";   strength = Math.min(90, Math.abs(chgPct) * 12); }
      else if (chgPct >= 3.5) { signal = "SELL"; strength = Math.min(90, chgPct * 10); }
      else if (Math.abs(chgPct) <= 1) { signal = "HOLD"; strength = 55; }
      else { signal = "WATCH"; strength = 45; }
      reason = `${symbol} ${chgPct >= 0 ? "+" : ""}${chgPct.toFixed(2)}% today`;
    }

    const risk = RiskEngine.compute(tech, quote);
    return { signal, strength: Math.round(strength), reason, changePercent: chgPct, quote, symbol, tech, risk, buyAt, sellAt, holdDays };
  },
};

// ─── RECOMMENDED AMOUNT ENGINE ────────────────────────────────────────────────
const calcRecommendedAmount = (signal, tech, quote, budget = 1000) => {
  if (!signal || !quote?.c) return null;
  const riskFactor = { Low: 0.25, Medium: 0.18, High: 0.12, "Very High": 0.07 };
  const risk = signal?.risk?.level || "Medium";
  const pct = riskFactor[risk] ?? 0.15;
  const conf = (tech?.confidence || 55) / 100;
  const adjPct = Math.min(pct * (1 + conf * 0.25), 0.25);
  const price = quote.c;
  const shares = Math.max(1, Math.floor((budget * adjPct) / price));
  const amount = Math.round(shares * price);
  const projectedProfit = signal.sellAt ? (signal.sellAt - price) * shares : null;
  const projectedPct = signal.sellAt ? ((signal.sellAt - price) / price * 100) : null;
  return { amount, shares, projectedProfit, projectedPct, budgetPct: Math.round(adjPct * 100) };
};

// ─── MARKET AGENT ──────────────────────────────────────────────────────────────
const MarketAgent = {
  cache: {}, data: null, signals: [],

  async fetchQuote(symbol) {
    const key = `q_${symbol}`, now = Date.now();
    if (this.cache[key] && now - this.cache[key].ts < 60_000) return this.cache[key].data;
    const finnhubKey = getFinnhubKey();
    if (!finnhubKey) return null;
    try {
      SecurityAgent.logEvent("API_CALL", `Quote: ${symbol}`);
      const res = await fetch(`https://finnhub.io/api/v1/quote?symbol=${symbol}&token=${finnhubKey}`);
      const data = await res.json();
      this.cache[key] = { data, ts: now }; return data;
    } catch { SecurityAgent.logEvent("ERROR", `Quote: ${symbol}`); return null; }
  },

  async fetchQuoteYahoo(symbol) {
    const key = `qy_${symbol}`, now = Date.now();
    if (this.cache[key] && now - this.cache[key].ts < 60_000) return this.cache[key].data;
    try {
      const candles = await HistoricalAgent.fetchCandles(symbol);
      if (!candles || candles.closes.length === 0) return null;
      const closes = candles.closes;
      const c = closes[closes.length - 1];
      const pc = closes[closes.length - 2] || c;
      const h = candles.highs[candles.highs.length - 1] || c;
      const l = candles.lows[candles.lows.length - 1] || c;
      const o = candles.opens?.[candles.opens.length - 1] || c;
      const data = { c, pc, h, l, o, t: Date.now() };
      this.cache[key] = { data, ts: now }; return data;
    } catch { return null; }
  },

  async fetchQuoteAny(symbol) {
    const finnhubKey = getFinnhubKey();
    if (finnhubKey) {
      const q = await this.fetchQuote(symbol);
      if (q?.c) return q;
    }
    return this.fetchQuoteYahoo(symbol);
  },

  async fetchCrypto(symbol) {
    const key = `c_${symbol}`, now = Date.now();
    if (this.cache[key] && now - this.cache[key].ts < 60_000) return this.cache[key].data;
    const finnhubKey = getFinnhubKey();
    if (!finnhubKey) return null;
    try {
      const res = await fetch(`https://finnhub.io/api/v1/quote?symbol=BINANCE:${symbol}USDT&token=${finnhubKey}`);
      const data = await res.json();
      this.cache[key] = { data, ts: now }; return data;
    } catch { return null; }
  },

  async fetchNews() {
    const now = Date.now();
    if (this.cache.news && now - this.cache.news.ts < 300_000) return this.cache.news.data;
    const finnhubKey = getFinnhubKey();
    if (!finnhubKey) return [];
    try {
      const res = await fetch(`https://finnhub.io/api/v1/news?category=general&token=${finnhubKey}`);
      const data = await res.json();
      const clean = Array.isArray(data) ? data.slice(0, 8) : [];
      this.cache.news = { data: clean, ts: now }; return clean;
    } catch { return []; }
  },

  async getQuotes() {
    const [spy, qqq, voo, btc, eth, news] = await Promise.all([
      this.fetchQuote("SPY"), this.fetchQuote("QQQ"), this.fetchQuote("VOO"),
      this.fetchCrypto("BTC"), this.fetchCrypto("ETH"), this.fetchNews(),
    ]);
    const signals = [
      SignalEngine.analyze(spy, "SPY", null),
      SignalEngine.analyze(qqq, "QQQ", null),
      SignalEngine.analyze(voo, "VOO", null),
    ].filter(Boolean);
    this.signals = signals;
    this.data = { spy, qqq, voo, btc, eth, news, technicals: {}, recommendations: {}, fetchedAt: new Date() };
    return { ...this.data, signals };
  },

  async enrichWithTechnicals(baseData) {
    const [spyC, qqqC, vooC, btcC, ethC, spyRec, qqqRec, vooRec] = await Promise.all([
      HistoricalAgent.fetchCandles("SPY"), HistoricalAgent.fetchCandles("QQQ"),
      HistoricalAgent.fetchCandles("VOO"), HistoricalAgent.fetchCandles("BTC"),
      HistoricalAgent.fetchCandles("ETH"),
      HistoricalAgent.fetchRecommendations("SPY"), HistoricalAgent.fetchRecommendations("QQQ"),
      HistoricalAgent.fetchRecommendations("VOO"),
    ]);
    const technicals = {
      SPY: HistoricalAgent.computeTechnicals(spyC),
      QQQ: HistoricalAgent.computeTechnicals(qqqC),
      VOO: HistoricalAgent.computeTechnicals(vooC),
      BTC: HistoricalAgent.computeTechnicals(btcC),
      ETH: HistoricalAgent.computeTechnicals(ethC),
    };
    const recommendations = { SPY: spyRec, QQQ: qqqRec, VOO: vooRec };
    const signals = [
      SignalEngine.analyze(baseData.spy, "SPY", technicals.SPY),
      SignalEngine.analyze(baseData.qqq, "QQQ", technicals.QQQ),
      SignalEngine.analyze(baseData.voo, "VOO", technicals.VOO),
    ].filter(Boolean);
    this.signals = signals;
    const enriched = { ...baseData, technicals, recommendations, signals };
    this.data = enriched;
    return enriched;
  },

  formatForAI(data) {
    if (!data) return "Market data loading.";
    const fmt = (q, label) => {
      if (!q || !q.c) return `${label}: N/A`;
      const chg = ((q.c - q.pc) / q.pc) * 100;
      return `${label}: $${q.c.toFixed(2)} (${chg >= 0 ? "+" : ""}${chg.toFixed(2)}% today)`;
    };
    const fmtC = (c, label) => {
      if (!c || !c.c) return `${label}: N/A`;
      const chg = c.pc ? ((c.c - c.pc) / c.pc) * 100 : 0;
      return `${label}: $${Number(c.c).toLocaleString()} (${chg >= 0 ? "+" : ""}${chg.toFixed(2)}%)`;
    };
    let techSection = "=== TECHNICAL ANALYSIS ===\n";
    for (const [sym, t] of Object.entries(data.technicals || {})) {
      if (!t) { techSection += `${sym}: data unavailable\n`; continue; }
      techSection += `\n${sym}: ${t.compositeSignal} (${t.confidence}% confidence)\n`;
      if (t.rsi !== null) techSection += `  RSI: ${t.rsi} | `;
      if (t.macd) techSection += `MACD: ${t.macd.bullish ? "bullish" : "bearish"} | `;
      if (t.ch30 !== null) techSection += `30d: ${t.ch30 >= 0 ? "+" : ""}${t.ch30.toFixed(1)}%\n`;
      if (t.patterns.length > 0) techSection += `  Patterns: ${t.patterns.map(p => p.name).join(", ")}\n`;
    }
    const signals = (data.signals || []).map(s => `${s.symbol}: ${s.signal} ${s.strength}% — ${s.reason}`).join("\n");
    const headlines = (data.news || []).slice(0, 5).map(n => `• ${n.headline}`).join("\n");
    return `=== LIVE PRICES (${data.fetchedAt?.toLocaleTimeString()}) ===
${fmt(data.spy, "SPY")}\n${fmt(data.qqq, "QQQ")}\n${fmt(data.voo, "VOO")}
${fmtC(data.btc, "Bitcoin")}\n${fmtC(data.eth, "Ethereum")}

=== ATLAS SIGNALS ===\n${signals || "Generating…"}

${techSection}
=== MARKET HEADLINES ===\n${headlines || "No headlines"}`;
  },
};

// ─── LEARNING AGENT ────────────────────────────────────────────────────────────
const LearningAgent = {
  sessions: (() => { try { return JSON.parse(localStorage.getItem("atlas_sessions") || "[]"); } catch { return []; } })(),
  alerts: (() => { try { return JSON.parse(localStorage.getItem("atlas_alerts") || "[]"); } catch { return []; } })(),
  signalHistory: (() => { try { return JSON.parse(localStorage.getItem("atlas_signals") || "[]"); } catch { return []; } })(),

  logSession(messages) {
    const topics = [], text = messages.map(m => m.content).join(" ").toLowerCase();
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
  logAlert(alert) { this.alerts.unshift({ ...alert, date: new Date().toISOString() }); if (this.alerts.length > 50) this.alerts.pop(); this.save(); },
  trackSignal(symbol, signal, price, confidence) {
    this.signalHistory.unshift({ symbol, signal, price, confidence, date: new Date().toISOString(), outcome: null });
    if (this.signalHistory.length > 200) this.signalHistory.pop();
    this.save();
  },
  evaluateSignals(currentPrices) {
    let updated = false;
    this.signalHistory.forEach(s => {
      if (s.outcome !== null) return;
      const ageHours = (Date.now() - new Date(s.date).getTime()) / 3_600_000;
      if (ageHours < 24) return;
      const curPrice = currentPrices[s.symbol];
      if (!curPrice) return;
      const changePct = ((curPrice - s.price) / s.price) * 100;
      const correct = (s.signal === "BUY" && changePct > 0.5) || (s.signal === "SELL" && changePct < -0.5) || (s.signal === "HOLD" && Math.abs(changePct) <= 1.5);
      s.outcome = correct ? "correct" : "incorrect";
      s.priceAfter = curPrice; s.changePct = changePct; updated = true;
    });
    if (updated) this.save();
  },
  getSignalAccuracy() {
    const evaluated = this.signalHistory.filter(s => s.outcome !== null);
    if (evaluated.length === 0) return null;
    const correct = evaluated.filter(s => s.outcome === "correct").length;
    return { correct, total: evaluated.length, accuracy: Math.round(correct / evaluated.length * 100) };
  },
  save() {
    try {
      localStorage.setItem("atlas_sessions", JSON.stringify(this.sessions.slice(-100)));
      localStorage.setItem("atlas_alerts", JSON.stringify(this.alerts.slice(-50)));
      localStorage.setItem("atlas_signals", JSON.stringify(this.signalHistory.slice(-200)));
    } catch {}
  },
};

// ─── NOTIFICATION SYSTEM ───────────────────────────────────────────────────────
const NotificationSystem = {
  permission: "default",
  async requestPermission() {
    if (!("Notification" in window)) return false;
    const r = await Notification.requestPermission();
    this.permission = r; return r === "granted";
  },
  send(title, body) {
    LearningAgent.logAlert({ title, body });
    if (this.permission === "granted") try { new Notification(`ATLAS: ${title}`, { body }); } catch {}
  },
};

// ─── SYSTEM PROMPT ─────────────────────────────────────────────────────────────
const buildPrompt = (marketContext, watchlistContext = "") => `You are ATLAS — an elite AI financial intelligence system. You have access to live prices, 180 days of historical OHLCV data, technical indicators (RSI, MACD, Bollinger Bands, SMA 20/50/200, ATR), pattern recognition (Golden Cross, Death Cross, etc.), and Wall Street analyst consensus.

CAPABILITIES:
• Analyze any stock or ETF in depth using technical + fundamental signals
• Predict market direction with confidence levels and risk assessment
• Generate personalized investment plans based on goals (e.g. "make $200 in 1 month")
• Track favorite stocks and send buy/sell/hold alerts with exact timing and dollar amounts
• Analyze news and market trends for their impact
• Run Monte Carlo simulations for price prediction

RESPONSE RULES:
1. Always cite exact live prices and indicator values
2. For every BUY recommendation: state buy price, target sell price, estimated hold time, and dollar amount to invest
3. For every SELL recommendation: state exit price and reason
4. For goal-based requests ("I want to make $X in Y days"): create a numbered step-by-step plan with specific stocks, entry prices, exit prices, and timing
5. Always show confidence % and risk level (Low/Medium/High/Very High)
6. Never recommend >25% of budget in any single position
7. Always end with: "Educational analysis only — not licensed financial advice."

${watchlistContext ? `USER'S WATCHLIST:\n${watchlistContext}\n` : ""}

LIVE MARKET DATA:
${marketContext}`;

// ─── DESIGN TOKENS ─────────────────────────────────────────────────────────────
const T = {
  bg: "#000", card: "rgba(28,28,30,0.82)", cardHigh: "rgba(44,44,46,0.9)",
  border: "rgba(255,255,255,0.08)", borderStrong: "rgba(255,255,255,0.13)",
  text: "#fff", textSub: "rgba(235,235,245,0.62)", textMuted: "rgba(235,235,245,0.3)",
  gold: "#D4A853", goldDim: "rgba(212,168,83,0.14)", goldBorder: "rgba(212,168,83,0.28)",
  green: "#30D158", greenDim: "rgba(48,209,88,0.12)", greenBorder: "rgba(48,209,88,0.35)",
  red: "#FF453A", redDim: "rgba(255,69,58,0.12)", redBorder: "rgba(255,69,58,0.35)",
  orange: "#FF9F0A", orangeDim: "rgba(255,159,10,0.12)", orangeBorder: "rgba(255,159,10,0.35)",
  indigo: "#6E7BF0", indigoDim: "rgba(110,123,240,0.12)", indigoBorder: "rgba(110,123,240,0.3)",
  sep: "rgba(255,255,255,0.06)",
  font: "-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Helvetica Neue', Arial, sans-serif",
  mono: "'SF Mono', 'Fira Code', 'Menlo', monospace",
  radius: { xs: 8, sm: 12, md: 16, lg: 20, pill: 100 },
  glass: "blur(40px) saturate(180%)",
};

const SIG_CFG = {
  BUY:   { bg: T.greenDim,  border: T.greenBorder,  color: T.green },
  SELL:  { bg: T.redDim,    border: T.redBorder,    color: T.red   },
  HOLD:  { bg: T.goldDim,   border: T.goldBorder,   color: T.gold  },
  WATCH: { bg: T.orangeDim, border: T.orangeBorder, color: T.orange },
  BULLISH: { bg: T.greenDim, border: T.greenBorder, color: T.green },
  BEARISH: { bg: T.redDim,  border: T.redBorder,   color: T.red   },
  NEUTRAL: { bg: T.goldDim, border: T.goldBorder,  color: T.gold  },
};

// ─── UI COMPONENTS ─────────────────────────────────────────────────────────────
function SignalPill({ signal, strength, small }) {
  const c = SIG_CFG[signal] || SIG_CFG.HOLD;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: small ? "2px 7px 2px 5px" : "3px 10px 3px 7px", borderRadius: T.radius.pill, background: c.bg, border: `0.5px solid ${c.border}`, flexShrink: 0 }}>
      <span style={{ width: small ? 4 : 5, height: small ? 4 : 5, borderRadius: "50%", background: c.color, boxShadow: `0 0 4px ${c.color}` }} />
      <span style={{ fontSize: small ? 9 : 11, fontWeight: 600, color: c.color }}>{signal}</span>
      {strength && !small && <span style={{ fontSize: 9, color: c.color, opacity: 0.65 }}>{strength}%</span>}
    </span>
  );
}

function RiskBadge({ risk }) {
  if (!risk) return null;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "2px 8px", borderRadius: T.radius.pill, background: `${risk.color}15`, border: `0.5px solid ${risk.color}40`, flexShrink: 0 }}>
      <span style={{ fontSize: 9, fontWeight: 700, color: risk.color, letterSpacing: "0.04em" }}>RISK</span>
      <span style={{ fontSize: 9, fontWeight: 600, color: risk.color }}>{risk.level}</span>
    </span>
  );
}

function ConfidenceBar({ value, color }) {
  const c = color || (value >= 70 ? T.green : value >= 50 ? T.gold : T.red);
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span style={{ fontSize: 10, color: T.textMuted }}>Confidence</span>
        <span style={{ fontSize: 10, fontWeight: 700, color: c }}>{value}%</span>
      </div>
      <div style={{ height: 3, background: "rgba(255,255,255,0.06)", borderRadius: 100 }}>
        <div style={{ width: `${value}%`, height: "100%", background: c, borderRadius: 100, transition: "width 0.6s ease", boxShadow: `0 0 6px ${c}60` }} />
      </div>
    </div>
  );
}

function RSIGauge({ value }) {
  if (value === null || value === undefined) return null;
  const pct = value / 100;
  const color = value < 30 ? T.green : value > 70 ? T.red : value < 45 ? T.orange : T.gold;
  const label = value < 30 ? "Oversold" : value > 70 ? "Overbought" : value < 45 ? "Weak" : value > 55 ? "Strong" : "Neutral";
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
        <span style={{ fontSize: 10, color: T.textMuted }}>RSI(14)</span>
        <span style={{ fontSize: 10, color, fontWeight: 700 }}>{value.toFixed(1)} · {label}</span>
      </div>
      <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 100, position: "relative", overflow: "hidden" }}>
        <div style={{ position: "absolute", left: 0, width: "30%", height: "100%", background: "rgba(48,209,88,0.2)" }} />
        <div style={{ position: "absolute", right: 0, width: "30%", height: "100%", background: "rgba(255,69,58,0.2)" }} />
        <div style={{ position: "absolute", left: 0, width: `${pct * 100}%`, height: "100%", background: color, borderRadius: 100, transition: "width 0.6s ease" }} />
      </div>
    </div>
  );
}

function TechRow({ label, value, color, mono }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: `0.5px solid ${T.sep}` }}>
      <span style={{ fontSize: 12, color: T.textSub }}>{label}</span>
      <span style={{ fontSize: 12, fontWeight: 500, color: color || T.text, fontVariantNumeric: mono ? "tabular-nums" : "normal" }}>{value}</span>
    </div>
  );
}

function PatternCard({ pattern }) {
  const c = pattern.type === "bullish" ? { bg: T.greenDim, border: T.greenBorder, color: T.green }
          : pattern.type === "bearish" ? { bg: T.redDim,   border: T.redBorder,   color: T.red  }
          : { bg: T.goldDim, border: T.goldBorder, color: T.gold };
  return (
    <div style={{ background: c.bg, border: `0.5px solid ${c.border}`, borderRadius: T.radius.sm, padding: "9px 12px", marginBottom: 6 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: c.color }}>{pattern.name}</span>
        <span style={{ fontSize: 9, color: c.color, opacity: 0.7 }}>{pattern.strength}%</span>
      </div>
      <div style={{ fontSize: 11, color: T.textSub, lineHeight: 1.5 }}>{pattern.desc}</div>
    </div>
  );
}

function AlertBanner({ alert, onDismiss }) {
  const isRed = alert.type === "sell", isGreen = alert.type === "buy";
  const bg = isRed ? T.redDim : isGreen ? T.greenDim : T.goldDim;
  const border = isRed ? T.redBorder : isGreen ? T.greenBorder : T.goldBorder;
  const accent = isRed ? T.red : isGreen ? T.green : T.gold;
  return (
    <div style={{ margin: "8px 16px 0", padding: "11px 14px", borderRadius: T.radius.md, background: bg, border: `0.5px solid ${border}`, display: "flex", alignItems: "flex-start", gap: 10 }}>
      <div style={{ width: 28, height: 28, borderRadius: T.radius.xs, background: `${accent}20`, border: `0.5px solid ${border}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, flexShrink: 0 }}>{isRed ? "↓" : isGreen ? "↑" : "◆"}</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: accent, marginBottom: 2 }}>{alert.title}</div>
        <div style={{ fontSize: 12, color: T.textSub, lineHeight: 1.45, overflow: "hidden", textOverflow: "ellipsis", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>{alert.body}</div>
      </div>
      <button onClick={onDismiss} style={{ background: "none", border: "none", color: T.textMuted, cursor: "pointer", fontSize: 16 }}>×</button>
    </div>
  );
}

// ─── PREDICTION CHART COMPONENT ────────────────────────────────────────────────
function PredictionChart({ prediction, symbol }) {
  if (!prediction) return <div style={{ padding: 16, textAlign: "center", fontSize: 12, color: T.textMuted }}>Loading prediction data…</div>;

  const isUp = prediction.baseReturn >= 0;
  const color = isUp ? T.green : T.red;
  const formatVal = v => `$${v >= 1 ? v.toFixed(2) : v.toFixed(4)}`;

  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
      <div style={{ background: T.cardHigh, border: `0.5px solid ${T.borderStrong}`, borderRadius: T.radius.sm, padding: "10px 12px", fontSize: 11 }}>
        <div style={{ color: T.textMuted, marginBottom: 4 }}>{label}</div>
        {payload.map((p, i) => (
          <div key={i} style={{ color: p.color, fontVariantNumeric: "tabular-nums" }}>{p.name}: {formatVal(p.value)}</div>
        ))}
      </div>
    );
  };

  return (
    <div style={{ padding: "12px 0 0" }}>
      <div style={{ display: "flex", gap: 10, marginBottom: 12, paddingLeft: 4 }}>
        <div style={{ flex: 1, background: isUp ? T.greenDim : T.redDim, border: `0.5px solid ${isUp ? T.greenBorder : T.redBorder}`, borderRadius: T.radius.sm, padding: "8px 12px" }}>
          <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 2 }}>BASE CASE (+30d)</div>
          <div style={{ fontSize: 15, fontWeight: 700, color, fontVariantNumeric: "tabular-nums" }}>{isUp ? "+" : ""}{prediction.baseReturn.toFixed(2)}%</div>
          <div style={{ fontSize: 10, color: T.textMuted }}>{formatVal(prediction.projectedPrice)}</div>
        </div>
        <div style={{ flex: 1, background: T.greenDim, border: `0.5px solid ${T.greenBorder}`, borderRadius: T.radius.sm, padding: "8px 12px" }}>
          <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 2 }}>OPTIMISTIC (+1.5σ)</div>
          <div style={{ fontSize: 15, fontWeight: 700, color: T.green, fontVariantNumeric: "tabular-nums" }}>+{prediction.optReturn.toFixed(2)}%</div>
        </div>
        <div style={{ flex: 1, background: T.redDim, border: `0.5px solid ${T.redBorder}`, borderRadius: T.radius.sm, padding: "8px 12px" }}>
          <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 2 }}>PESSIMISTIC (-1.5σ)</div>
          <div style={{ fontSize: 15, fontWeight: 700, color: T.red, fontVariantNumeric: "tabular-nums" }}>{prediction.pessReturn.toFixed(2)}%</div>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={160}>
        <AreaChart data={prediction.data} margin={{ top: 5, right: 4, left: 4, bottom: 0 }}>
          <defs>
            <linearGradient id={`grad_opt_${symbol}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={T.green} stopOpacity={0.25} />
              <stop offset="95%" stopColor={T.green} stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id={`grad_pess_${symbol}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={T.red} stopOpacity={0.15} />
              <stop offset="95%" stopColor={T.red} stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id={`grad_base_${symbol}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={color} stopOpacity={0.35} />
              <stop offset="95%" stopColor={color} stopOpacity={0.05} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
          <XAxis dataKey="day" tick={{ fill: T.textMuted, fontSize: 9 }} tickLine={false} axisLine={false} tickFormatter={v => v === 0 ? "Now" : v === 30 ? "30d" : v % 10 === 0 ? `${v}d` : ""} />
          <YAxis tick={{ fill: T.textMuted, fontSize: 9 }} tickLine={false} axisLine={false} tickFormatter={formatVal} width={50} domain={["auto", "auto"]} />
          <Tooltip content={<CustomTooltip />} />
          <ReferenceLine x={0} stroke="rgba(255,255,255,0.15)" strokeDasharray="3 3" />
          <Area type="monotone" dataKey="optimistic" stroke={T.green} strokeWidth={1} fill={`url(#grad_opt_${symbol})`} strokeDasharray="3 3" name="Optimistic" dot={false} />
          <Area type="monotone" dataKey="pessimistic" stroke={T.red} strokeWidth={1} fill={`url(#grad_pess_${symbol})`} strokeDasharray="3 3" name="Pessimistic" dot={false} />
          <Area type="monotone" dataKey="base" stroke={color} strokeWidth={2} fill={`url(#grad_base_${symbol})`} name="Base Case" dot={false} activeDot={{ r: 3, fill: color }} />
        </AreaChart>
      </ResponsiveContainer>
      <div style={{ textAlign: "center", fontSize: 10, color: T.textMuted, marginTop: 6 }}>Monte Carlo projection · Based on 180d historical volatility · Not a guarantee</div>
    </div>
  );
}

// ─── ENHANCED MARKET CARD ──────────────────────────────────────────────────────
function MarketCard({ label, quote, signal, tech, isCrypto, isFavorite, onToggleFav, onAsk }) {
  const [expanded, setExpanded] = useState(false);
  const [showChart, setShowChart] = useState(false);

  if (!quote || !quote.c) return (
    <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: 16, marginBottom: 10 }}>
      <div style={{ fontSize: 12, color: T.textMuted }}>{label}</div>
      <div style={{ fontSize: 12, color: T.textMuted, marginTop: 4 }}>{getFinnhubKey() ? "Loading…" : "Add VITE_FINNHUB_KEY to Secrets for live prices"}</div>
    </div>
  );

  const chg = quote.pc ? ((quote.c - quote.pc) / quote.pc) * 100 : 0;
  const up = chg >= 0;
  const risk = signal?.risk;
  const prediction = tech?.prediction;
  const sym = signal?.symbol || label.split(" ").pop().replace("—", "").trim();

  return (
    <div style={{ background: T.card, border: `0.5px solid ${signal?.signal === "BUY" ? T.greenBorder : signal?.signal === "SELL" ? T.redBorder : T.border}`, borderRadius: T.radius.md, marginBottom: 10, overflow: "hidden", boxShadow: "0 2px 12px rgba(0,0,0,0.3)" }}>
      <div style={{ padding: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 500, color: T.textMuted }}>{label}</span>
            {onToggleFav && (
              <button onClick={() => onToggleFav(sym)} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 14, color: isFavorite ? T.gold : "rgba(255,255,255,0.2)", transition: "all 0.2s", padding: "0 2px" }}>
                {isFavorite ? "★" : "☆"}
              </button>
            )}
          </div>
          <div style={{ display: "flex", gap: 5, alignItems: "center", flexWrap: "wrap", justifyContent: "flex-end" }}>
            {risk && <RiskBadge risk={risk} />}
            {tech && <SignalPill signal={tech.compositeSignal} strength={tech.confidence} small />}
            {signal && <SignalPill signal={signal.signal} strength={signal.strength} />}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "flex-end", gap: 10, marginBottom: 8 }}>
          <span style={{ fontSize: 28, fontWeight: 700, color: isCrypto ? T.gold : T.text, letterSpacing: "-0.02em", fontVariantNumeric: "tabular-nums" }}>
            ${Number(quote.c).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
          </span>
          <span style={{ fontSize: 13, fontWeight: 500, color: up ? T.green : T.red, marginBottom: 3 }}>{up ? "+" : ""}{chg.toFixed(2)}%</span>
        </div>
        {tech && <ConfidenceBar value={tech.confidence} color={tech.compositeSignal === "BULLISH" ? T.green : tech.compositeSignal === "BEARISH" ? T.red : T.gold} />}

        {/* BUY signal details */}
        {signal?.signal === "BUY" && signal.sellAt && (() => {
          const rec = calcRecommendedAmount(signal, tech, quote);
          return (
            <div style={{ marginTop: 10, background: T.greenDim, border: `0.5px solid ${T.greenBorder}`, borderRadius: T.radius.sm, padding: "10px 12px" }}>
              <div style={{ fontSize: 11, color: T.green, fontWeight: 600, marginBottom: 6 }}>▲ BUY SIGNAL</div>
              <div style={{ fontSize: 11, color: T.textSub, display: "flex", gap: 12, flexWrap: "wrap", marginBottom: rec ? 8 : 0 }}>
                <span>Entry: <b style={{ color: T.green }}>${signal.buyAt?.toFixed(2)}</b></span>
                <span>Target: <b style={{ color: T.gold }}>${signal.sellAt?.toFixed(2)}</b></span>
                {signal.holdDays && <span>Hold: <b style={{ color: T.textSub }}>{signal.holdDays}d</b></span>}
              </div>
              {rec && (
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "rgba(0,0,0,0.2)", borderRadius: T.radius.xs, padding: "7px 10px", marginTop: 4 }}>
                  <div>
                    <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 2, textTransform: "uppercase", letterSpacing: "0.06em" }}>Recommended amount</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: T.green }}>${rec.amount.toLocaleString()} <span style={{ fontSize: 10, color: T.textMuted, fontWeight: 400 }}>~{rec.shares} share{rec.shares !== 1 ? "s" : ""}</span></div>
                  </div>
                  {rec.projectedProfit && (
                    <div style={{ textAlign: "right" }}>
                      <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 2, textTransform: "uppercase", letterSpacing: "0.06em" }}>Est. profit</div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: T.green }}>+${rec.projectedProfit.toFixed(0)}</div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })()}
        {signal?.signal === "SELL" && signal.buyAt && (
          <div style={{ marginTop: 10, background: T.redDim, border: `0.5px solid ${T.redBorder}`, borderRadius: T.radius.sm, padding: "8px 12px" }}>
            <div style={{ fontSize: 11, color: T.red, fontWeight: 600, marginBottom: 4 }}>▼ SELL SIGNAL</div>
            <div style={{ fontSize: 11, color: T.textSub }}>
              Exit at: <b style={{ color: T.red }}>${signal.sellAt?.toFixed(2)}</b> · Re-enter near: <b style={{ color: T.gold }}>${signal.buyAt?.toFixed(2)}</b>
            </div>
          </div>
        )}

        <div style={{ display: "flex", gap: 6, marginTop: 12 }}>
          {onCardClick && (
            <button onClick={() => onCardClick({ symbol: sym, quote, signal, tech, isFavorite })} style={{ flex: 2, background: signal?.signal === "BUY" ? T.greenDim : signal?.signal === "SELL" ? T.redDim : "rgba(255,255,255,0.06)", border: `0.5px solid ${signal?.signal === "BUY" ? T.greenBorder : signal?.signal === "SELL" ? T.redBorder : T.border}`, borderRadius: T.radius.xs, padding: "7px 0", color: signal?.signal === "BUY" ? T.green : signal?.signal === "SELL" ? T.red : T.textMuted, fontSize: 11, fontWeight: 600, cursor: "pointer", fontFamily: T.font }}>
              View Full Details →
            </button>
          )}
          {prediction && (
            <button onClick={() => setShowChart(e => !e)} style={{ flex: 1, background: showChart ? T.indigoDim : "rgba(255,255,255,0.04)", border: `0.5px solid ${showChart ? T.indigoBorder : T.border}`, borderRadius: T.radius.xs, padding: "7px 0", color: showChart ? T.indigo : T.textMuted, fontSize: 11, cursor: "pointer", fontFamily: T.font }}>
              {showChart ? "Hide" : "📈"}
            </button>
          )}
          <button onClick={() => setExpanded(e => !e)} style={{ flex: 1, background: "rgba(255,255,255,0.04)", border: `0.5px solid ${T.border}`, borderRadius: T.radius.xs, padding: "7px 0", color: T.textMuted, fontSize: 11, cursor: "pointer", fontFamily: T.font }}>
            {expanded ? "▲" : "📊"}
          </button>
        </div>
      </div>

      {showChart && prediction && (
        <div style={{ padding: "0 16px 16px", borderTop: `0.5px solid ${T.sep}` }}>
          <PredictionChart prediction={prediction} symbol={sym} />
        </div>
      )}

      {expanded && tech && (
        <div style={{ padding: "12px 16px 16px", borderTop: `0.5px solid ${T.sep}` }}>
          <RSIGauge value={tech.rsi} />
          <div style={{ marginTop: 10 }}>
            {tech.macd && <TechRow label="MACD" value={`${tech.macd.bullish ? "▲ Bullish" : "▼ Bearish"} (${tech.macd.histogram.toFixed(3)})`} color={tech.macd.bullish ? T.green : T.red} />}
            {tech.sma20  && <TechRow label="SMA 20"  value={`$${tech.sma20.toFixed(2)} (${tech.cur > tech.sma20 ? "above ✓" : "below ✗"})`} color={tech.cur > tech.sma20 ? T.green : T.red} mono />}
            {tech.sma50  && <TechRow label="SMA 50"  value={`$${tech.sma50.toFixed(2)} (${tech.cur > tech.sma50 ? "above ✓" : "below ✗"})`} color={tech.cur > tech.sma50 ? T.green : T.red} mono />}
            {tech.sma200 && <TechRow label="SMA 200" value={`$${tech.sma200.toFixed(2)} (${tech.cur > tech.sma200 ? "bull ✓" : "bear ✗"})`} color={tech.cur > tech.sma200 ? T.green : T.red} mono />}
            {tech.bb && <TechRow label="BB Mid" value={`$${tech.bb.middle.toFixed(2)} ±${tech.bb.std.toFixed(2)}`} mono />}
            {tech.ch30 !== null && <TechRow label="30d return" value={`${tech.ch30 >= 0 ? "+" : ""}${tech.ch30.toFixed(2)}%`} color={tech.ch30 >= 0 ? T.green : T.red} />}
            {tech.ch90 !== null && <TechRow label="90d return" value={`${tech.ch90 >= 0 ? "+" : ""}${tech.ch90.toFixed(2)}%`} color={tech.ch90 >= 0 ? T.green : T.red} />}
            {risk && <TechRow label="Risk Level" value={`${risk.level} — ${risk.detail}`} color={risk.color} />}
          </div>
          {tech.patterns.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>Patterns</div>
              {tech.patterns.map((p, i) => <PatternCard key={i} pattern={p} />)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── ANALYST CARD ─────────────────────────────────────────────────────────────
function AnalystCard({ symbol, rec }) {
  if (!rec) return null;
  const bullW = `${rec.bullishPct}%`, bearW = `${rec.bearishPct}%`, holdW = `${100 - rec.bullishPct - rec.bearishPct}%`;
  return (
    <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: 14, marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, color: T.text }}>{symbol} — Wall St. Consensus</div>
          <div style={{ fontSize: 10, color: T.textMuted, marginTop: 2 }}>{rec.total} analysts · {rec.period}</div>
        </div>
        <SignalPill signal={rec.consensus} />
      </div>
      <div style={{ height: 6, borderRadius: 100, display: "flex", overflow: "hidden", marginBottom: 10 }}>
        <div style={{ width: bullW, background: T.green }} />
        <div style={{ width: holdW, background: T.gold }} />
        <div style={{ width: bearW, background: T.red }} />
      </div>
      <div style={{ display: "flex", gap: 10 }}>
        {[["Strong Buy", rec.strongBuy, T.green], ["Buy", rec.buy, "#60d394"], ["Hold", rec.hold, T.gold], ["Sell", rec.sell, "#ff8a7a"], ["Strong Sell", rec.strongSell, T.red]].map(([l, v, col]) => (
          <div key={l} style={{ textAlign: "center" }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: col }}>{v}</div>
            <div style={{ fontSize: 9, color: T.textMuted, marginTop: 2, whiteSpace: "pre" }}>{l.replace(" ", "\n")}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── STOCK DETAIL MODAL ────────────────────────────────────────────────────────
function StockDetailModal({ symbol, quote, signal, tech, isFavorite, onToggleFav, onAsk, onClose }) {
  const [showChart, setShowChart] = useState(false);
  if (!quote || !symbol) return null;

  const price = quote.c || 0;
  const chg = quote.pc ? ((price - quote.pc) / quote.pc * 100) : 0;
  const rec = signal ? calcRecommendedAmount(signal, tech, quote) : null;
  const decision = signal?.signal || "WATCH";
  const risk = signal?.risk;
  const prediction = tech?.prediction;

  const DC = {
    BUY:   { icon: "▲", label: "BUY",   bg: T.greenDim,  border: T.greenBorder,  color: T.green,  desc: "Strong buy signal — conditions are favorable" },
    SELL:  { icon: "▼", label: "SELL",  bg: T.redDim,    border: T.redBorder,    color: T.red,    desc: "Consider selling or reducing position" },
    HOLD:  { icon: "◆", label: "HOLD",  bg: T.goldDim,   border: T.goldBorder,   color: T.gold,   desc: "Hold current position — no clear entry yet" },
    WATCH: { icon: "◉", label: "WATCH", bg: T.orangeDim, border: T.orangeBorder, color: T.orange, desc: "Monitor closely — entry opportunity forming" },
  };
  const dc = DC[decision] || DC.HOLD;

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.82)", backdropFilter: "blur(18px)", WebkitBackdropFilter: "blur(18px)", zIndex: 200, display: "flex", flexDirection: "column", justifyContent: "flex-end" }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ background: "#0a0a0a", borderTop: `0.5px solid ${T.borderStrong}`, borderRadius: "24px 24px 0 0", padding: "20px 20px 48px", maxHeight: "92vh", overflowY: "auto" }}>

        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 18 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
              <span style={{ fontSize: 22, fontWeight: 800, color: T.text, letterSpacing: "-0.02em" }}>{symbol}</span>
              {onToggleFav && (
                <button onClick={() => onToggleFav(symbol)} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 18, color: isFavorite ? T.gold : "rgba(255,255,255,0.18)", transition: "all 0.2s" }}>
                  {isFavorite ? "★" : "☆"}
                </button>
              )}
            </div>
            <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
              <span style={{ fontSize: 34, fontWeight: 700, color: T.text, fontVariantNumeric: "tabular-nums", letterSpacing: "-0.02em" }}>
                ${price.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
              </span>
              <span style={{ fontSize: 14, color: chg >= 0 ? T.green : T.red, fontWeight: 600 }}>{chg >= 0 ? "+" : ""}{chg.toFixed(2)}%</span>
            </div>
          </div>
          <button onClick={onClose} style={{ background: "rgba(255,255,255,0.08)", border: "none", borderRadius: "50%", width: 32, height: 32, color: T.textMuted, fontSize: 18, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>✕</button>
        </div>

        {/* ATLAS Decision */}
        <div style={{ background: dc.bg, border: `1px solid ${dc.border}`, borderRadius: T.radius.lg, padding: "16px 18px", marginBottom: 14, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div style={{ fontSize: 9, color: dc.color, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 5 }}>ATLAS DECISION</div>
            <div style={{ fontSize: 30, fontWeight: 800, color: dc.color, letterSpacing: "-0.01em" }}>{dc.icon} {dc.label}</div>
            <div style={{ fontSize: 11, color: T.textSub, marginTop: 3 }}>{dc.desc}</div>
          </div>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 4 }}>CONFIDENCE</div>
            <div style={{ fontSize: 28, fontWeight: 800, color: dc.color }}>{signal?.strength || "—"}%</div>
          </div>
        </div>

        {/* Stats Grid */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 14 }}>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: "12px 14px" }}>
            <div style={{ fontSize: 9, color: T.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>RISK LEVEL</div>
            {risk ? (
              <>
                <div style={{ fontSize: 15, fontWeight: 700, color: risk.color }}>{risk.level}</div>
                <div style={{ fontSize: 10, color: T.textMuted, marginTop: 2, lineHeight: 1.4 }}>{risk.detail}</div>
              </>
            ) : <div style={{ fontSize: 12, color: T.textMuted }}>Calculating…</div>}
          </div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: "12px 14px" }}>
            <div style={{ fontSize: 9, color: T.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>HOLD TIME</div>
            {signal?.holdDays ? (
              <>
                <div style={{ fontSize: 15, fontWeight: 700, color: T.gold }}>{signal.holdDays} days</div>
                <div style={{ fontSize: 10, color: T.textMuted, marginTop: 2 }}>Est. hold period</div>
              </>
            ) : <div style={{ fontSize: 12, color: T.textMuted }}>N/A</div>}
          </div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: "12px 14px" }}>
            <div style={{ fontSize: 9, color: T.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>{decision === "BUY" ? "ENTRY → TARGET" : "EXIT → RE-ENTRY"}</div>
            {signal?.buyAt && signal?.sellAt ? (
              <div style={{ fontSize: 12, fontWeight: 600, fontVariantNumeric: "tabular-nums" }}>
                <span style={{ color: T.green }}>${signal.buyAt.toFixed(2)}</span>
                <span style={{ color: T.textMuted }}> → </span>
                <span style={{ color: T.gold }}>${signal.sellAt.toFixed(2)}</span>
              </div>
            ) : <div style={{ fontSize: 12, color: T.textMuted }}>No target set</div>}
          </div>
          <div style={{ background: decision === "BUY" ? T.greenDim : T.card, border: `0.5px solid ${decision === "BUY" ? T.greenBorder : T.border}`, borderRadius: T.radius.md, padding: "12px 14px" }}>
            <div style={{ fontSize: 9, color: T.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>RECOMMENDED</div>
            {rec ? (
              <>
                <div style={{ fontSize: 15, fontWeight: 700, color: decision === "BUY" ? T.green : T.textSub, fontVariantNumeric: "tabular-nums" }}>${rec.amount.toLocaleString()}</div>
                <div style={{ fontSize: 10, color: T.textMuted, marginTop: 2 }}>~{rec.shares} share{rec.shares !== 1 ? "s" : ""} · {rec.budgetPct}% of $1k</div>
              </>
            ) : <div style={{ fontSize: 12, color: T.textMuted }}>N/A</div>}
          </div>
        </div>

        {/* Projected Profit */}
        {rec?.projectedProfit && decision === "BUY" && (
          <div style={{ background: `linear-gradient(135deg, ${T.greenDim}, rgba(0,0,0,0))`, border: `0.5px solid ${T.greenBorder}`, borderRadius: T.radius.md, padding: "13px 16px", marginBottom: 14, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontSize: 9, color: T.green, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 2 }}>PROJECTED PROFIT</div>
              <div style={{ fontSize: 11, color: T.textSub }}>If target ${signal.sellAt?.toFixed(2)} is hit in ~{signal.holdDays}d</div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: 24, fontWeight: 800, color: T.green, fontVariantNumeric: "tabular-nums" }}>+${rec.projectedProfit.toFixed(2)}</div>
              <div style={{ fontSize: 11, color: T.green }}>+{rec.projectedPct?.toFixed(1)}%</div>
            </div>
          </div>
        )}

        {/* Confidence Bar */}
        {tech && <ConfidenceBar value={tech.confidence} color={dc.color} />}

        {/* Current Trends */}
        {tech && (
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: "14px", marginBottom: 12, marginTop: 14 }}>
            <div style={{ fontSize: 10, color: T.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 10 }}>Current Trends</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
              {tech.rsi !== null && (
                <div style={{ background: "rgba(255,255,255,0.04)", borderRadius: T.radius.xs, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 2 }}>RSI</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: tech.rsi < 30 ? T.green : tech.rsi > 70 ? T.red : T.gold }}>{tech.rsi.toFixed(0)} — {tech.rsi < 30 ? "↑ Oversold" : tech.rsi > 70 ? "↓ Overbought" : "Neutral"}</div>
                </div>
              )}
              {tech.macd && (
                <div style={{ background: "rgba(255,255,255,0.04)", borderRadius: T.radius.xs, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 2 }}>MACD</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: tech.macd.bullish ? T.green : T.red }}>{tech.macd.bullish ? "▲ Bullish" : "▼ Bearish"}</div>
                </div>
              )}
              {tech.ch30 !== null && (
                <div style={{ background: "rgba(255,255,255,0.04)", borderRadius: T.radius.xs, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 2 }}>30-Day</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: tech.ch30 >= 0 ? T.green : T.red }}>{tech.ch30 >= 0 ? "+" : ""}{tech.ch30.toFixed(1)}%</div>
                </div>
              )}
              {tech.ch90 !== null && (
                <div style={{ background: "rgba(255,255,255,0.04)", borderRadius: T.radius.xs, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 2 }}>90-Day</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: tech.ch90 >= 0 ? T.green : T.red }}>{tech.ch90 >= 0 ? "+" : ""}{tech.ch90.toFixed(1)}%</div>
                </div>
              )}
              {tech.sma50 && (
                <div style={{ background: "rgba(255,255,255,0.04)", borderRadius: T.radius.xs, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 2 }}>50-MA</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: tech.cur > tech.sma50 ? T.green : T.red }}>{tech.cur > tech.sma50 ? "Above ✓" : "Below ✗"} ${tech.sma50.toFixed(0)}</div>
                </div>
              )}
              {tech.sma200 && (
                <div style={{ background: "rgba(255,255,255,0.04)", borderRadius: T.radius.xs, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 2 }}>200-MA</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: tech.cur > tech.sma200 ? T.green : T.red }}>{tech.cur > tech.sma200 ? "Above ✓" : "Below ✗"} ${tech.sma200.toFixed(0)}</div>
                </div>
              )}
            </div>
            {tech.patterns.length > 0 && (
              <div style={{ marginTop: 10, paddingTop: 10, borderTop: `0.5px solid ${T.sep}` }}>
                <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.06em" }}>Patterns Detected</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {tech.patterns.map((p, i) => {
                    const c = p.type === "bullish" ? T.green : p.type === "bearish" ? T.red : T.gold;
                    return <span key={i} style={{ fontSize: 10, color: c, background: `${c}15`, border: `0.5px solid ${c}40`, borderRadius: T.radius.pill, padding: "2px 8px" }}>{p.name}</span>;
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* 30-Day Prediction */}
        {prediction && (
          <>
            <button onClick={() => setShowChart(e => !e)} style={{ width: "100%", padding: "9px", borderRadius: T.radius.sm, border: `0.5px solid ${showChart ? T.indigoBorder : T.border}`, background: showChart ? T.indigoDim : "rgba(255,255,255,0.04)", color: showChart ? T.indigo : T.textMuted, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: T.font, marginBottom: showChart ? 12 : 14 }}>
              {showChart ? "▲ Hide Chart" : "📈 30-Day Monte Carlo Prediction"}
            </button>
            {showChart && <div style={{ marginBottom: 14 }}><PredictionChart prediction={prediction} symbol={symbol} /></div>}
          </>
        )}

        <button onClick={() => { onAsk(`Deep analysis of ${symbol} at $${price.toFixed(2)} (${chg >= 0 ? "+" : ""}${chg.toFixed(2)}% today). Is it a BUY or PASS right now? Give me: exact entry price, sell target, stop-loss, risk level, confidence %, how much to invest, hold time, and projected profit.`); onClose(); }}
          style={{ width: "100%", padding: "14px", borderRadius: T.radius.md, border: "none", background: `linear-gradient(145deg, ${T.gold}, #8b5e12)`, color: "#000", fontSize: 14, fontWeight: 700, cursor: "pointer", fontFamily: T.font }}>
          Ask ATLAS for Full Analysis
        </button>
      </div>
    </div>
  );
}

// ─── WATCHLIST TAB ─────────────────────────────────────────────────────────────
function WatchlistTab({ favorites, onToggleFav, onAsk, onCardClick, marketData }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [searching, setSearching] = useState(false);
  const [watchlistData, setWatchlistData] = useState({});
  const searchTimer = useRef(null);

  const doSearch = useCallback(async (q) => {
    if (!q.trim()) { setResults([]); return; }
    setSearching(true);
    const r = await HistoricalAgent.searchSymbols(q.trim());
    setResults(r);
    setSearching(false);
  }, []);

  useEffect(() => {
    clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => doSearch(query), 400);
    return () => clearTimeout(searchTimer.current);
  }, [query, doSearch]);

  // Load data for favorite symbols
  useEffect(() => {
    if (favorites.length === 0) return;
    const load = async () => {
      const updates = {};
      await Promise.all(favorites.map(async sym => {
        try {
          const [quote, candles] = await Promise.all([
            MarketAgent.fetchQuoteAny(sym),
            HistoricalAgent.fetchCandles(sym),
          ]);
          const tech = HistoricalAgent.computeTechnicals(candles);
          const signal = SignalEngine.analyze(quote, sym, tech);
          updates[sym] = { quote, tech, signal };
        } catch {}
      }));
      setWatchlistData(prev => ({ ...prev, ...updates }));
    };
    load();
  }, [favorites]);

  const [portfolio, setPortfolio] = useState(() => { try { return JSON.parse(localStorage.getItem("atlas_portfolio") || "[]"); } catch { return []; } });
  const [portfolioData, setPortfolioData] = useState({});

  // Load live data for portfolio positions
  useEffect(() => {
    if (portfolio.length === 0) return;
    const syms = [...new Set(portfolio.map(p => p.symbol))];
    Promise.all(syms.map(async sym => {
      try {
        const [quote, candles] = await Promise.all([MarketAgent.fetchQuoteAny(sym), HistoricalAgent.fetchCandles(sym)]);
        const tech = HistoricalAgent.computeTechnicals(candles);
        const signal = SignalEngine.analyze(quote, sym, tech);
        return [sym, { quote, tech, signal }];
      } catch { return [sym, null]; }
    })).then(entries => {
      const map = {};
      entries.forEach(([sym, d]) => { if (d) map[sym] = d; });
      setPortfolioData(map);
    });
  }, [portfolio]);

  const totalCost = portfolio.reduce((s, p) => s + p.shares * p.avgPrice, 0);
  const totalCurrent = portfolio.reduce((s, p) => {
    const price = portfolioData[p.symbol]?.quote?.c;
    return price ? s + p.shares * price : s;
  }, 0);
  const totalPnl = totalCurrent > 0 ? totalCurrent - totalCost : null;
  const totalPnlPct = totalPnl !== null && totalCost > 0 ? (totalPnl / totalCost) * 100 : null;

  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "16px 16px 32px" }}>

      {/* ── MY PORTFOLIO ── */}
      {portfolio.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em" }}>My Portfolio</div>
            {totalPnl !== null && (
              <div style={{ fontSize: 12, fontWeight: 600, color: totalPnl >= 0 ? T.green : T.red }}>
                {totalPnl >= 0 ? "+" : ""}${totalPnl.toFixed(2)} ({totalPnlPct >= 0 ? "+" : ""}{totalPnlPct?.toFixed(2)}%)
              </div>
            )}
          </div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, overflow: "hidden", marginBottom: 10 }}>
            {portfolio.map((pos, i) => {
              const d = portfolioData[pos.symbol] || {};
              const curPrice = d.quote?.c;
              const pnl = curPrice ? (curPrice - pos.avgPrice) * pos.shares : null;
              const pnlPct = pnl !== null ? (pnl / (pos.avgPrice * pos.shares)) * 100 : null;
              const sig = d.signal;
              return (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 14px", borderBottom: i < portfolio.length - 1 ? `0.5px solid ${T.sep}` : "none", cursor: onCardClick ? "pointer" : "default" }}
                  onClick={() => onCardClick && d.quote && onCardClick({ symbol: pos.symbol, quote: d.quote, signal: sig, tech: d.tech, isFavorite: favorites.includes(pos.symbol) })}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 2 }}>
                      <span style={{ fontSize: 14, fontWeight: 700, color: T.text }}>{pos.symbol}</span>
                      {sig && <SignalPill signal={sig.signal} strength={sig.strength} small />}
                    </div>
                    <div style={{ fontSize: 11, color: T.textMuted }}>{pos.shares} shares · avg ${pos.avgPrice.toFixed(2)}</div>
                  </div>
                  <div style={{ textAlign: "right" }}>
                    {curPrice ? (
                      <>
                        <div style={{ fontSize: 13, fontWeight: 600, color: T.text, fontVariantNumeric: "tabular-nums" }}>${(curPrice * pos.shares).toFixed(2)}</div>
                        <div style={{ fontSize: 11, color: pnl >= 0 ? T.green : T.red, fontVariantNumeric: "tabular-nums" }}>{pnl >= 0 ? "+" : ""}${pnl?.toFixed(2)} ({pnlPct >= 0 ? "+" : ""}{pnlPct?.toFixed(1)}%)</div>
                      </>
                    ) : <div style={{ fontSize: 12, color: T.textMuted }}>…</div>}
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={() => onAsk(`Analyze my portfolio performance and give me specific buy/sell/hold recommendations for each position: ${portfolio.map(p => `${p.symbol} (${p.shares} shares at $${p.avgPrice})`).join(", ")}`)}
              style={{ flex: 1, background: T.goldDim, border: `0.5px solid ${T.goldBorder}`, borderRadius: T.radius.xs, padding: "8px", color: T.gold, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: T.font }}>Ask ATLAS to Review Portfolio</button>
          </div>
        </div>
      )}

      {/* ── SEARCH ── */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Search Any Stock</div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", background: T.card, border: `0.5px solid ${T.borderStrong}`, borderRadius: T.radius.md, padding: "10px 14px" }}>
          <span style={{ fontSize: 14, color: T.textMuted }}>🔍</span>
          <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search by ticker or name (e.g. AAPL, Tesla)" style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: T.text, fontSize: 14, fontFamily: T.font }} />
          {searching && <span style={{ fontSize: 10, color: T.textMuted, animation: "pulse 1s ease infinite" }}>…</span>}
          {query && <button onClick={() => { setQuery(""); setResults([]); }} style={{ background: "none", border: "none", color: T.textMuted, cursor: "pointer", fontSize: 16 }}>×</button>}
        </div>
        {results.length > 0 && (
          <div style={{ background: T.cardHigh, border: `0.5px solid ${T.borderStrong}`, borderRadius: T.radius.md, marginTop: 4, overflow: "hidden" }}>
            {results.map((r, i) => {
              const isFav = favorites.includes(r.symbol);
              return (
                <div key={r.symbol} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "11px 14px", borderBottom: i < results.length - 1 ? `0.5px solid ${T.sep}` : "none" }}>
                  <div>
                    <span style={{ fontSize: 13, fontWeight: 600, color: T.text, marginRight: 8 }}>{r.symbol}</span>
                    <span style={{ fontSize: 12, color: T.textSub }}>{r.name}</span>
                  </div>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button onClick={() => onAsk(`Analyze ${r.symbol} — buy/sell/hold signal, confidence, risk, entry price, target, and recommended investment amount`)}
                      style={{ background: T.goldDim, border: `0.5px solid ${T.goldBorder}`, borderRadius: T.radius.xs, padding: "4px 10px", color: T.gold, fontSize: 11, cursor: "pointer", fontFamily: T.font }}>Ask ATLAS</button>
                    <button onClick={() => onToggleFav(r.symbol)}
                      style={{ background: isFav ? T.goldDim : "rgba(255,255,255,0.05)", border: `0.5px solid ${isFav ? T.goldBorder : T.border}`, borderRadius: T.radius.xs, padding: "4px 10px", color: isFav ? T.gold : T.textMuted, fontSize: 12, cursor: "pointer", fontFamily: T.font }}>
                      {isFav ? "★ Saved" : "☆ Watch"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── WATCHLIST ── */}
      {favorites.length > 0 ? (
        <>
          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Watchlist ({favorites.length})</div>
          {favorites.map(sym => {
            const d = watchlistData[sym] || {};
            const mSig = marketData?.signals?.find(s => s.symbol === sym);
            const mTech = marketData?.technicals?.[sym];
            const mQuote = sym === "SPY" ? marketData?.spy : sym === "QQQ" ? marketData?.qqq : sym === "VOO" ? marketData?.voo : null;
            const quote = d.quote || mQuote;
            const tech  = d.tech  || mTech;
            const signal = d.signal || mSig;
            return (
              <MarketCard key={sym} label={sym} quote={quote} signal={signal} tech={tech}
                isFavorite onToggleFav={onToggleFav} onAsk={onAsk}
                onCardClick={onCardClick}
              />
            );
          })}
        </>
      ) : (
        <div style={{ textAlign: "center", padding: "40px 20px", color: T.textMuted }}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>☆</div>
          <div style={{ fontSize: 14, color: T.textSub, marginBottom: 6 }}>Your watchlist is empty</div>
          <div style={{ fontSize: 12 }}>Search for stocks above and tap "Watch" to add them here.</div>
        </div>
      )}

      {favorites.length === 0 && (
        <div style={{ marginTop: 8 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Popular Stocks</div>
          {["SPY", "QQQ", "AAPL", "TSLA", "NVDA", "MSFT"].map(sym => (
            <div key={sym} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "11px 14px", background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, marginBottom: 6 }}>
              <span style={{ fontSize: 14, fontWeight: 600, color: T.text }}>{sym}</span>
              <div style={{ display: "flex", gap: 6 }}>
                <button onClick={() => onAsk(`Analyze ${sym} — buy/sell/hold signal, confidence, risk, entry/target prices, hold time, and how much to invest`)}
                  style={{ background: T.goldDim, border: `0.5px solid ${T.goldBorder}`, borderRadius: T.radius.xs, padding: "4px 10px", color: T.gold, fontSize: 11, cursor: "pointer", fontFamily: T.font }}>Ask ATLAS</button>
                <button onClick={() => onToggleFav(sym)}
                  style={{ background: "rgba(255,255,255,0.05)", border: `0.5px solid ${T.border}`, borderRadius: T.radius.xs, padding: "4px 10px", color: T.textMuted, fontSize: 12, cursor: "pointer", fontFamily: T.font }}>☆ Watch</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── GOAL PLANNER ──────────────────────────────────────────────────────────────
function GoalPlanner({ onAsk }) {
  const [goal, setGoal] = useState("");
  const [timeframe, setTimeframe] = useState("1 month");
  const [investment, setInvestment] = useState("");

  const buildGoalPrompt = () => {
    const inv = investment ? `I have $${investment} to invest.` : "";
    return `GOAL-BASED INVESTMENT PLAN REQUEST:\nI want to make $${goal} profit in ${timeframe}. ${inv}\n\nPlease create a detailed step-by-step investment plan:\n1. Which specific stock(s) to buy first and why\n2. Exact entry price to buy at\n3. How much to invest (specific dollar amounts)\n4. When to sell (exact price target or trigger)\n5. After selling, where to reinvest the profit+capital\n6. Continue the cycle until I reach the $${goal} target\n7. Confidence level for each step\n8. Risk level for this plan\n9. What to do if a position goes against me\n\nBase this on current market conditions, technical signals, and historical performance.`;
  };

  return (
    <div style={{ background: `linear-gradient(145deg, rgba(212,168,83,0.1), rgba(212,168,83,0.03))`, border: `0.5px solid ${T.goldBorder}`, borderRadius: T.radius.lg, padding: 20, marginBottom: 20 }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: T.gold, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 12 }}>Goal-Based Planning</div>
      <div style={{ fontSize: 14, color: T.textSub, marginBottom: 16, lineHeight: 1.5 }}>Tell ATLAS your profit goal and timeframe — it will build you a step-by-step plan to get there.</div>

      <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>PROFIT TARGET ($)</div>
          <input value={goal} onChange={e => setGoal(e.target.value.replace(/[^0-9.]/g, ""))} placeholder="e.g. 200" style={{ width: "100%", background: "rgba(0,0,0,0.3)", border: `0.5px solid ${T.goldBorder}`, borderRadius: T.radius.sm, padding: "10px 12px", color: T.text, fontSize: 14, fontFamily: T.font, outline: "none", boxSizing: "border-box" }} />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>TIMEFRAME</div>
          <select value={timeframe} onChange={e => setTimeframe(e.target.value)} style={{ width: "100%", background: "rgba(0,0,0,0.5)", border: `0.5px solid ${T.goldBorder}`, borderRadius: T.radius.sm, padding: "10px 12px", color: T.text, fontSize: 14, fontFamily: T.font, outline: "none", appearance: "none", WebkitAppearance: "none" }}>
            {["1 week", "2 weeks", "1 month", "2 months", "3 months", "6 months"].map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
      </div>

      <div style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>INVESTMENT AMOUNT ($) — optional</div>
        <input value={investment} onChange={e => setInvestment(e.target.value.replace(/[^0-9.]/g, ""))} placeholder="How much you can invest" style={{ width: "100%", background: "rgba(0,0,0,0.3)", border: `0.5px solid ${T.goldBorder}`, borderRadius: T.radius.sm, padding: "10px 12px", color: T.text, fontSize: 14, fontFamily: T.font, outline: "none", boxSizing: "border-box" }} />
      </div>

      <button onClick={() => { if (goal) onAsk(buildGoalPrompt()); }} disabled={!goal} style={{ width: "100%", padding: "13px 0", borderRadius: T.radius.md, border: "none", background: goal ? `linear-gradient(145deg, ${T.gold}, #8b5e12)` : "rgba(255,255,255,0.06)", color: goal ? "#000" : T.textMuted, fontSize: 14, fontWeight: 700, cursor: goal ? "pointer" : "not-allowed", fontFamily: T.font, boxShadow: goal ? "0 2px 16px rgba(212,168,83,0.3)" : "none", transition: "all 0.2s" }}>
        Generate My Plan →
      </button>
    </div>
  );
}

// ─── PRICE ALERTS PANEL ───────────────────────────────────────────────────────
function PriceAlertsPanel({ onClose }) {
  const [alerts, setAlerts] = useState(() => PriceAlertManager.getAll());
  const [form, setForm] = useState({ symbol: "", targetPrice: "", direction: "above" });
  const [err, setErr] = useState("");

  const refresh = () => setAlerts(PriceAlertManager.getAll());

  const add = () => {
    setErr("");
    if (!form.symbol.trim()) return setErr("Enter a ticker symbol");
    if (!form.targetPrice || isNaN(+form.targetPrice) || +form.targetPrice <= 0) return setErr("Enter a valid price");
    PriceAlertManager.add(form.symbol, form.targetPrice, form.direction);
    setForm({ symbol: "", targetPrice: "", direction: "above" });
    refresh();
  };

  const remove = (id) => { PriceAlertManager.remove(id); refresh(); };

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", zIndex: 100, display: "flex", flexDirection: "column", justifyContent: "flex-end" }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ background: "#1C1C1E", borderTop: `0.5px solid ${T.borderStrong}`, borderRadius: "20px 20px 0 0", padding: "20px 20px 40px", maxHeight: "80vh", overflowY: "auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: T.text }}>Price Alerts</div>
            <div style={{ fontSize: 11, color: T.textMuted, marginTop: 2 }}>Get notified when a stock hits your target</div>
          </div>
          <button onClick={onClose} style={{ background: "rgba(255,255,255,0.08)", border: "none", borderRadius: "50%", width: 30, height: 30, color: T.textMuted, fontSize: 16, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>✕</button>
        </div>

        {/* Add Alert Form */}
        <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: 14, marginBottom: 16 }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>TICKER</div>
              <input value={form.symbol} onChange={e => setForm(f => ({ ...f, symbol: e.target.value }))} placeholder="AAPL" style={{ width: "100%", background: "rgba(0,0,0,0.3)", border: `0.5px solid ${T.borderStrong}`, borderRadius: T.radius.sm, padding: "8px 10px", color: T.text, fontSize: 14, outline: "none", boxSizing: "border-box" }} />
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>TARGET PRICE ($)</div>
              <input value={form.targetPrice} onChange={e => setForm(f => ({ ...f, targetPrice: e.target.value }))} placeholder="195.00" type="number" style={{ width: "100%", background: "rgba(0,0,0,0.3)", border: `0.5px solid ${T.borderStrong}`, borderRadius: T.radius.sm, padding: "8px 10px", color: T.text, fontSize: 14, outline: "none", boxSizing: "border-box" }} />
            </div>
          </div>
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>DIRECTION</div>
            <div style={{ display: "flex", gap: 6 }}>
              {["above", "below"].map(d => (
                <button key={d} onClick={() => setForm(f => ({ ...f, direction: d }))} style={{ flex: 1, padding: "7px 0", borderRadius: T.radius.sm, border: `0.5px solid ${form.direction === d ? T.goldBorder : T.border}`, background: form.direction === d ? T.goldDim : "transparent", color: form.direction === d ? T.gold : T.textMuted, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: T.font, textTransform: "capitalize" }}>
                  {d === "above" ? "📈 Goes Above" : "📉 Drops Below"}
                </button>
              ))}
            </div>
          </div>
          {err && <div style={{ fontSize: 11, color: T.red, marginBottom: 8 }}>{err}</div>}
          <button onClick={add} style={{ width: "100%", padding: "10px 0", borderRadius: T.radius.sm, border: "none", background: `linear-gradient(145deg, ${T.gold}, #8b5e12)`, color: "#000", fontSize: 13, fontWeight: 700, cursor: "pointer", fontFamily: T.font }}>
            Set Alert
          </button>
        </div>

        {/* Existing Alerts */}
        {alerts.length === 0 ? (
          <div style={{ textAlign: "center", padding: "20px", color: T.textMuted, fontSize: 13 }}>No alerts set yet</div>
        ) : (
          alerts.map(a => (
            <div key={a.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 14px", background: a.triggered ? "rgba(48,209,88,0.06)" : T.card, border: `0.5px solid ${a.triggered ? T.greenBorder : T.border}`, borderRadius: T.radius.sm, marginBottom: 8 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 14, fontWeight: 700, color: T.text }}>{a.symbol}</span>
                  <span style={{ fontSize: 10, color: T.textMuted, background: "rgba(255,255,255,0.06)", padding: "2px 7px", borderRadius: T.radius.pill }}>{a.direction === "above" ? "↑ above" : "↓ below"} ${a.targetPrice}</span>
                  {a.triggered && <span style={{ fontSize: 10, color: T.green, fontWeight: 600 }}>✓ FIRED</span>}
                </div>
                <div style={{ fontSize: 10, color: T.textMuted, marginTop: 2 }}>Set {new Date(a.createdAt).toLocaleDateString()}{a.triggeredAt ? ` · Triggered ${new Date(a.triggeredAt).toLocaleTimeString()}` : ""}</div>
              </div>
              <button onClick={() => remove(a.id)} style={{ background: T.redDim, border: `0.5px solid ${T.redBorder}`, borderRadius: T.radius.xs, padding: "4px 10px", color: T.red, fontSize: 11, cursor: "pointer", fontFamily: T.font }}>Remove</button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// ─── PORTFOLIO TAB ────────────────────────────────────────────────────────────
function PortfolioTab({ onAsk }) {
  const [positions, setPositions] = useState(() => {
    try { return JSON.parse(localStorage.getItem("atlas_portfolio") || "[]"); } catch { return []; }
  });
  const [liveData, setLiveData] = useState({});
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ symbol: "", shares: "", buyPrice: "", buyDate: new Date().toISOString().slice(0, 10) });
  const [formErr, setFormErr] = useState("");

  const save = (next) => {
    setPositions(next);
    localStorage.setItem("atlas_portfolio", JSON.stringify(next));
  };

  const addPosition = () => {
    setFormErr("");
    if (!form.symbol.trim()) return setFormErr("Symbol is required");
    if (!form.shares || isNaN(+form.shares) || +form.shares <= 0) return setFormErr("Enter valid share count");
    if (!form.buyPrice || isNaN(+form.buyPrice) || +form.buyPrice <= 0) return setFormErr("Enter valid buy price");
    const pos = { id: Date.now(), symbol: form.symbol.trim().toUpperCase(), shares: +form.shares, buyPrice: +form.buyPrice, buyDate: form.buyDate };
    save([...positions, pos]);
    setForm({ symbol: "", shares: "", buyPrice: "", buyDate: new Date().toISOString().slice(0, 10) });
    setShowAdd(false);
  };

  const removePosition = (id) => save(positions.filter(p => p.id !== id));

  // Load live prices for all positions
  useEffect(() => {
    if (positions.length === 0) return;
    const load = async () => {
      const updates = {};
      await Promise.all(positions.map(async pos => {
        try {
          const [quote, candles] = await Promise.all([
            MarketAgent.fetchQuoteAny(pos.symbol),
            HistoricalAgent.fetchCandles(pos.symbol),
          ]);
          const tech = HistoricalAgent.computeTechnicals(candles);
          const signal = SignalEngine.analyze(quote, pos.symbol, tech);
          updates[pos.id] = { quote, tech, signal };
        } catch {}
      }));
      setLiveData(prev => ({ ...prev, ...updates }));
    };
    load();
  }, [positions.length]);

  // Totals
  const totalInvested = positions.reduce((s, p) => s + p.shares * p.buyPrice, 0);
  const totalCurrent  = positions.reduce((s, p) => {
    const cur = liveData[p.id]?.quote?.c;
    return s + (cur ? p.shares * cur : p.shares * p.buyPrice);
  }, 0);
  const totalPnL = totalCurrent - totalInvested;
  const totalPnLPct = totalInvested > 0 ? (totalPnL / totalInvested) * 100 : 0;

  const buildAskPrompt = () => {
    if (positions.length === 0) return "";
    const lines = positions.map(p => {
      const d = liveData[p.id];
      const cur = d?.quote?.c;
      const pnl = cur ? ((cur - p.buyPrice) / p.buyPrice * 100).toFixed(2) : "loading";
      const sig = d?.signal?.signal || "loading";
      return `${p.symbol}: bought ${p.shares} shares @ $${p.buyPrice} on ${p.buyDate} | current: ${cur ? "$" + cur.toFixed(2) : "loading"} | P&L: ${pnl}% | signal: ${sig}`;
    }).join("\n");
    return `Review my portfolio and give me specific recommendations for each position:\n\n${lines}\n\nFor each position tell me: should I hold, add, or sell? When exactly should I sell (price target or trigger)? What is the risk right now? Is there a better stock I should rotate into?`;
  };

  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "16px 16px 32px" }}>
      {/* Summary */}
      {positions.length > 0 && (
        <div style={{ background: `linear-gradient(145deg, ${totalPnL >= 0 ? "rgba(48,209,88,0.1)" : "rgba(255,69,58,0.1)"}, rgba(0,0,0,0))`, border: `0.5px solid ${totalPnL >= 0 ? T.greenBorder : T.redBorder}`, borderRadius: T.radius.lg, padding: 18, marginBottom: 16 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em" }}>Portfolio Summary</div>
            <button onClick={() => onAsk(buildAskPrompt())} style={{ background: T.goldDim, border: `0.5px solid ${T.goldBorder}`, borderRadius: T.radius.xs, padding: "5px 12px", color: T.gold, fontSize: 11, fontWeight: 600, cursor: "pointer", fontFamily: T.font }}>Ask ATLAS to review all</button>
          </div>
          <div style={{ display: "flex", gap: 12 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>TOTAL INVESTED</div>
              <div style={{ fontSize: 20, fontWeight: 700, color: T.text, fontVariantNumeric: "tabular-nums" }}>${totalInvested.toFixed(2)}</div>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>CURRENT VALUE</div>
              <div style={{ fontSize: 20, fontWeight: 700, color: T.text, fontVariantNumeric: "tabular-nums" }}>${totalCurrent.toFixed(2)}</div>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>TOTAL P&L</div>
              <div style={{ fontSize: 20, fontWeight: 700, color: totalPnL >= 0 ? T.green : T.red, fontVariantNumeric: "tabular-nums" }}>
                {totalPnL >= 0 ? "+" : ""}${totalPnL.toFixed(2)}
              </div>
              <div style={{ fontSize: 11, color: totalPnL >= 0 ? T.green : T.red, fontVariantNumeric: "tabular-nums" }}>{totalPnLPct >= 0 ? "+" : ""}{totalPnLPct.toFixed(2)}%</div>
            </div>
          </div>
        </div>
      )}

      {/* Add Button */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em" }}>Positions ({positions.length})</div>
        <button onClick={() => setShowAdd(s => !s)} style={{ background: showAdd ? "rgba(255,255,255,0.07)" : T.goldDim, border: `0.5px solid ${showAdd ? T.border : T.goldBorder}`, borderRadius: T.radius.xs, padding: "6px 14px", color: showAdd ? T.textMuted : T.gold, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: T.font }}>
          {showAdd ? "✕ Cancel" : "+ Add Position"}
        </button>
      </div>

      {/* Add Form */}
      {showAdd && (
        <div style={{ background: T.cardHigh, border: `0.5px solid ${T.borderStrong}`, borderRadius: T.radius.md, padding: 16, marginBottom: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: T.gold, marginBottom: 12 }}>New Position</div>
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>TICKER</div>
              <input value={form.symbol} onChange={e => setForm(f => ({ ...f, symbol: e.target.value }))} placeholder="e.g. AAPL" style={{ width: "100%", background: "rgba(0,0,0,0.3)", border: `0.5px solid ${T.borderStrong}`, borderRadius: T.radius.sm, padding: "9px 12px", color: T.text, fontSize: 14, outline: "none", boxSizing: "border-box" }} />
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>SHARES</div>
              <input value={form.shares} onChange={e => setForm(f => ({ ...f, shares: e.target.value }))} placeholder="e.g. 10" type="number" min="0" style={{ width: "100%", background: "rgba(0,0,0,0.3)", border: `0.5px solid ${T.borderStrong}`, borderRadius: T.radius.sm, padding: "9px 12px", color: T.text, fontSize: 14, outline: "none", boxSizing: "border-box" }} />
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>BUY PRICE ($)</div>
              <input value={form.buyPrice} onChange={e => setForm(f => ({ ...f, buyPrice: e.target.value }))} placeholder="e.g. 182.50" type="number" min="0" style={{ width: "100%", background: "rgba(0,0,0,0.3)", border: `0.5px solid ${T.borderStrong}`, borderRadius: T.radius.sm, padding: "9px 12px", color: T.text, fontSize: 14, outline: "none", boxSizing: "border-box" }} />
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4 }}>BUY DATE</div>
              <input value={form.buyDate} onChange={e => setForm(f => ({ ...f, buyDate: e.target.value }))} type="date" style={{ width: "100%", background: "rgba(0,0,0,0.3)", border: `0.5px solid ${T.borderStrong}`, borderRadius: T.radius.sm, padding: "9px 12px", color: T.text, fontSize: 13, outline: "none", boxSizing: "border-box", colorScheme: "dark" }} />
            </div>
          </div>
          {formErr && <div style={{ fontSize: 12, color: T.red, marginBottom: 8 }}>{formErr}</div>}
          <button onClick={addPosition} style={{ width: "100%", padding: "11px 0", borderRadius: T.radius.md, border: "none", background: `linear-gradient(145deg, ${T.gold}, #8b5e12)`, color: "#000", fontSize: 14, fontWeight: 700, cursor: "pointer", fontFamily: T.font }}>
            Add to Portfolio
          </button>
        </div>
      )}

      {/* Position Cards */}
      {positions.length === 0 && !showAdd ? (
        <div style={{ textAlign: "center", padding: "40px 20px", color: T.textMuted }}>
          <div style={{ fontSize: 36, marginBottom: 12 }}>📊</div>
          <div style={{ fontSize: 14, color: T.textSub, marginBottom: 6 }}>No positions yet</div>
          <div style={{ fontSize: 12 }}>Tap "+ Add Position" to log your first trade.</div>
        </div>
      ) : (
        positions.map(pos => {
          const d = liveData[pos.id] || {};
          const cur = d.quote?.c;
          const invested = pos.shares * pos.buyPrice;
          const current  = cur ? pos.shares * cur : null;
          const pnl      = current !== null ? current - invested : null;
          const pnlPct   = pnl !== null ? (pnl / invested) * 100 : null;
          const isUp     = pnl !== null ? pnl >= 0 : null;
          const sig      = d.signal;
          const tech     = d.tech;
          const risk     = sig?.risk;

          // Sell target
          const sellTarget = sig?.sellAt || (tech?.bb?.upper) || (cur ? cur * 1.08 : null);
          const toSellTarget = sellTarget && cur ? ((sellTarget - cur) / cur * 100) : null;

          // Days held
          const daysSince = Math.floor((Date.now() - new Date(pos.buyDate).getTime()) / 86400000);

          return (
            <div key={pos.id} style={{ background: T.card, border: `0.5px solid ${isUp === null ? T.border : isUp ? T.greenBorder : T.redBorder}`, borderRadius: T.radius.md, marginBottom: 12, overflow: "hidden" }}>
              <div style={{ padding: 16 }}>
                {/* Header */}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ fontSize: 17, fontWeight: 700, color: T.text }}>{pos.symbol}</span>
                      {sig && <SignalPill signal={sig.signal} strength={sig.strength} />}
                      {risk && <RiskBadge risk={risk} />}
                    </div>
                    <div style={{ fontSize: 11, color: T.textMuted, marginTop: 3 }}>{pos.shares} shares · bought ${pos.buyPrice.toFixed(2)} · {daysSince}d ago</div>
                  </div>
                  <button onClick={() => removePosition(pos.id)} style={{ background: "rgba(255,69,58,0.1)", border: `0.5px solid ${T.redBorder}`, borderRadius: T.radius.xs, padding: "4px 8px", color: T.red, fontSize: 11, cursor: "pointer", fontFamily: T.font }}>Remove</button>
                </div>

                {/* P&L Row */}
                <div style={{ display: "flex", gap: 10, marginBottom: 12 }}>
                  <div style={{ flex: 1, background: "rgba(255,255,255,0.04)", borderRadius: T.radius.sm, padding: "10px 12px" }}>
                    <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 3 }}>INVESTED</div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: T.text, fontVariantNumeric: "tabular-nums" }}>${invested.toFixed(2)}</div>
                  </div>
                  <div style={{ flex: 1, background: "rgba(255,255,255,0.04)", borderRadius: T.radius.sm, padding: "10px 12px" }}>
                    <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 3 }}>CURRENT</div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: T.text, fontVariantNumeric: "tabular-nums" }}>{current !== null ? `$${current.toFixed(2)}` : "…"}</div>
                  </div>
                  <div style={{ flex: 1, background: isUp === null ? "rgba(255,255,255,0.04)" : isUp ? T.greenDim : T.redDim, borderRadius: T.radius.sm, padding: "10px 12px", border: `0.5px solid ${isUp === null ? "transparent" : isUp ? T.greenBorder : T.redBorder}` }}>
                    <div style={{ fontSize: 9, color: T.textMuted, marginBottom: 3 }}>P&L</div>
                    {pnl !== null ? (
                      <>
                        <div style={{ fontSize: 14, fontWeight: 700, color: isUp ? T.green : T.red, fontVariantNumeric: "tabular-nums" }}>{isUp ? "+" : ""}${pnl.toFixed(2)}</div>
                        <div style={{ fontSize: 10, color: isUp ? T.green : T.red, fontVariantNumeric: "tabular-nums" }}>{pnlPct >= 0 ? "+" : ""}{pnlPct.toFixed(2)}%</div>
                      </>
                    ) : <div style={{ fontSize: 14, color: T.textMuted }}>…</div>}
                  </div>
                </div>

                {/* Sell Target */}
                {cur && sellTarget && (
                  <div style={{ background: toSellTarget > 0 ? T.goldDim : T.redDim, border: `0.5px solid ${toSellTarget > 0 ? T.goldBorder : T.redBorder}`, borderRadius: T.radius.sm, padding: "9px 12px", marginBottom: 10 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div>
                        <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 2 }}>ATLAS SELL TARGET</div>
                        <div style={{ fontSize: 13, fontWeight: 600, color: T.gold }}>${sellTarget.toFixed(2)}</div>
                      </div>
                      <div style={{ textAlign: "right" }}>
                        <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 2 }}>TO TARGET</div>
                        <div style={{ fontSize: 13, fontWeight: 600, color: toSellTarget > 0 ? T.green : T.red }}>{toSellTarget > 0 ? "+" : ""}{toSellTarget.toFixed(2)}%</div>
                      </div>
                    </div>
                    {sig?.signal === "SELL" && (
                      <div style={{ marginTop: 6, fontSize: 11, color: T.red, fontWeight: 600 }}>⚠️ ATLAS says: SELL NOW — {sig.reason?.slice(0, 80)}</div>
                    )}
                    {sig?.signal === "HOLD" && (
                      <div style={{ marginTop: 6, fontSize: 11, color: T.gold }}>Hold — target not reached yet ({toSellTarget?.toFixed(1)}% away)</div>
                    )}
                  </div>
                )}

                {/* Confidence */}
                {tech && <ConfidenceBar value={tech.confidence} color={tech.compositeSignal === "BULLISH" ? T.green : tech.compositeSignal === "BEARISH" ? T.red : T.gold} />}

                <button onClick={() => onAsk(`Analyze my ${pos.symbol} position: I bought ${pos.shares} shares at $${pos.buyPrice} on ${pos.buyDate}. ${cur ? `Current price: $${cur.toFixed(2)}.` : ""} ${pnlPct !== null ? `I'm ${pnlPct >= 0 ? "up" : "down"} ${Math.abs(pnlPct).toFixed(2)}%.` : ""} Should I hold, add more, or sell? Give me the exact sell target, risk level, and what to watch for.`)}
                  style={{ width: "100%", marginTop: 12, padding: "9px 0", borderRadius: T.radius.sm, border: `0.5px solid ${T.goldBorder}`, background: T.goldDim, color: T.gold, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: T.font }}>
                  Ask ATLAS about this position
                </button>
              </div>
            </div>
          );
        })
      )}
    </div>
  );
}

// ─── MAIN ──────────────────────────────────────────────────────────────────────
export default function ATLASv4() {
  const [tab, setTab] = useState("chat");
  const [messages, setMessages] = useState([{
    role: "assistant",
    content: "ATLAS online. Powered by Gemini AI.\n\nLoading live prices + 180 days of historical data + technical indicators + Wall Street consensus…\n\nI can:\n• Analyze any stock with buy/sell signals + confidence + risk levels\n• Search any stock and add it to your watchlist\n• Generate goal-based investment plans (\"I want to make $200 in 1 month\")\n• Show prediction charts for any stock\n• Alert you when to buy, sell, how much, and at what price\n\nWhat do you want to know?",
  }]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [marketData, setMarketData] = useState(null);
  const [marketLoading, setMarketLoading] = useState(true);
  const [alerts, setAlerts] = useState([]);
  const [notifGranted, setNotifGranted] = useState(false);
  const [agentActive, setAgentActive] = useState({ intel: false, market: false });
  const [favorites, setFavorites] = useState(() => { try { return JSON.parse(localStorage.getItem("atlas_favorites") || "[]"); } catch { return []; } });
  const [showAlerts, setShowAlerts] = useState(false);
  const [activeAlertCount, setActiveAlertCount] = useState(() => PriceAlertManager.getActive().length);
  const [stockDetail, setStockDetail] = useState(null);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => { NotificationSystem.requestPermission().then(setNotifGranted); }, []);

  // Poll price alerts every 30s
  useEffect(() => {
    const poll = () => {
      if (!marketData) return;
      const prices = {};
      if (marketData.spy?.c) prices.SPY = marketData.spy.c;
      if (marketData.qqq?.c) prices.QQQ = marketData.qqq.c;
      if (marketData.voo?.c) prices.VOO = marketData.voo.c;
      PriceAlertManager.check(prices);
      setActiveAlertCount(PriceAlertManager.getActive().length);
    };
    poll();
    const t = setInterval(poll, 30_000);
    return () => clearInterval(t);
  }, [marketData]);

  const toggleFav = useCallback((symbol) => {
    setFavorites(prev => {
      const next = prev.includes(symbol) ? prev.filter(s => s !== symbol) : [...prev, symbol];
      localStorage.setItem("atlas_favorites", JSON.stringify(next));
      return next;
    });
  }, []);

  const handleAlerts = useCallback((data) => {
    const prices = {};
    if (data.spy?.c) prices.SPY = data.spy.c;
    if (data.qqq?.c) prices.QQQ = data.qqq.c;
    if (data.voo?.c) prices.VOO = data.voo.c;
    LearningAgent.evaluateSignals(prices);
    if (data.signals) {
      const newAlerts = [];
      data.signals.forEach(sig => {
        LearningAgent.trackSignal(sig.symbol, sig.signal, sig.quote?.c, sig.strength);
        if (sig.signal === "SELL" && sig.strength >= 65) {
          const a = { type: "sell", title: `Sell Signal — ${sig.symbol} (${sig.strength}%)`, body: sig.reason };
          NotificationSystem.send(a.title, a.body); newAlerts.push(a);
        } else if (sig.signal === "BUY" && sig.strength >= 65) {
          const a = { type: "buy", title: `Buy Signal — ${sig.symbol} (${sig.strength}%)`, body: sig.reason };
          NotificationSystem.send(a.title, a.body); newAlerts.push(a);
        }
      });
      if (newAlerts.length > 0) setAlerts(prev => [...newAlerts, ...prev].slice(0, 5));
    }
  }, []);

  const fetchMarket = useCallback(async () => {
    setMarketLoading(true);
    setAgentActive(s => ({ ...s, market: true }));
    const base = await MarketAgent.getQuotes();
    setMarketData(base);
    setMarketLoading(false);
    setAgentActive(s => ({ ...s, market: false }));
    handleAlerts(base);
    MarketAgent.enrichWithTechnicals(base).then(enriched => {
      setMarketData(enriched);
      handleAlerts(enriched);
    }).catch(() => {});
  }, [handleAlerts]);

  useEffect(() => {
    fetchMarket();
    const interval = setInterval(fetchMarket, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, [fetchMarket]);

  useEffect(() => { messagesEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const sendMessage = useCallback(async (text) => {
    const raw = text || input.trim();
    if (!raw || loading) return;

    if (!SecurityAgent.checkRateLimit()) {
      setMessages(prev => [...prev, { role: "assistant", content: "⚠️ Rate limit reached (20 requests/min). Please wait a moment before asking again.", isError: true }]);
      return;
    }

    const userText = SecurityAgent.sanitize(raw);
    setInput("");
    const newMessages = [...messages, { role: "user", content: userText }];
    setMessages(newMessages);
    setLoading(true);
    setAgentActive(s => ({ ...s, intel: true }));
    setTab("chat");
    setMessages(prev => [...prev, { role: "assistant", content: "", typing: true }]);

    try {
      SecurityAgent.logEvent("API_CALL", "Gemini Chat");
      const snapshot = MarketAgent.formatForAI(marketData);
      const watchlistContext = favorites.length > 0 ? `User's watchlist: ${favorites.join(", ")}` : "";
      const apiMsgs = newMessages.map(m => ({ role: m.role, content: m.content }));
      const body = JSON.stringify({ messages: apiMsgs, systemPrompt: buildPrompt(snapshot, watchlistContext) });

      let fullText = "";

      await ErrorRecoveryAgent.withRetry(
        async (attempt) => {
          const res = await fetch(`${API_BASE}/chat`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body,
          });

          if (!res.ok) {
            const errData = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
            throw new Error(errData.error || `HTTP ${res.status}`);
          }

          const reader = res.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          fullText = "";

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split("\n");
            buffer = lines.pop() || "";
            for (const line of lines) {
              if (!line.startsWith("data: ")) continue;
              try {
                const data = JSON.parse(line.slice(6));
                if (!SecurityAgent.validateApiResponse(data)) continue;
                if (data.error) throw new Error(data.error);
                if (data.content) {
                  fullText += data.content;
                  setMessages(prev => { const u = [...prev]; u[u.length - 1] = { role: "assistant", content: fullText }; return u; });
                }
              } catch (parseErr) {
                if (parseErr.message && !parseErr.message.includes("JSON")) throw parseErr;
              }
            }
          }
        },
        (attempt, delayMs) => {
          const sec = (delayMs / 1000).toFixed(1);
          setMessages(prev => {
            const u = [...prev];
            u[u.length - 1] = { role: "assistant", content: `⟳ Retrying… (attempt ${attempt + 1}/${ErrorRecoveryAgent.MAX_RETRIES}, waiting ${sec}s)`, typing: true };
            return u;
          });
        }
      );

      const lower = fullText.toLowerCase();
      if (lower.includes("sell") && lower.includes("recommend")) {
        const a = { type: "sell", title: "ATLAS recommends a sell", body: fullText.slice(0, 130) + "…" };
        NotificationSystem.send(a.title, a.body); setAlerts(prev => [a, ...prev].slice(0, 5));
      } else if (lower.includes("strong buy") || (lower.includes("buy") && lower.includes("opportunity"))) {
        const a = { type: "buy", title: "ATLAS identified a buy opportunity", body: fullText.slice(0, 130) + "…" };
        NotificationSystem.send(a.title, a.body); setAlerts(prev => [a, ...prev].slice(0, 5));
      }

      LearningAgent.logSession([...newMessages, { role: "assistant", content: fullText }]);
      setMessages(prev => { const u = [...prev]; u[u.length - 1] = { role: "assistant", content: fullText || "No response." }; return u; });
    } catch (err) {
      SecurityAgent.logEvent("ERROR", err.message);
      const friendly = ErrorRecoveryAgent.friendlyMessage(err);
      setMessages(prev => { const u = [...prev]; u[u.length - 1] = { role: "assistant", content: friendly, isError: true, retryText: raw }; return u; });
    }
    setLoading(false);
    setAgentActive(s => ({ ...s, intel: false }));
  }, [input, loading, messages, marketData, favorites]);

  const TABS = [
    { id: "chat",      label: "Chat" },
    { id: "market",    label: "Trends" },
    { id: "watchlist", label: "Watch" },
    { id: "plan",      label: "Plan" },
  ];

  const quickPrompts = [
    "What's the strongest buy signal right now?",
    "RSI analysis for SPY?",
    "I want to make $200 in 1 month",
    "Which stock has the lowest risk today?",
    "Show me a Golden Cross or Death Cross signal",
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", background: T.bg, fontFamily: T.font, overflow: "hidden", color: T.text }}>
      <style>{`
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        @keyframes pulse{0%,100%{opacity:.35;transform:scale(.8)}50%{opacity:1;transform:scale(1)}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
        @keyframes blink{0%,100%{opacity:.3}50%{opacity:1}}
        ::-webkit-scrollbar{width:0}
        textarea,input,select{resize:none;font-family:inherit}
        textarea::placeholder,input::placeholder{color:rgba(235,235,245,0.25)}
        button{font-family:inherit}
      `}</style>

      {/* ── NAV BAR ── */}
      <div style={{ padding: "12px 16px 10px", borderBottom: `0.5px solid ${T.sep}`, background: "rgba(0,0,0,0.72)", backdropFilter: T.glass, WebkitBackdropFilter: T.glass, zIndex: 20, flexShrink: 0, display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9, flex: 1 }}>
          <div style={{ width: 32, height: 32, borderRadius: 9, background: `linear-gradient(145deg, ${T.gold}, #8b5e12)`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 700, color: "#000", boxShadow: `0 0 0 0.5px rgba(255,255,255,0.1), 0 4px 12px rgba(212,168,83,0.3)`, flexShrink: 0 }}>A</div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600, color: T.text, letterSpacing: "-0.01em" }}>ATLAS</div>
            <div style={{ fontSize: 10, color: T.textMuted }}>Financial Intelligence · Gemini AI</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button onClick={() => setShowAlerts(true)} style={{ position: "relative", background: activeAlertCount > 0 ? T.goldDim : "rgba(255,255,255,0.06)", border: `0.5px solid ${activeAlertCount > 0 ? T.goldBorder : T.border}`, borderRadius: T.radius.xs, width: 32, height: 32, display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer", fontSize: 15, flexShrink: 0 }}>
            🔔
            {activeAlertCount > 0 && (
              <div style={{ position: "absolute", top: -4, right: -4, background: T.red, borderRadius: "50%", width: 14, height: 14, fontSize: 9, fontWeight: 700, color: "#fff", display: "flex", alignItems: "center", justifyContent: "center" }}>{activeAlertCount}</div>
            )}
          </button>
          <div style={{ display: "flex", background: "rgba(118,118,128,0.18)", borderRadius: T.radius.sm, padding: 2, gap: 1 }}>
            {TABS.map(t => (
              <button key={t.id} onClick={() => setTab(t.id)} style={{ padding: "5px 10px", borderRadius: T.radius.xs, fontSize: 11, fontWeight: tab === t.id ? 600 : 400, color: tab === t.id ? T.text : T.textMuted, background: tab === t.id ? "rgba(255,255,255,0.14)" : "transparent", border: "none", cursor: "pointer", boxShadow: tab === t.id ? "0 1px 4px rgba(0,0,0,0.5)" : "none", transition: "all 0.18s ease", whiteSpace: "nowrap" }}>{t.label}</button>
            ))}
          </div>
        </div>
      </div>

      {/* ── STATUS ROW ── */}
      <div style={{ display: "flex", gap: 6, padding: "6px 16px", background: "rgba(0,0,0,0.5)", backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)", borderBottom: `0.5px solid ${T.sep}`, flexShrink: 0, overflowX: "auto" }}>
        {[
          { label: "Gemini AI", color: T.gold, active: agentActive.intel },
          { label: "Market Feed", color: T.green, active: agentActive.market || marketLoading },
          { label: "Technicals", color: T.indigo, active: !!(marketData?.technicals?.SPY) },
          { label: "Security Guardian", color: "#8E9CF0", active: true },
          { label: "Error Recovery", color: "#5E9CF0", active: true },
          { label: notifGranted ? `Alerts (${activeAlertCount})` : "Enable Alerts", color: notifGranted ? T.green : T.red, active: notifGranted, onClick: !notifGranted ? () => NotificationSystem.requestPermission().then(setNotifGranted) : () => setShowAlerts(true) },
        ].map(a => (
          <div key={a.label} onClick={a.onClick} style={{ display: "flex", alignItems: "center", gap: 5, padding: "3px 10px", borderRadius: T.radius.pill, border: `0.5px solid ${a.active ? `${a.color}30` : "rgba(255,255,255,0.04)"}`, background: a.active ? `${a.color}0D` : "transparent", cursor: a.onClick ? "pointer" : "default", flexShrink: 0, transition: "all 0.25s ease" }}>
            <div style={{ width: 5, height: 5, borderRadius: "50%", background: a.active ? a.color : "rgba(255,255,255,0.1)", boxShadow: a.active ? `0 0 6px ${a.color}` : "none", animation: a.active ? "pulse 2.5s ease infinite" : "none" }} />
            <span style={{ fontSize: 10, color: a.active ? a.color : T.textMuted, fontWeight: 500 }}>{a.label}</span>
          </div>
        ))}
      </div>

      {/* ── LIVE TICKER ── */}
      {marketData && (
        <div style={{ display: "flex", gap: 0, padding: "0 16px", borderBottom: `0.5px solid ${T.sep}`, background: "rgba(0,0,0,0.4)", flexShrink: 0, overflowX: "auto" }}>
          {[
            { label: "SPY", q: marketData.spy },
            { label: "QQQ", q: marketData.qqq },
            { label: "VOO", q: marketData.voo },
            { label: "BTC", q: marketData.btc, crypto: true },
            { label: "ETH", q: marketData.eth, crypto: true },
          ].map(({ label, q, crypto }, i, arr) => {
            if (!q || !q.c) return null;
            const chg = q.pc ? ((q.c - q.pc) / q.pc) * 100 : 0;
            const sig = marketData.signals?.find(s => s.symbol === label);
            const tech = marketData.technicals?.[label];
            return (
              <div key={label} style={{ display: "flex", alignItems: "center", gap: 6, padding: "7px 14px", borderRight: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none", flexShrink: 0 }}>
                <span style={{ fontSize: 10, fontWeight: 600, color: T.textMuted, letterSpacing: "0.04em" }}>{label}</span>
                <span style={{ fontSize: 11, color: crypto ? T.gold : T.text, fontVariantNumeric: "tabular-nums", fontWeight: 500 }}>${Number(q.c).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</span>
                <span style={{ fontSize: 10, color: chg >= 0 ? T.green : T.red, fontVariantNumeric: "tabular-nums" }}>{chg >= 0 ? "+" : ""}{chg.toFixed(2)}%</span>
                {tech && <SignalPill signal={tech.compositeSignal} small />}
                {sig && sig.signal !== "HOLD" && sig.signal !== "WATCH" && <SignalPill signal={sig.signal} strength={sig.strength} small />}
              </div>
            );
          })}
        </div>
      )}

      {/* ── ALERTS ── */}
      {alerts.length > 0 && tab === "chat" && (
        <div style={{ flexShrink: 0 }}>
          {alerts.slice(0, 2).map((a, i) => <AlertBanner key={i} alert={a} onDismiss={() => setAlerts(prev => prev.filter((_, j) => j !== i))} />)}
        </div>
      )}

      {/* ── CHAT TAB ── */}
      {tab === "chat" && (
        <>
          <div style={{ flex: 1, overflowY: "auto", paddingTop: 16, paddingBottom: 8 }}>
            {messages.map((msg, i) => {
              const isUser = msg.role === "user";
              return (
                <div key={i} style={{ display: "flex", justifyContent: isUser ? "flex-end" : "flex-start", padding: "0 16px", marginBottom: 10, animation: "fadeIn 0.25s ease", alignItems: "flex-end", gap: 8 }}>
                  {!isUser && !msg.typing && (
                    <div style={{ width: 24, height: 24, borderRadius: 7, flexShrink: 0, background: `linear-gradient(145deg, ${T.gold}, #8b5e12)`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, color: "#000", marginBottom: 2 }}>A</div>
                  )}
                  {msg.typing ? (
                    <div style={{ display: "flex", alignItems: "center", gap: 5, background: T.card, border: `0.5px solid ${T.border}`, borderRadius: "4px 16px 16px 16px", padding: "12px 16px", marginLeft: 32 }}>
                      {msg.content ? (
                        <span style={{ fontSize: 12, color: T.gold }}>{msg.content}</span>
                      ) : (
                        [0, 1, 2].map(j => <div key={j} style={{ width: 6, height: 6, borderRadius: "50%", background: T.gold, animation: `pulse 1.4s ease ${j * 0.18}s infinite` }} />)
                      )}
                    </div>
                  ) : (
                    <div style={{ maxWidth: "85%" }}>
                      <div style={{ padding: "11px 14px", borderRadius: isUser ? "16px 16px 4px 16px" : i === 0 ? "16px 16px 16px 4px" : "4px 16px 16px 16px", background: isUser ? T.goldDim : msg.isError ? "rgba(255,69,58,0.08)" : T.card, border: `0.5px solid ${isUser ? T.goldBorder : msg.isError ? T.redBorder : T.border}`, boxShadow: "0 1px 6px rgba(0,0,0,0.25)", fontSize: 14, lineHeight: 1.65, color: msg.isError ? T.red : T.text, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                        {msg.content}
                      </div>
                      {msg.isError && msg.retryText && (
                        <button onClick={() => sendMessage(msg.retryText)} style={{ marginTop: 6, padding: "6px 14px", borderRadius: T.radius.pill, border: `0.5px solid ${T.goldBorder}`, background: T.goldDim, color: T.gold, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: T.font }}>
                          ↺ Retry
                        </button>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
            <div ref={messagesEndRef} />
          </div>

          {messages.length <= 1 && (
            <div style={{ padding: "6px 0 6px 16px", display: "flex", gap: 7, overflowX: "auto", flexShrink: 0 }}>
              {quickPrompts.map(p => (
                <button key={p} onClick={() => sendMessage(p)} style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.pill, padding: "7px 14px", color: T.textSub, fontSize: 12, fontWeight: 500, cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0 }}>{p}</button>
              ))}
            </div>
          )}

          <div style={{ padding: "10px 16px 22px", borderTop: `0.5px solid ${T.sep}`, background: "rgba(0,0,0,0.6)", backdropFilter: "blur(30px)", WebkitBackdropFilter: "blur(30px)", flexShrink: 0 }}>
            <div style={{ display: "flex", gap: 10, alignItems: "flex-end", background: "rgba(28,28,30,0.9)", border: `0.5px solid ${T.borderStrong}`, borderRadius: 20, padding: "10px 10px 10px 16px" }}>
              <textarea ref={inputRef} value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } }} placeholder="Ask about signals, goals, stocks, predictions…" rows={1} style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: T.text, fontSize: 14, lineHeight: 1.5, maxHeight: 100, overflowY: "auto" }} onInput={e => { e.target.style.height = "auto"; e.target.style.height = Math.min(e.target.scrollHeight, 100) + "px"; }} />
              <button onClick={() => sendMessage()} disabled={loading || !input.trim()} style={{ width: 34, height: 34, borderRadius: "50%", border: "none", background: !loading && input.trim() ? `linear-gradient(145deg, ${T.gold}, #8b5e12)` : "rgba(255,255,255,0.07)", cursor: !loading && input.trim() ? "pointer" : "not-allowed", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, transition: "all 0.2s ease" }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={!loading && input.trim() ? "#000" : "rgba(255,255,255,0.25)"} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" /></svg>
              </button>
            </div>
            <div style={{ textAlign: "center", fontSize: 10, color: "rgba(255,255,255,0.12)", marginTop: 6 }}>Powered by Gemini AI · Educational use only · Not financial advice</div>
          </div>
        </>
      )}

      {/* ── MARKET TAB — TRENDS ── */}
      {tab === "market" && (() => {
        const allStocks = [
          { label: "SPY", q: marketData?.spy, sig: marketData?.signals?.find(s => s.symbol === "SPY"), tech: marketData?.technicals?.SPY },
          { label: "QQQ", q: marketData?.qqq, sig: marketData?.signals?.find(s => s.symbol === "QQQ"), tech: marketData?.technicals?.QQQ },
          { label: "VOO", q: marketData?.voo, sig: marketData?.signals?.find(s => s.symbol === "VOO"), tech: marketData?.technicals?.VOO },
        ].filter(s => s.q?.c);
        const trendingUp   = allStocks.filter(s => s.sig?.signal === "BUY"  || s.tech?.compositeSignal === "BULLISH");
        const trendingDown = allStocks.filter(s => s.sig?.signal === "SELL" || s.tech?.compositeSignal === "BEARISH");
        const stable       = allStocks.filter(s => !trendingUp.includes(s) && !trendingDown.includes(s));
        return (
          <div style={{ flex: 1, overflowY: "auto", padding: "16px 16px 32px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <div>
                <div style={{ fontSize: 17, fontWeight: 700, color: T.text }}>Trends</div>
                <div style={{ fontSize: 11, color: T.textMuted, marginTop: 2 }}>{marketData ? `Updated ${marketData.fetchedAt?.toLocaleTimeString()}` : "Loading…"}</div>
              </div>
              <button onClick={fetchMarket} style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.xs, padding: "5px 12px", color: T.gold, cursor: "pointer", fontSize: 11, fontWeight: 500 }}>↻ Refresh</button>
            </div>

            {/* Trending Up */}
            {trendingUp.length > 0 && (
              <>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                  <div style={{ width: 7, height: 7, borderRadius: "50%", background: T.green, boxShadow: `0 0 6px ${T.green}` }} />
                  <span style={{ fontSize: 11, fontWeight: 700, color: T.green, textTransform: "uppercase", letterSpacing: "0.07em" }}>Trending Up — likely to rise</span>
                </div>
                {trendingUp.map(item => (
                  <MarketCard key={item.label} label={item.label} quote={item.q} signal={item.sig} tech={item.tech}
                    isFavorite={favorites.includes(item.label)} onToggleFav={toggleFav} onAsk={sendMessage}
                    onCardClick={setStockDetail} />
                ))}
              </>
            )}

            {/* Trending Down */}
            {trendingDown.length > 0 && (
              <>
                <div style={{ display: "flex", alignItems: "center", gap: 8, margin: `${trendingUp.length > 0 ? "16px" : "0"} 0 8px` }}>
                  <div style={{ width: 7, height: 7, borderRadius: "50%", background: T.red, boxShadow: `0 0 6px ${T.red}` }} />
                  <span style={{ fontSize: 11, fontWeight: 700, color: T.red, textTransform: "uppercase", letterSpacing: "0.07em" }}>Trending Down — watch for weakness</span>
                </div>
                {trendingDown.map(item => (
                  <MarketCard key={item.label} label={item.label} quote={item.q} signal={item.sig} tech={item.tech}
                    isFavorite={favorites.includes(item.label)} onToggleFav={toggleFav} onAsk={sendMessage}
                    onCardClick={setStockDetail} />
                ))}
              </>
            )}

            {/* Stable / Watching */}
            {stable.length > 0 && (
              <>
                <div style={{ display: "flex", alignItems: "center", gap: 8, margin: `${(trendingUp.length > 0 || trendingDown.length > 0) ? "16px" : "0"} 0 8px` }}>
                  <div style={{ width: 7, height: 7, borderRadius: "50%", background: T.gold }} />
                  <span style={{ fontSize: 11, fontWeight: 700, color: T.gold, textTransform: "uppercase", letterSpacing: "0.07em" }}>Stable — no clear direction yet</span>
                </div>
                {stable.map(item => (
                  <MarketCard key={item.label} label={item.label} quote={item.q} signal={item.sig} tech={item.tech}
                    isFavorite={favorites.includes(item.label)} onToggleFav={toggleFav} onAsk={sendMessage}
                    onCardClick={setStockDetail} />
                ))}
              </>
            )}

            {/* Wall Street Consensus */}
            {marketData?.recommendations && Object.values(marketData.recommendations).some(Boolean) && (
              <>
                <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", margin: "18px 0 8px" }}>Wall St. Consensus</div>
                {Object.entries(marketData.recommendations).map(([sym, rec]) => <AnalystCard key={sym} symbol={sym} rec={rec} />)}
              </>
            )}

            {/* Crypto */}
            <div style={{ display: "flex", alignItems: "center", gap: 8, margin: "18px 0 8px" }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: T.gold, textTransform: "uppercase", letterSpacing: "0.07em" }}>⚡ Crypto</span>
            </div>
            {[
              { label: "BTC", q: marketData?.btc, tech: marketData?.technicals?.BTC, sig: null },
              { label: "ETH", q: marketData?.eth, tech: marketData?.technicals?.ETH, sig: null },
            ].map(item => (
              <MarketCard key={item.label} label={item.label} quote={item.q} tech={item.tech} isCrypto
                isFavorite={favorites.includes(item.label)} onToggleFav={toggleFav} onAsk={sendMessage}
                onCardClick={setStockDetail} />
            ))}

            {/* Headlines */}
            {marketData?.news?.length > 0 && (
              <>
                <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", margin: "18px 0 8px" }}>Headlines</div>
                {marketData.news.map((n, i) => (
                  <div key={i} style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: "12px 14px", marginBottom: 8, cursor: "pointer" }}
                    onClick={() => sendMessage(`What is the market impact of this news: "${n.headline}"?`)}>
                    <div style={{ fontSize: 13, color: T.text, lineHeight: 1.5, marginBottom: 5 }}>{n.headline}</div>
                    <div style={{ fontSize: 10, color: T.textMuted }}>{n.source} · {new Date(n.datetime * 1000).toLocaleDateString()} · Tap to analyze</div>
                  </div>
                ))}
              </>
            )}
          </div>
        );
      })()}

      {/* ── WATCH + PORTFOLIO TAB ── */}
      {tab === "watchlist" && (
        <WatchlistTab favorites={favorites} onToggleFav={toggleFav} onAsk={sendMessage} marketData={marketData} onCardClick={setStockDetail} />
      )}

      {/* ── PLAN TAB ── */}
      {tab === "plan" && (
        <div style={{ flex: 1, overflowY: "auto", padding: "16px 16px 40px" }}>
          <GoalPlanner onAsk={sendMessage} />

          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>DCA Strategy</div>
          <div style={{ background: T.greenDim, border: `0.5px solid ${T.greenBorder}`, borderRadius: T.radius.md, padding: 16, marginBottom: 20 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: T.green, marginBottom: 8 }}>Dollar-Cost Averaging</div>
            <div style={{ fontSize: 13, color: T.textSub, lineHeight: 1.6, marginBottom: 12 }}>Invest a fixed amount every month regardless of market conditions. Removes emotion, builds wealth steadily over time.</div>
            <div style={{ background: "rgba(0,0,0,0.25)", borderRadius: T.radius.xs, padding: "8px 12px", fontSize: 12, color: T.green, fontWeight: 500 }}>Suggested: 60% VOO + 30% QQQ + 10% cash buffer</div>
          </div>

          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Quick Actions</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 20 }}>
            {[
              { label: "📊 Analyze my watchlist", prompt: `Analyze these stocks from my watchlist: ${favorites.length > 0 ? favorites.join(", ") : "SPY, QQQ, VOO"}. Give me buy/sell/hold for each with confidence and risk levels.` },
              { label: "📈 Best stock to buy right now", prompt: "Based on current signals, which stock has the strongest buy signal? Give me confidence level, risk level, entry price, and target." },
              { label: "🛡️ Lowest risk investment now", prompt: "Which stock or ETF currently has the best risk/reward ratio? Low risk, positive signal, good upside potential." },
              { label: "⚡ Highest conviction signal", prompt: "What is the single highest-conviction signal in the market right now? Back it up with all available technical indicators." },
            ].map(({ label, prompt }) => (
              <button key={label} onClick={() => sendMessage(prompt)} style={{ width: "100%", textAlign: "left", background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: "13px 16px", color: T.textSub, fontSize: 13, cursor: "pointer", fontFamily: T.font, transition: "all 0.18s ease" }}>
                {label}
              </button>
            ))}
          </div>

          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>When To Sell</div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, overflow: "hidden" }}>
            {[
              "Position is up 20%+ and RSI is overbought (>70)",
              "You need the money within 12 months",
              "Fundamental news changes (scandal, delisting, earnings collapse)",
              "ATLAS fires a SELL signal with 70%+ confidence",
              "Stop-loss: position is down 8% and showing no recovery signs",
            ].map((rule, i, arr) => (
              <div key={i} style={{ display: "flex", gap: 12, padding: "13px 16px", borderBottom: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none", alignItems: "flex-start" }}>
                <div style={{ width: 20, height: 20, borderRadius: 6, flexShrink: 0, background: T.redDim, border: `0.5px solid ${T.redBorder}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, color: T.red, marginTop: 1 }}>{i + 1}</div>
                <div style={{ fontSize: 13, color: T.textSub, lineHeight: 1.55 }}>{rule}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {showAlerts && <PriceAlertsPanel onClose={() => { setShowAlerts(false); setActiveAlertCount(PriceAlertManager.getActive().length); }} />}

      {stockDetail && (
        <StockDetailModal
          symbol={stockDetail.symbol}
          quote={stockDetail.quote}
          signal={stockDetail.signal}
          tech={stockDetail.tech}
          isFavorite={favorites.includes(stockDetail.symbol)}
          onToggleFav={toggleFav}
          onAsk={(msg) => { sendMessage(msg); setTab("chat"); }}
          onClose={() => setStockDetail(null)}
        />
      )}
    </div>
  );
}
