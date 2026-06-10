import { useState, useRef, useEffect, useCallback } from "react";

// ─── USER PROFILE ──────────────────────────────────────────────────────────────
const USER_PROFILE = {
  monthlyBudget: 200,
  budgetRange: "$100–$300/month",
  experience: "Complete beginner",
  riskTolerance: "Medium — balanced growth",
  investmentStyle: "Index funds + select stocks",
};

// ─── CONFIG ────────────────────────────────────────────────────────────────────
const getApiKey = () => (typeof import.meta !== "undefined" && import.meta.env?.VITE_ANTHROPIC_KEY) || "";
const getFinnhubKey = () => (typeof import.meta !== "undefined" && import.meta.env?.VITE_FINNHUB_KEY) || "";

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
      threats: this.log.filter(e => e.type === "THREAT_BLOCKED"),
      apiCalls: this.log.filter(e => e.type === "API_CALL"),
      errors: this.log.filter(e => e.type === "ERROR"),
      total: this.log.length,
      sessionId: this.sessionId,
    };
  },
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
    // Approximate signal line
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

    // Golden Cross
    if (sma50 && sma200 && sma50p && sma200p && sma50 > sma200 && sma50p <= sma200p)
      patterns.push({ name: "Golden Cross 🟢", type: "bullish", strength: 92,
        desc: `50-day SMA ($${sma50.toFixed(2)}) just crossed above 200-day SMA ($${sma200.toFixed(2)}). Historically one of the most reliable long-term buy signals — often precedes sustained uptrends.` });

    // Death Cross
    if (sma50 && sma200 && sma50p && sma200p && sma50 < sma200 && sma50p >= sma200p)
      patterns.push({ name: "Death Cross 🔴", type: "bearish", strength: 90,
        desc: `50-day SMA ($${sma50.toFixed(2)}) crossed below 200-day SMA ($${sma200.toFixed(2)}). A major bearish signal — this pattern preceded every major bear market since 1929.` });

    // Strong uptrend: price > SMA20 > SMA50 > SMA200
    if (sma20 && sma50 && sma200 && cur > sma20 && sma20 > sma50 && sma50 > sma200)
      patterns.push({ name: "Perfect Uptrend 🟢", type: "bullish", strength: 80,
        desc: `Price > 20-day > 50-day > 200-day MA. All moving averages aligned — textbook bull trend structure.` });

    // RSI oversold
    if (rsi !== null && rsi < 30)
      patterns.push({ name: `Oversold RSI ${rsi.toFixed(0)} ⚡`, type: "bullish", strength: 72,
        desc: `RSI at ${rsi.toFixed(1)} is deep in oversold territory (<30). In 73% of historical cases, assets recover within 5–10 trading days from this level.` });

    // RSI overbought
    if (rsi !== null && rsi > 75)
      patterns.push({ name: `Overbought RSI ${rsi.toFixed(0)} ⚠️`, type: "bearish", strength: 68,
        desc: `RSI at ${rsi.toFixed(1)} indicates overbought conditions (>70). Momentum tends to slow from these levels — watch for reversal.` });

    // MACD bullish crossover
    if (macd && macd.bullish && macd.histogram > 0)
      patterns.push({ name: "MACD Bullish ↑", type: "bullish", strength: 65,
        desc: `MACD line (${macd.line.toFixed(2)}) above signal line. Bullish momentum confirmed — trend acceleration likely.` });

    // MACD bearish
    if (macd && !macd.bullish && macd.histogram < 0)
      patterns.push({ name: "MACD Bearish ↓", type: "bearish", strength: 60,
        desc: `MACD line (${macd.line.toFixed(2)}) below signal line. Bearish momentum in force.` });

    // Bollinger Band signals
    if (bb && cur <= bb.lower)
      patterns.push({ name: "BB Lower Band Touch", type: "bullish", strength: 64,
        desc: `Price at lower Bollinger Band ($${bb.lower.toFixed(2)}). Statistically, 95% of price action stays within the bands — reversion to the mean ($${bb.middle.toFixed(2)}) is expected.` });

    if (bb && cur >= bb.upper)
      patterns.push({ name: "BB Upper Band Touch", type: "bearish", strength: 60,
        desc: `Price at upper Bollinger Band ($${bb.upper.toFixed(2)}). Mean-reversion pull toward $${bb.middle.toFixed(2)} is statistically likely.` });

    // BB Squeeze (volatility compression)
    if (bb && bb.bandwidth < 0.04)
      patterns.push({ name: "Volatility Squeeze ⚡", type: "neutral", strength: 70,
        desc: `Bollinger Bands compressed (bandwidth: ${(bb.bandwidth * 100).toFixed(1)}%). Low-volatility squeezes historically resolve with explosive moves — direction TBD by next catalyst.` });

    return patterns.slice(0, 5);
  },
};

// ─── HISTORICAL + TECHNICALS AGENT ────────────────────────────────────────────
const HistoricalAgent = {
  cache: {},

  // Yahoo Finance → free, no key, 6 months of daily OHLCV
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
        const closes = [], highs = [], lows = [], opens = [];
        (result.timestamp || []).forEach((_, i) => {
          const c = quotes.close?.[i], h = quotes.high?.[i], l = quotes.low?.[i], o = quotes.open?.[i];
          if (c != null) { closes.push(c); highs.push(h ?? c); lows.push(l ?? c); opens.push(o ?? c); }
        });
        if (closes.length >= 14) return { closes, highs, lows, opens, volumes: [] };
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

  async fetchRecommendations(symbol) {
    const key = `rec_${symbol}`;
    const now = Date.now();
    if (this.cache[key] && now - this.cache[key].ts < 3_600_000) return this.cache[key].data;
    try {
      SecurityAgent.logEvent("API_CALL", `Recommendations: ${symbol}`);
      const res = await fetch(`https://finnhub.io/api/v1/recommendation?symbol=${symbol}&token=${getFinnhubKey()}`);
      if (!res.ok) return null;
      const data = await res.json();
      if (!Array.isArray(data) || data.length === 0) return null;
      const d = data[0];
      const total = (d.buy || 0) + (d.hold || 0) + (d.sell || 0) + (d.strongBuy || 0) + (d.strongSell || 0);
      if (total === 0) return null;
      const bullishPct = Math.round(((d.strongBuy || 0) + (d.buy || 0)) / total * 100);
      const bearishPct = Math.round(((d.strongSell || 0) + (d.sell || 0)) / total * 100);
      const result = {
        period: d.period, strongBuy: d.strongBuy || 0, buy: d.buy || 0,
        hold: d.hold || 0, sell: d.sell || 0, strongSell: d.strongSell || 0,
        total, bullishPct, bearishPct,
        consensus: bullishPct > 55 ? "BUY" : bearishPct > 35 ? "SELL" : "HOLD",
      };
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

    // Multi-factor composite score (-1 to +1)
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

    // BB position (0 = at lower, 1 = at upper)
    const bbPosition = bb ? (cur - bb.lower) / (bb.upper - bb.lower) : null;

    return { cur, rsi, macd, sma20, sma50, sma200, bb, bbPosition, atr, ch30, ch60, ch90, patterns, compositeSignal, composite, confidence };
  },
};

// ─── SIGNAL ENGINE ─────────────────────────────────────────────────────────────
const SignalEngine = {
  analyze(quote, symbol, tech) {
    if (!quote || !quote.c || !quote.pc) return null;
    const chgPct = ((quote.c - quote.pc) / quote.pc) * 100;

    let signal = "HOLD", strength = 55, reason = "";

    if (tech) {
      const { compositeSignal, confidence, rsi, macd, sma50, sma200, bb, patterns, ch30, ch90 } = tech;

      // Primary signal from composite
      if (compositeSignal === "BULLISH") signal = "BUY";
      else if (compositeSignal === "BEARISH") signal = "SELL";
      else signal = chgPct <= -2.5 ? "BUY" : chgPct >= 3.5 ? "SELL" : "HOLD";

      strength = confidence;
      // Boost on strong confirmation
      if (chgPct <= -2.5 && signal === "BUY")  strength = Math.min(94, strength + 10);
      if (chgPct >= 3.5  && signal === "SELL") strength = Math.min(94, strength + 10);

      // Build rich reason
      const bullets = [];
      if (rsi !== null) bullets.push(`RSI ${rsi.toFixed(0)} (${rsi < 30 ? "oversold" : rsi > 70 ? "overbought" : "neutral"})`);
      if (macd)         bullets.push(`MACD ${macd.bullish ? "▲ bullish" : "▼ bearish"}`);
      if (sma50)        bullets.push(`Price ${quote.c > sma50 ? "above" : "below"} 50-MA $${sma50.toFixed(2)}`);
      if (sma200)       bullets.push(`${quote.c > sma200 ? "above" : "below"} 200-MA $${sma200.toFixed(2)}`);
      if (ch30 !== null) bullets.push(`30-day trend: ${ch30 >= 0 ? "+" : ""}${ch30.toFixed(1)}%`);
      if (ch90 !== null) bullets.push(`90-day trend: ${ch90 >= 0 ? "+" : ""}${ch90.toFixed(1)}%`);
      if (patterns[0])  bullets.push(`Pattern: ${patterns[0].name}`);

      reason = `${signal} ${strength}% confidence · ${bullets.join(" · ")}`;
    } else {
      // Fallback: price-action only
      if (chgPct <= -2.5) { signal = "BUY";   strength = Math.min(90, Math.abs(chgPct) * 12); }
      else if (chgPct >= 3.5) { signal = "SELL"; strength = Math.min(90, chgPct * 10); }
      else if (Math.abs(chgPct) <= 1) { signal = "HOLD"; strength = 55; }
      else { signal = "WATCH"; strength = 45; }
      reason = `${symbol} ${chgPct >= 0 ? "+" : ""}${chgPct.toFixed(2)}% today — price-action signal only (historical data loading)`;
    }

    return { signal, strength: Math.round(strength), reason, changePercent: chgPct, quote, symbol, tech };
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
    if (this.cache[key] && now - this.cache[key].ts < 60_000) return this.cache[key].data;
    try {
      SecurityAgent.logEvent("API_CALL", `Quote: ${symbol}`);
      const res = await fetch(`https://finnhub.io/api/v1/quote?symbol=${symbol}&token=${getFinnhubKey()}`);
      const data = await res.json();
      this.cache[key] = { data, ts: now }; return data;
    } catch { SecurityAgent.logEvent("ERROR", `Quote: ${symbol}`); return null; }
  },
  async fetchCrypto(symbol) {
    const key = `c_${symbol}`, now = Date.now();
    if (this.cache[key] && now - this.cache[key].ts < 60_000) return this.cache[key].data;
    try {
      const res = await fetch(`https://finnhub.io/api/v1/quote?symbol=BINANCE:${symbol}USDT&token=${getFinnhubKey()}`);
      const data = await res.json();
      this.cache[key] = { data, ts: now }; return data;
    } catch { return null; }
  },
  async fetchNews() {
    const now = Date.now();
    if (this.cache.news && now - this.cache.news.ts < 300_000) return this.cache.news.data;
    try {
      const res = await fetch(`https://finnhub.io/api/v1/news?category=general&token=${getFinnhubKey()}`);
      const data = await res.json();
      const clean = Array.isArray(data) ? data.slice(0, 8) : [];
      this.cache.news = { data: clean, ts: now }; return clean;
    } catch { return []; }
  },

  // Phase 1: fast quotes (renders in ~300ms)
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

  // Phase 2: historical + technicals (runs in background, ~2-5s via CORS proxy)
  async enrichWithTechnicals(baseData) {
    const [spyC, qqqC, vooC, btcC, ethC, spyRec, qqqRec, vooRec] = await Promise.all([
      HistoricalAgent.fetchCandles("SPY"),
      HistoricalAgent.fetchCandles("QQQ"),
      HistoricalAgent.fetchCandles("VOO"),
      HistoricalAgent.fetchCandles("BTC"),
      HistoricalAgent.fetchCandles("ETH"),
      HistoricalAgent.fetchRecommendations("SPY"),
      HistoricalAgent.fetchRecommendations("QQQ"),
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

    let techSection = "=== TECHNICAL ANALYSIS (90-200 day historical data) ===\n";
    for (const [sym, t] of Object.entries(data.technicals || {})) {
      if (!t) { techSection += `${sym}: Historical data unavailable\n`; continue; }
      techSection += `\n${sym}:\n`;
      techSection += `  Composite Signal: ${t.compositeSignal} (${t.confidence}% confidence, score: ${t.composite.toFixed(2)})\n`;
      if (t.rsi !== null) techSection += `  RSI(14): ${t.rsi} — ${t.rsi < 30 ? "OVERSOLD — strong mean-reversion buy zone" : t.rsi > 70 ? "OVERBOUGHT — elevated reversal risk" : t.rsi < 45 ? "Mildly bearish" : "Mildly bullish"}\n`;
      if (t.macd) techSection += `  MACD: Line ${t.macd.line.toFixed(3)}, Signal ${t.macd.signal.toFixed(3)}, Histogram ${t.macd.histogram.toFixed(3)} — ${t.macd.bullish ? "BULLISH crossover" : "BEARISH crossover"}\n`;
      if (t.sma20) techSection += `  SMA-20: $${t.sma20.toFixed(2)} (price ${t.cur > t.sma20 ? "above ✓" : "below ✗"})\n`;
      if (t.sma50) techSection += `  SMA-50: $${t.sma50.toFixed(2)} (price ${t.cur > t.sma50 ? "above ✓" : "below ✗"})\n`;
      if (t.sma200) techSection += `  SMA-200: $${t.sma200.toFixed(2)} (price ${t.cur > t.sma200 ? "above ✓ — long-term bull market" : "below ✗ — long-term bear market"})\n`;
      if (t.bb) techSection += `  Bollinger Bands: Upper $${t.bb.upper.toFixed(2)} | Mid $${t.bb.middle.toFixed(2)} | Lower $${t.bb.lower.toFixed(2)} | Width ${(t.bb.bandwidth * 100).toFixed(1)}%\n`;
      if (t.ch30 !== null) techSection += `  Trend: 30d ${t.ch30 >= 0 ? "+" : ""}${t.ch30.toFixed(1)}% | 60d ${t.ch60 !== null ? (t.ch60 >= 0 ? "+" : "") + t.ch60.toFixed(1) + "%" : "N/A"} | 90d ${t.ch90 !== null ? (t.ch90 >= 0 ? "+" : "") + t.ch90.toFixed(1) + "%" : "N/A"}\n`;
      if (t.patterns.length > 0) {
        techSection += `  Patterns Detected:\n`;
        t.patterns.forEach(p => techSection += `    • ${p.name} (${p.strength}% strength, ${p.type}): ${p.desc}\n`);
      }
    }

    let analystSection = "=== WALL STREET ANALYST CONSENSUS ===\n";
    for (const [sym, r] of Object.entries(data.recommendations || {})) {
      if (!r) { analystSection += `${sym}: No analyst data\n`; continue; }
      analystSection += `${sym} (${r.period}): CONSENSUS ${r.consensus} — ${r.bullishPct}% bullish, ${r.bearishPct}% bearish\n`;
      analystSection += `  Strong Buy: ${r.strongBuy} | Buy: ${r.buy} | Hold: ${r.hold} | Sell: ${r.sell} | Strong Sell: ${r.strongSell} (${r.total} analysts total)\n`;
    }

    const signals = (data.signals || []).map(s => `${s.symbol}: ${s.signal} ${s.strength}% — ${s.reason}`).join("\n");
    const headlines = (data.news || []).slice(0, 5).map(n => `• ${n.headline}`).join("\n");

    return `=== LIVE PRICES (${data.fetchedAt?.toLocaleTimeString()}) ===
${fmt(data.spy, "S&P 500 / SPY")}
${fmt(data.qqq, "NASDAQ / QQQ")}
${fmt(data.voo, "VOO (Vanguard S&P500 ETF)")}
${fmtC(data.btc, "Bitcoin")}
${fmtC(data.eth, "Ethereum")}

=== ATLAS MULTI-FACTOR SIGNALS ===
${signals || "Generating signals..."}

${techSection}
${analystSection}
=== MARKET HEADLINES ===
${headlines || "No headlines"}`;
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

  logAlert(alert) {
    this.alerts.unshift({ ...alert, date: new Date().toISOString() });
    if (this.alerts.length > 50) this.alerts.pop();
    this.save();
  },

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
      if (ageHours < 24) return; // wait at least 24h
      const curPrice = currentPrices[s.symbol];
      if (!curPrice) return;
      const changePct = ((curPrice - s.price) / s.price) * 100;
      const correct = (s.signal === "BUY" && changePct > 0.5) || (s.signal === "SELL" && changePct < -0.5) || (s.signal === "HOLD" && Math.abs(changePct) <= 1.5);
      s.outcome = correct ? "correct" : "incorrect";
      s.priceAfter = curPrice;
      s.changePct = changePct;
      updated = true;
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

  generateReport() {
    const now = new Date(), weekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);
    const recent = this.sessions.filter(s => new Date(s.date) > weekAgo);
    const allTopics = recent.flatMap(s => s.topics);
    const topicCount = allTopics.reduce((acc, t) => { acc[t] = (acc[t] || 0) + 1; return acc; }, {});
    const topTopics = Object.entries(topicCount).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const sec = SecurityAgent.getReport();
    const accuracy = this.getSignalAccuracy();
    return {
      period: `${weekAgo.toLocaleDateString()} – ${now.toLocaleDateString()}`,
      totalSessions: recent.length,
      totalMessages: recent.reduce((a, s) => a + s.messageCount, 0),
      topTopics, recentAlerts: this.alerts.slice(0, 5),
      securityThreats: sec.threats.length, apiCalls: sec.apiCalls.length, errors: sec.errors.length,
      sessionId: SecurityAgent.sessionId, accuracy,
    };
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
  send(title, body, type = "info") {
    LearningAgent.logAlert({ title, body, type });
    if (this.permission === "granted") try { new Notification(`ATLAS: ${title}`, { body }); } catch {}
  },
};

// ─── SYSTEM PROMPT ─────────────────────────────────────────────────────────────
const buildPrompt = (marketContext) => `You are ATLAS — an elite AI financial intelligence system with access to live prices, 200 days of historical OHLCV data, technical indicators, pattern recognition, and Wall Street analyst consensus.

USER PROFILE:
• Monthly budget: $100–$300 | Experience: Beginner | Risk: Medium | Strategy: Index-first

HOW TO USE THE DATA BELOW:
1. ALWAYS cite exact live prices and exact indicator values when answering
2. Synthesize the composite signal, RSI, MACD, SMA crossovers, and Bollinger Bands together — a single indicator is noise, confluence is signal
3. Patterns like "Golden Cross" or "Death Cross" are extremely high-conviction — weight them heavily
4. Wall Street consensus adds external validation — align with it when your technical analysis agrees
5. 30/60/90-day trends tell you the macro direction — never fight a strong trend
6. When RSI is oversold (<30) AND price is near the lower Bollinger Band AND the 30-day trend is down but MACD is crossing bullish — that's a very high-probability buy setup
7. When RSI is overbought (>70) AND price is near upper BB AND momentum is slowing — that's a strong sell signal
8. Never recommend putting more than 25% of the monthly budget in any single position

LIVE MARKET DATA AND ANALYSIS:
${marketContext}

INVESTMENT FRAMEWORK:
• Core: 60% VOO + 30% QQQ (dollar-cost average monthly)
• Stocks: Only when technical confluence is strong (3+ indicators agreeing)
• BUY zone: RSI < 35 + price near/below 50-day MA + MACD bullish crossover
• SELL zone: RSI > 72 + price at/above upper BB + MACD bearish crossover
• Always state: signal, confidence %, specific indicators supporting it, and the dollar amount from their $100–$300 budget to act with

RESPONSE FORMAT:
• Lead with the signal and confidence
• List the key indicators supporting it
• Give the specific dollar action for their budget
• Note any risks or counter-signals
• End with: "This is educational analysis, not licensed financial advice."`;

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
  BUY:   { bg: T.greenDim,  border: T.greenBorder,  color: T.green,  dot: T.green },
  SELL:  { bg: T.redDim,    border: T.redBorder,    color: T.red,    dot: T.red  },
  HOLD:  { bg: T.goldDim,   border: T.goldBorder,   color: T.gold,   dot: T.gold },
  WATCH: { bg: T.orangeDim, border: T.orangeBorder, color: T.orange, dot: T.orange },
  BULLISH: { bg: T.greenDim,  border: T.greenBorder, color: T.green, dot: T.green },
  BEARISH: { bg: T.redDim,   border: T.redBorder,   color: T.red,   dot: T.red  },
  NEUTRAL: { bg: T.goldDim,  border: T.goldBorder,  color: T.gold,  dot: T.gold },
};

// ─── UI COMPONENTS ─────────────────────────────────────────────────────────────
function SignalPill({ signal, strength, small }) {
  const c = SIG_CFG[signal] || SIG_CFG.HOLD;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      padding: small ? "2px 7px 2px 5px" : "3px 10px 3px 7px",
      borderRadius: T.radius.pill, background: c.bg,
      border: `0.5px solid ${c.border}`, flexShrink: 0,
    }}>
      <span style={{ width: small ? 4 : 5, height: small ? 4 : 5, borderRadius: "50%", background: c.dot, boxShadow: `0 0 4px ${c.dot}` }} />
      <span style={{ fontSize: small ? 9 : 11, fontWeight: 600, color: c.color }}>{signal}</span>
      {strength && !small && <span style={{ fontSize: 9, color: c.color, opacity: 0.65, fontVariantNumeric: "tabular-nums" }}>{strength}%</span>}
    </span>
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
        <span style={{ fontSize: 10, color: T.textMuted, fontWeight: 500 }}>RSI(14)</span>
        <span style={{ fontSize: 10, color, fontWeight: 700, fontVariantNumeric: "tabular-nums" }}>{value.toFixed(1)} · {label}</span>
      </div>
      <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 100, position: "relative", overflow: "hidden" }}>
        {/* Zone colors */}
        <div style={{ position: "absolute", left: 0, width: "30%", height: "100%", background: "rgba(48,209,88,0.2)" }} />
        <div style={{ position: "absolute", right: 0, width: "30%", height: "100%", background: "rgba(255,69,58,0.2)" }} />
        <div style={{ position: "absolute", left: 0, width: `${pct * 100}%`, height: "100%", background: color, borderRadius: 100, transition: "width 0.6s ease" }} />
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 3 }}>
        <span style={{ fontSize: 8, color: T.green, opacity: 0.6 }}>30</span>
        <span style={{ fontSize: 8, color: T.red, opacity: 0.6 }}>70</span>
      </div>
    </div>
  );
}

function TechRow({ label, value, color, mono }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "9px 0", borderBottom: `0.5px solid ${T.sep}` }}>
      <span style={{ fontSize: 13, color: T.textSub }}>{label}</span>
      <span style={{ fontSize: 13, fontWeight: 500, color: color || T.text, fontVariantNumeric: mono ? "tabular-nums" : "normal" }}>{value}</span>
    </div>
  );
}

function PatternCard({ pattern }) {
  const c = pattern.type === "bullish" ? { bg: T.greenDim, border: T.greenBorder, color: T.green }
          : pattern.type === "bearish" ? { bg: T.redDim,   border: T.redBorder,   color: T.red  }
          : { bg: T.goldDim, border: T.goldBorder, color: T.gold };
  return (
    <div style={{ background: c.bg, border: `0.5px solid ${c.border}`, borderRadius: T.radius.sm, padding: "10px 12px", marginBottom: 8 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: c.color }}>{pattern.name}</span>
        <span style={{ fontSize: 10, color: c.color, opacity: 0.7, fontVariantNumeric: "tabular-nums" }}>{pattern.strength}% strength</span>
      </div>
      <div style={{ fontSize: 12, color: T.textSub, lineHeight: 1.5 }}>{pattern.desc}</div>
    </div>
  );
}

function AlertBanner({ alert, onDismiss }) {
  const isRed = alert.type === "sell", isGreen = alert.type === "buy";
  const bg = isRed ? T.redDim : isGreen ? T.greenDim : T.goldDim;
  const border = isRed ? T.redBorder : isGreen ? T.greenBorder : T.goldBorder;
  const accent = isRed ? T.red : isGreen ? T.green : T.gold;
  return (
    <div style={{ margin: "8px 16px 0", padding: "11px 14px", borderRadius: T.radius.md, background: bg, border: `0.5px solid ${border}`, display: "flex", alignItems: "flex-start", gap: 10, animation: "slideDown 0.3s ease" }}>
      <div style={{ width: 28, height: 28, borderRadius: T.radius.xs, background: `${accent}20`, border: `0.5px solid ${border}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, flexShrink: 0 }}>
        {isRed ? "↓" : isGreen ? "↑" : "◆"}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: accent, marginBottom: 2 }}>{alert.title}</div>
        <div style={{ fontSize: 12, color: T.textSub, lineHeight: 1.45, overflow: "hidden", textOverflow: "ellipsis", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>{alert.body}</div>
      </div>
      <button onClick={onDismiss} style={{ background: "none", border: "none", color: T.textMuted, cursor: "pointer", fontSize: 16, flexShrink: 0 }}>×</button>
    </div>
  );
}

function MarketCard({ label, quote, signal, tech, isCrypto }) {
  const [expanded, setExpanded] = useState(false);
  if (!quote || !quote.c) return (
    <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: 16, marginBottom: 10 }}>
      <div style={{ fontSize: 12, color: T.textMuted }}>{label}</div>
      <div style={{ fontSize: 13, color: T.textMuted, marginTop: 6 }}>Add Finnhub key to see live data</div>
    </div>
  );
  const chg = quote.pc ? ((quote.c - quote.pc) / quote.pc) * 100 : 0;
  const up = chg >= 0;
  const sigBorder = signal?.signal === "BUY" ? T.greenBorder : signal?.signal === "SELL" ? T.redBorder : T.border;

  return (
    <div style={{ background: T.card, border: `0.5px solid ${signal?.signal && signal.signal !== "HOLD" ? sigBorder : T.border}`, borderRadius: T.radius.md, marginBottom: 10, overflow: "hidden", boxShadow: "0 2px 12px rgba(0,0,0,0.3)" }}>
      <div style={{ padding: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <span style={{ fontSize: 12, fontWeight: 500, color: T.textMuted }}>{label}</span>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            {tech && <SignalPill signal={tech.compositeSignal} strength={tech.confidence} small />}
            {signal && <SignalPill signal={signal.signal} strength={signal.strength} />}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "flex-end", gap: 10, marginBottom: 8 }}>
          <span style={{ fontSize: 28, fontWeight: 700, color: isCrypto ? T.gold : T.text, letterSpacing: "-0.02em", fontVariantNumeric: "tabular-nums" }}>
            ${Number(quote.c).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
          </span>
          <span style={{ fontSize: 13, fontWeight: 500, color: up ? T.green : T.red, marginBottom: 3 }}>
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
      </div>

      {/* Technical details toggle */}
      {tech && (
        <>
          <button onClick={() => setExpanded(e => !e)} style={{
            width: "100%", background: "rgba(255,255,255,0.04)", border: "none", borderTop: `0.5px solid ${T.sep}`,
            padding: "9px 16px", display: "flex", justifyContent: "space-between", alignItems: "center",
            cursor: "pointer", color: T.textMuted, fontSize: 11, fontFamily: T.font,
          }}>
            <span>Technical Analysis</span>
            <span style={{ fontSize: 10, transition: "transform 0.2s", transform: expanded ? "rotate(180deg)" : "none" }}>▾</span>
          </button>
          {expanded && (
            <div style={{ padding: "12px 16px 16px", borderTop: `0.5px solid ${T.sep}` }}>
              <RSIGauge value={tech.rsi} />
              <div style={{ marginTop: 12 }}>
                {tech.macd && <TechRow label="MACD" value={`${tech.macd.bullish ? "▲ Bullish" : "▼ Bearish"} (${tech.macd.histogram.toFixed(3)})`} color={tech.macd.bullish ? T.green : T.red} />}
                {tech.sma20  && <TechRow label="SMA 20"  value={`$${tech.sma20.toFixed(2)} (price ${tech.cur > tech.sma20 ? "above ✓" : "below ✗"})`}  color={tech.cur > tech.sma20 ? T.green : T.red} mono />}
                {tech.sma50  && <TechRow label="SMA 50"  value={`$${tech.sma50.toFixed(2)} (${tech.cur > tech.sma50 ? "above ✓" : "below ✗"})`}  color={tech.cur > tech.sma50 ? T.green : T.red} mono />}
                {tech.sma200 && <TechRow label="SMA 200" value={`$${tech.sma200.toFixed(2)} (${tech.cur > tech.sma200 ? "bull ✓" : "bear ✗"})`} color={tech.cur > tech.sma200 ? T.green : T.red} mono />}
                {tech.bb && <TechRow label="Bollinger Mid" value={`$${tech.bb.middle.toFixed(2)} ±${(tech.bb.std).toFixed(2)}`} mono />}
                {tech.ch30 !== null && <TechRow label="30-day return" value={`${tech.ch30 >= 0 ? "+" : ""}${tech.ch30.toFixed(2)}%`} color={tech.ch30 >= 0 ? T.green : T.red} />}
                {tech.ch90 !== null && <TechRow label="90-day return" value={`${tech.ch90 >= 0 ? "+" : ""}${tech.ch90.toFixed(2)}%`} color={tech.ch90 >= 0 ? T.green : T.red} />}
              </div>
              {tech.patterns.length > 0 && (
                <div style={{ marginTop: 14 }}>
                  <div style={{ fontSize: 10, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Patterns Detected</div>
                  {tech.patterns.map((p, i) => <PatternCard key={i} pattern={p} />)}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function AnalystCard({ symbol, rec }) {
  if (!rec) return null;
  const c = rec.consensus === "BUY" ? T.green : rec.consensus === "SELL" ? T.red : T.gold;
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
      {/* Bar */}
      <div style={{ height: 6, borderRadius: 100, display: "flex", overflow: "hidden", marginBottom: 10 }}>
        <div style={{ width: bullW, background: T.green, transition: "width 0.6s ease" }} />
        <div style={{ width: holdW, background: T.gold, transition: "width 0.6s ease" }} />
        <div style={{ width: bearW, background: T.red, transition: "width 0.6s ease" }} />
      </div>
      <div style={{ display: "flex", gap: 12 }}>
        {[["Strong Buy", rec.strongBuy, T.green], ["Buy", rec.buy, "#60d394"], ["Hold", rec.hold, T.gold], ["Sell", rec.sell, "#ff8a7a"], ["Strong Sell", rec.strongSell, T.red]].map(([l, v, col]) => (
          <div key={l} style={{ textAlign: "center" }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: col, fontVariantNumeric: "tabular-nums" }}>{v}</div>
            <div style={{ fontSize: 9, color: T.textMuted, marginTop: 2 }}>{l.replace(" ", "\n")}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function WeeklyReport({ onClose }) {
  const r = LearningAgent.generateReport();
  return (
    <div style={{ position: "absolute", inset: 0, zIndex: 60, background: "rgba(0,0,0,0.6)", backdropFilter: T.glass, WebkitBackdropFilter: T.glass, display: "flex", flexDirection: "column", animation: "fadeUp 0.35s cubic-bezier(0.25,0.46,0.45,0.94)" }}>
      <div style={{ flex: 1, display: "flex", flexDirection: "column", background: "#111114", borderRadius: `${T.radius.lg}px ${T.radius.lg}px 0 0`, marginTop: 44, overflow: "hidden" }}>
        <div style={{ padding: "16px 20px", borderBottom: `0.5px solid ${T.sep}`, display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0 }}>
          <div>
            <div style={{ fontSize: 17, fontWeight: 600, color: T.text }}>Weekly Report</div>
            <div style={{ fontSize: 12, color: T.textMuted, marginTop: 1 }}>{r.period}</div>
          </div>
          <button onClick={onClose} style={{ background: "rgba(255,255,255,0.08)", border: `0.5px solid ${T.border}`, borderRadius: T.radius.pill, padding: "6px 16px", color: T.textSub, cursor: "pointer", fontSize: 14, fontFamily: T.font }}>Done</button>
        </div>
        <div style={{ flex: 1, overflowY: "auto", padding: "20px 16px" }}>

          {/* Signal Accuracy */}
          {r.accuracy && (
            <>
              <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8, paddingLeft: 4 }}>Signal Accuracy</div>
              <div style={{ background: r.accuracy.accuracy >= 60 ? T.greenDim : T.redDim, border: `0.5px solid ${r.accuracy.accuracy >= 60 ? T.greenBorder : T.redBorder}`, borderRadius: T.radius.md, padding: 16, marginBottom: 20, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <div style={{ fontSize: 32, fontWeight: 700, color: r.accuracy.accuracy >= 60 ? T.green : T.red, fontVariantNumeric: "tabular-nums" }}>{r.accuracy.accuracy}%</div>
                  <div style={{ fontSize: 12, color: T.textSub, marginTop: 2 }}>{r.accuracy.correct} correct of {r.accuracy.total} evaluated signals</div>
                </div>
                <div style={{ fontSize: 40 }}>{r.accuracy.accuracy >= 70 ? "🎯" : r.accuracy.accuracy >= 50 ? "📊" : "📉"}</div>
              </div>
            </>
          )}

          {/* Profile */}
          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8, paddingLeft: 4 }}>Your Profile</div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, overflow: "hidden", marginBottom: 20 }}>
            {[["Monthly Budget", USER_PROFILE.budgetRange, T.gold], ["Risk Level", "Medium", T.gold], ["Strategy", "Index-first", T.gold], ["Core Split", "60% VOO / 30% QQQ / 10% cash", T.gold]].map(([k, v, c], i, arr) => (
              <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "12px 16px", borderBottom: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none", alignItems: "center" }}>
                <span style={{ fontSize: 14, color: T.textSub }}>{k}</span>
                <span style={{ fontSize: 14, fontWeight: 500, color: c }}>{v}</span>
              </div>
            ))}
          </div>

          {/* Usage */}
          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8, paddingLeft: 4 }}>This Week</div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, overflow: "hidden", marginBottom: 20 }}>
            {[["Sessions", r.totalSessions, T.green], ["Messages", r.totalMessages, T.green], ["Avg / Session", r.totalSessions > 0 ? (r.totalMessages / r.totalSessions).toFixed(1) : 0, T.green]].map(([k, v, c], i, arr) => (
              <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "12px 16px", borderBottom: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none", alignItems: "center" }}>
                <span style={{ fontSize: 14, color: T.textSub }}>{k}</span>
                <span style={{ fontSize: 14, fontWeight: 600, color: c, fontVariantNumeric: "tabular-nums" }}>{v}</span>
              </div>
            ))}
          </div>

          {/* Topics */}
          {r.topTopics.length > 0 && (
            <>
              <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8, paddingLeft: 4 }}>Top Topics</div>
              <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, overflow: "hidden", marginBottom: 20 }}>
                {r.topTopics.map(([topic, count], i, arr) => (
                  <div key={topic} style={{ padding: "12px 16px", borderBottom: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                      <span style={{ fontSize: 14, color: T.textSub }}>{topic}</span>
                      <span style={{ fontSize: 13, color: T.textMuted, fontVariantNumeric: "tabular-nums" }}>{count}</span>
                    </div>
                    <div style={{ height: 3, background: "rgba(255,255,255,0.06)", borderRadius: 100 }}>
                      <div style={{ width: `${(count / (r.topTopics[0]?.[1] || 1)) * 100}%`, height: "100%", background: T.gold, borderRadius: 100 }} />
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}

          {/* Security */}
          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8, paddingLeft: 4 }}>Security</div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, overflow: "hidden", marginBottom: 32 }}>
            {[["Threats Blocked", r.securityThreats, r.securityThreats > 0 ? T.red : T.green], ["API Calls Made", r.apiCalls, T.gold], ["Errors", r.errors, r.errors > 0 ? T.red : T.green], ["Session", r.sessionId, T.textMuted]].map(([k, v, c], i, arr) => (
              <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "12px 16px", borderBottom: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none", alignItems: "center" }}>
                <span style={{ fontSize: 14, color: T.textSub }}>{k}</span>
                <span style={{ fontSize: 13, fontWeight: 500, color: c, fontVariantNumeric: "tabular-nums" }}>{v}</span>
              </div>
            ))}
          </div>
          <div style={{ textAlign: "center", fontSize: 11, color: T.textMuted, marginBottom: 8 }}>Educational use only · Not financial advice</div>
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
    content: "ATLAS online. All systems active.\n\nLoading live prices + 200 days of historical data + technical indicators + Wall Street analyst consensus…\n\nOnce data loads, I'll surface multi-factor buy/sell signals based on RSI, MACD, moving averages, Bollinger Bands, and pattern recognition.\n\nWhat do you want to know?",
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
          NotificationSystem.send(a.title, a.body, "sell"); newAlerts.push(a);
        } else if (sig.signal === "BUY" && sig.strength >= 65) {
          const a = { type: "buy", title: `Buy Signal — ${sig.symbol} (${sig.strength}%)`, body: sig.reason };
          NotificationSystem.send(a.title, a.body, "buy"); newAlerts.push(a);
        }
      });
      if (newAlerts.length > 0) setAlerts(prev => [...newAlerts, ...prev].slice(0, 5));
    }
  }, []);

  const fetchMarket = useCallback(async () => {
    setMarketLoading(true);
    setAgentActive(s => ({ ...s, market: true }));

    // Phase 1 — quotes render immediately (~300ms)
    const base = await MarketAgent.getQuotes();
    setMarketData(base);
    setMarketLoading(false);
    setAgentActive(s => ({ ...s, market: false }));
    handleAlerts(base);

    // Phase 2 — technicals load in background (2-5s via CORS proxy)
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
    const userText = SecurityAgent.sanitize(raw);
    setInput("");
    const newMessages = [...messages, { role: "user", content: userText }];
    setMessages(newMessages);
    setLoading(true);
    setAgentActive(s => ({ ...s, intel: true }));
    setMessages(prev => [...prev, { role: "assistant", content: "", typing: true }]);

    try {
      SecurityAgent.logEvent("API_CALL", "Chat");
      const snapshot = MarketAgent.formatForAI(marketData);
      const apiMsgs = newMessages.map(m => ({ role: m.role, content: m.content }));
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": getApiKey(), "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" },
        body: JSON.stringify({ model: "claude-sonnet-4-20250514", max_tokens: 1200, system: buildPrompt(snapshot), tools: [{ type: "web_search_20250305", name: "web_search" }], messages: apiMsgs }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error.message);

      let finalText = "";
      if (data.content?.some(b => b.type === "tool_use")) {
        setMessages(prev => { const u = [...prev]; u[u.length - 1] = { role: "assistant", content: "Searching live data…", searching: true }; return u; });
        const res2 = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-api-key": getApiKey(), "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" },
          body: JSON.stringify({ model: "claude-sonnet-4-20250514", max_tokens: 1200, system: buildPrompt(snapshot), tools: [{ type: "web_search_20250305", name: "web_search" }], messages: [...apiMsgs, { role: "assistant", content: data.content }] }),
        });
        const d2 = await res2.json();
        finalText = (d2.content || []).filter(b => b.type === "text").map(b => b.text).join("");
      } else {
        finalText = (data.content || []).filter(b => b.type === "text").map(b => b.text).join("");
      }

      const lower = finalText.toLowerCase();
      if (lower.includes("sell") && lower.includes("recommend")) {
        const a = { type: "sell", title: "ATLAS recommends a sell", body: finalText.slice(0, 130) + "…" };
        NotificationSystem.send(a.title, a.body, "sell"); setAlerts(prev => [a, ...prev].slice(0, 5));
      } else if (lower.includes("strong buy") || (lower.includes("buy") && lower.includes("opportunity"))) {
        const a = { type: "buy", title: "ATLAS identified a buy opportunity", body: finalText.slice(0, 130) + "…" };
        NotificationSystem.send(a.title, a.body, "buy"); setAlerts(prev => [a, ...prev].slice(0, 5));
      }

      LearningAgent.logSession([...newMessages, { role: "assistant", content: finalText }]);
      setMessages(prev => { const u = [...prev]; u[u.length - 1] = { role: "assistant", content: finalText || "No response." }; return u; });
    } catch (err) {
      SecurityAgent.logEvent("ERROR", err.message);
      setMessages(prev => { const u = [...prev]; u[u.length - 1] = { role: "assistant", content: !getApiKey() ? "Add VITE_ANTHROPIC_KEY to Secrets to activate ATLAS." : `Error: ${err.message}` }; return u; });
    }
    setLoading(false);
    setAgentActive(s => ({ ...s, intel: false }));
  }, [input, loading, messages, marketData]);

  const quickPrompts = ["What's the strongest buy signal right now?", "RSI analysis for SPY?", "Golden cross or death cross?", "Build my $200/month plan", "Should I hold or sell today?"];
  const TABS = ["chat", "market", "plan"];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", background: T.bg, fontFamily: T.font, overflow: "hidden", color: T.text }}>
      <style>{`
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        @keyframes pulse{0%,100%{opacity:.35;transform:scale(.8)}50%{opacity:1;transform:scale(1)}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
        @keyframes fadeUp{from{opacity:0;transform:translateY(30px)}to{opacity:1;transform:translateY(0)}}
        @keyframes slideDown{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
        @keyframes blink{0%,100%{opacity:.3}50%{opacity:1}}
        ::-webkit-scrollbar{width:0}
        textarea{resize:none}
        textarea::placeholder{color:rgba(235,235,245,0.25)}
        button{font-family:inherit}
      `}</style>

      {showReport && <WeeklyReport onClose={() => setShowReport(false)} />}

      {/* ── NAV BAR ── */}
      <div style={{ padding: "12px 16px 10px", borderBottom: `0.5px solid ${T.sep}`, background: "rgba(0,0,0,0.72)", backdropFilter: T.glass, WebkitBackdropFilter: T.glass, zIndex: 20, flexShrink: 0, display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9, flex: 1 }}>
          <div style={{ width: 32, height: 32, borderRadius: 9, background: `linear-gradient(145deg, ${T.gold}, #8b5e12)`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 700, color: "#000", boxShadow: `0 0 0 0.5px rgba(255,255,255,0.1), 0 4px 12px rgba(212,168,83,0.3)`, flexShrink: 0 }}>A</div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600, color: T.text, letterSpacing: "-0.01em" }}>ATLAS</div>
            <div style={{ fontSize: 10, color: T.textMuted }}>Financial Intelligence</div>
          </div>
        </div>
        <div style={{ display: "flex", background: "rgba(118,118,128,0.18)", borderRadius: T.radius.sm, padding: 2, gap: 1 }}>
          {TABS.map(t => (
            <button key={t} onClick={() => setTab(t)} style={{ padding: "5px 12px", borderRadius: T.radius.xs, fontSize: 12, fontWeight: tab === t ? 600 : 400, color: tab === t ? T.text : T.textMuted, background: tab === t ? "rgba(255,255,255,0.14)" : "transparent", border: "none", cursor: "pointer", boxShadow: tab === t ? "0 1px 4px rgba(0,0,0,0.5)" : "none", transition: "all 0.18s ease", textTransform: "capitalize" }}>{t}</button>
          ))}
        </div>
        <button onClick={() => setShowReport(true)} style={{ background: "rgba(255,255,255,0.06)", border: `0.5px solid ${T.border}`, borderRadius: T.radius.xs, padding: "5px 10px", color: T.textMuted, cursor: "pointer", fontSize: 11 }}>Report</button>
      </div>

      {/* ── STATUS ROW ── */}
      <div style={{ display: "flex", gap: 6, padding: "6px 16px", background: "rgba(0,0,0,0.5)", backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)", borderBottom: `0.5px solid ${T.sep}`, flexShrink: 0, overflowX: "auto" }}>
        {[
          { label: "Intelligence", color: T.gold,   active: agentActive.intel },
          { label: "Market Feed",  color: T.green,  active: agentActive.market || marketLoading },
          { label: "Technicals",   color: T.indigo, active: !!(marketData?.technicals?.SPY) },
          { label: "Security",     color: "#8E9CF0", active: true },
          { label: notifGranted ? "Alerts On" : "Enable Alerts", color: notifGranted ? T.green : T.red, active: notifGranted, onClick: !notifGranted ? () => NotificationSystem.requestPermission().then(setNotifGranted) : undefined },
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
                      {[0, 1, 2].map(j => <div key={j} style={{ width: 6, height: 6, borderRadius: "50%", background: T.gold, animation: `pulse 1.4s ease ${j * 0.18}s infinite` }} />)}
                    </div>
                  ) : (
                    <div style={{ maxWidth: "80%", padding: "11px 14px", borderRadius: isUser ? "16px 16px 4px 16px" : i === 0 ? "16px 16px 16px 4px" : "4px 16px 16px 16px", background: isUser ? T.goldDim : T.card, border: `0.5px solid ${isUser ? T.goldBorder : T.border}`, boxShadow: "0 1px 6px rgba(0,0,0,0.25)", fontSize: 14, lineHeight: 1.65, color: T.text, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                      {msg.content}
                      {msg.searching && <div style={{ marginTop: 6, display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: T.gold, animation: "blink 1.2s ease infinite" }}><div style={{ width: 5, height: 5, borderRadius: "50%", background: T.gold }} />Searching live data…</div>}
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
                <button key={p} onClick={() => sendMessage(p)} style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.pill, padding: "7px 14px", color: T.textSub, fontSize: 12, fontWeight: 500, cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0, transition: "all 0.18s ease" }}>{p}</button>
              ))}
            </div>
          )}

          <div style={{ padding: "10px 16px 22px", borderTop: `0.5px solid ${T.sep}`, background: "rgba(0,0,0,0.6)", backdropFilter: "blur(30px)", WebkitBackdropFilter: "blur(30px)", flexShrink: 0 }}>
            <div style={{ display: "flex", gap: 10, alignItems: "flex-end", background: "rgba(28,28,30,0.9)", border: `0.5px solid ${T.borderStrong}`, borderRadius: 20, padding: "10px 10px 10px 16px", boxShadow: "0 2px 12px rgba(0,0,0,0.3)" }}>
              <textarea ref={inputRef} value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } }} placeholder="Ask about signals, RSI, patterns, your portfolio…" rows={1} style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: T.text, fontSize: 14, fontFamily: T.font, lineHeight: 1.5, maxHeight: 100, overflowY: "auto" }} onInput={e => { e.target.style.height = "auto"; e.target.style.height = Math.min(e.target.scrollHeight, 100) + "px"; }} />
              <button onClick={() => sendMessage()} disabled={loading || !input.trim()} style={{ width: 34, height: 34, borderRadius: "50%", border: "none", background: !loading && input.trim() ? `linear-gradient(145deg, ${T.gold}, #8b5e12)` : "rgba(255,255,255,0.07)", cursor: !loading && input.trim() ? "pointer" : "not-allowed", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, transition: "all 0.2s ease", boxShadow: !loading && input.trim() ? "0 2px 10px rgba(212,168,83,0.35)" : "none" }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={!loading && input.trim() ? "#000" : "rgba(255,255,255,0.25)"} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" /></svg>
              </button>
            </div>
            <div style={{ textAlign: "center", fontSize: 10, color: "rgba(255,255,255,0.12)", marginTop: 6 }}>Educational use only · Not financial advice</div>
          </div>
        </>
      )}

      {/* ── MARKET TAB ── */}
      {tab === "market" && (
        <div style={{ flex: 1, overflowY: "auto", padding: "16px 16px 32px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
            <span style={{ fontSize: 11, color: T.textMuted }}>{marketData ? `Updated ${marketData.fetchedAt?.toLocaleTimeString()}` : "Loading…"}</span>
            <button onClick={fetchMarket} style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.xs, padding: "4px 10px", color: T.gold, cursor: "pointer", fontSize: 11, fontWeight: 500 }}>↻ Refresh</button>
          </div>

          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Indices & ETFs</div>
          {[
            { label: "S&P 500 — SPY", q: marketData?.spy, sig: marketData?.signals?.find(s => s.symbol === "SPY"), tech: marketData?.technicals?.SPY },
            { label: "NASDAQ — QQQ", q: marketData?.qqq, sig: marketData?.signals?.find(s => s.symbol === "QQQ"), tech: marketData?.technicals?.QQQ },
            { label: "Vanguard S&P 500 — VOO", q: marketData?.voo, sig: marketData?.signals?.find(s => s.symbol === "VOO"), tech: marketData?.technicals?.VOO },
          ].map(item => <MarketCard key={item.label} label={item.label} quote={item.q} signal={item.sig} tech={item.tech} />)}

          {/* Analyst Consensus */}
          {marketData?.recommendations && Object.values(marketData.recommendations).some(Boolean) && (
            <>
              <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", margin: "16px 0 8px" }}>Wall Street Consensus</div>
              {Object.entries(marketData.recommendations).map(([sym, rec]) => <AnalystCard key={sym} symbol={sym} rec={rec} />)}
            </>
          )}

          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", margin: "16px 0 8px" }}>Crypto</div>
          {[
            { label: "Bitcoin", q: marketData?.btc, tech: marketData?.technicals?.BTC },
            { label: "Ethereum", q: marketData?.eth, tech: marketData?.technicals?.ETH },
          ].map(item => <MarketCard key={item.label} label={item.label} quote={item.q} tech={item.tech} isCrypto />)}

          {marketData?.news?.length > 0 && (
            <>
              <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", margin: "16px 0 8px" }}>Headlines</div>
              {marketData.news.map((n, i) => (
                <div key={i} style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: "12px 14px", marginBottom: 8 }}>
                  <div style={{ fontSize: 13, color: T.text, lineHeight: 1.5, marginBottom: 5 }}>{n.headline}</div>
                  <div style={{ fontSize: 11, color: T.textMuted }}>{n.source} · {new Date(n.datetime * 1000).toLocaleDateString()}</div>
                </div>
              ))}
            </>
          )}
        </div>
      )}

      {/* ── PLAN TAB ── */}
      {tab === "plan" && (
        <div style={{ flex: 1, overflowY: "auto", padding: "16px 16px 40px" }}>
          <div style={{ background: `linear-gradient(145deg, rgba(212,168,83,0.12), rgba(212,168,83,0.04))`, border: `0.5px solid ${T.goldBorder}`, borderRadius: T.radius.lg, padding: 20, marginBottom: 20, boxShadow: "0 4px 24px rgba(212,168,83,0.08)" }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: T.gold, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>Your Investment Plan</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: T.text, marginBottom: 8, letterSpacing: "-0.01em" }}>{recommendation.pick}</div>
            <div style={{ fontSize: 13, color: T.textSub, lineHeight: 1.6, marginBottom: 16 }}>{recommendation.rationale}</div>
            <div style={{ background: "rgba(0,0,0,0.3)", borderRadius: T.radius.sm, padding: "12px 14px" }}>
              <div style={{ fontSize: 10, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Monthly Breakdown</div>
              <div style={{ fontSize: 13, color: T.gold, lineHeight: 1.9, fontVariantNumeric: "tabular-nums" }}>{recommendation.monthlyPlan}</div>
            </div>
          </div>

          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Allocation</div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, padding: "14px 16px", marginBottom: 20 }}>
            {recommendation.allocation.split(", ").map((item, i) => {
              const [pct, ...rest] = item.split(" "); const num = parseInt(pct);
              const colors = [T.gold, T.indigo, T.green];
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

          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>Strategy</div>
          <div style={{ background: T.greenDim, border: `0.5px solid ${T.greenBorder}`, borderRadius: T.radius.md, padding: 16, marginBottom: 20 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: T.green, marginBottom: 8 }}>Dollar-Cost Averaging</div>
            <div style={{ fontSize: 13, color: T.textSub, lineHeight: 1.6, marginBottom: 12 }}>Invest your $100–$300 on the same day every month — regardless of market conditions. This removes emotion from investing and builds wealth steadily over time. Don't try to time the market.</div>
            <div style={{ background: "rgba(0,0,0,0.25)", borderRadius: T.radius.xs, padding: "8px 12px", fontSize: 12, color: T.green, fontWeight: 500 }}>Set a recurring buy on the 1st of each month</div>
          </div>

          <div style={{ fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 8 }}>When To Sell</div>
          <div style={{ background: T.card, border: `0.5px solid ${T.border}`, borderRadius: T.radius.md, overflow: "hidden" }}>
            {["A position is up 20%+ and RSI is overbought (>70)", "You need the money within 12 months — don't keep it invested", "Fundamental news changes (scandal, index delisting, earnings collapse)", "ATLAS fires a SELL signal with 70%+ confidence backed by multiple indicators"].map((rule, i, arr) => (
              <div key={i} style={{ display: "flex", gap: 12, padding: "13px 16px", borderBottom: i < arr.length - 1 ? `0.5px solid ${T.sep}` : "none", alignItems: "flex-start" }}>
                <div style={{ width: 20, height: 20, borderRadius: 6, flexShrink: 0, background: T.redDim, border: `0.5px solid ${T.redBorder}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, color: T.red, marginTop: 1 }}>{i + 1}</div>
                <div style={{ fontSize: 13, color: T.textSub, lineHeight: 1.55 }}>{rule}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
