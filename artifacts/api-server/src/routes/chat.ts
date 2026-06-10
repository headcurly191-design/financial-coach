import { Router } from "express";
import { GoogleGenerativeAI } from "@google/generative-ai";

const router = Router();

router.post("/chat", async (req, res) => {
  const { messages, systemPrompt } = req.body;

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    res.status(500).json({ error: "GEMINI_API_KEY not configured on server." });
    return;
  }
  if (!Array.isArray(messages) || messages.length === 0) {
    res.status(400).json({ error: "messages array is required." });
    return;
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({
      model: "gemini-2.5-flash",
      systemInstruction: systemPrompt || "",
    });

    const historyRaw = messages.slice(0, -1).map((m: any) => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: String(m.content || "") }],
    }));
    // Gemini requires history to start with a "user" turn — drop any leading model messages
    let startIdx = 0;
    while (startIdx < historyRaw.length && historyRaw[startIdx].role !== "user") {
      startIdx++;
    }
    const history = historyRaw.slice(startIdx);

    const lastMessage = messages[messages.length - 1];

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    const chat = model.startChat({ history });
    const stream = await chat.sendMessageStream(String(lastMessage.content || ""));

    for await (const chunk of stream) {
      const text = chunk.text();
      if (text) {
        res.write(`data: ${JSON.stringify({ content: text })}\n\n`);
      }
    }

    res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    res.end();
  } catch (err: any) {
    if (!res.headersSent) {
      res.status(500).json({ error: err.message });
    } else {
      res.write(`data: ${JSON.stringify({ error: err.message, done: true })}\n\n`);
      res.end();
    }
  }
});

export default router;
