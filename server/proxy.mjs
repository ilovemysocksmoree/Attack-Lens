// AttackLens local dev backend — proxies /api/llm to Anthropic.
// Storage is now handled in the browser via localStorage, so this server
// only exists to keep your API key off the client during local development.
//
// Required: a .env file at the project root containing:
//   ANTHROPIC_API_KEY=sk-ant-...

import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function loadEnv() {
  try {
    const text = await fs.readFile(path.join(__dirname, "..", ".env"), "utf8");
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq < 0) continue;
      const k = trimmed.slice(0, eq).trim();
      let v = trimmed.slice(eq + 1).trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1);
      }
      if (!(k in process.env)) process.env[k] = v;
    }
  } catch (e) {
    if (e.code !== "ENOENT") console.warn("⚠ Could not read .env:", e.message);
  }
}
await loadEnv();

const PORT = process.env.ATTACKLENS_PORT || 8787;
const API_KEY = process.env.ANTHROPIC_API_KEY;

if (!API_KEY) {
  console.warn("⚠ ANTHROPIC_API_KEY is not set. Create a .env file at the project root with:\n   ANTHROPIC_API_KEY=sk-ant-...");
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", c => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function send(res, status, body, contentType = "application/json") {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") return send(res, 204, "");

  try {
    const url = new URL(req.url, `http://localhost:${PORT}`);

    if (url.pathname === "/api/llm" && req.method === "POST") {
      if (!API_KEY) return send(res, 500, { error: "ANTHROPIC_API_KEY not configured on server" });
      const body = await readBody(req);
      const upstream = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": API_KEY,
          "anthropic-version": "2023-06-01",
        },
        body,
      });
      const text = await upstream.text();
      return send(res, upstream.status, text, upstream.headers.get("content-type") || "application/json");
    }

    return send(res, 404, { error: "Not found" });
  } catch (e) {
    console.error("Server error:", e);
    send(res, 500, { error: String(e?.message || e) });
  }
});

server.listen(PORT, () => {
  console.log(`✓ AttackLens local LLM proxy running on http://localhost:${PORT}`);
  if (!API_KEY) console.log(`  ⚠ Add ANTHROPIC_API_KEY to .env to enable analysis.`);
});
