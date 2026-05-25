// Netlify serverless function: proxies /api/llm to Anthropic.
// Keeps the API key on the server side (never exposed to the browser).
//
// Required env var: ANTHROPIC_API_KEY
//   Set in Netlify UI: Site settings → Environment variables → Add a variable

export default async (request) => {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }
  if (request.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  const apiKey = Netlify.env.get("ANTHROPIC_API_KEY") || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return json({
      error: "ANTHROPIC_API_KEY is not configured. In Netlify: Site settings → Environment variables → Add ANTHROPIC_API_KEY."
    }, 500);
  }

  let body;
  try {
    body = await request.text();
  } catch (e) {
    return json({ error: "Could not read request body" }, 400);
  }

  try {
    const upstream = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body,
    });

    const text = await upstream.text();
    return new Response(text, {
      status: upstream.status,
      headers: {
        "Content-Type": upstream.headers.get("content-type") || "application/json",
        ...corsHeaders(),
      },
    });
  } catch (e) {
    return json({ error: "Upstream fetch failed: " + (e?.message || String(e)) }, 502);
  }
};

export const config = {
  path: "/api/llm",
};

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}
