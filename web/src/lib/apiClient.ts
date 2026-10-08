const API_BASE_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8001/api/v1";

export async function fetchDashboardTelemetry() {
  try {
    const res = await fetch(`${API_BASE_URL}/dashboard`);
    if (!res.ok) throw new Error("Backend unreachable");
    return await res.json();
  } catch (error) {
    console.error(error);
    return { error: "Backend unreachable", analyses: [], system_events: [] };
  }
}

export async function runThreatScan(url: string) {
  try {
    const res = await fetch(`${API_BASE_URL}/scan/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error("Backend unreachable");
    return await res.json();
  } catch (error) {
    console.error(error);
    return { error: "Backend unreachable", risk_score: 0, verdict: "SAFE" };
  }
}

export async function getAiRemediation(vulnerability: string, context: string) {
  try {
    const res = await fetch(`${API_BASE_URL}/remediation/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vulnerability, context }),
    });
    if (!res.ok) throw new Error("Backend unreachable");
    return await res.json();
  } catch (error) {
    console.error(error);
    return { error: "Backend unreachable", patch: "# Fallback: Isolate network segment manually.", source: "fallback" };
  }
}
