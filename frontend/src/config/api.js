/**
 * VulnTwin AI - Enterprise API Configuration & Service Gateway
 * Handles seamless hybrid routing between local FastAPI instance and HTTPS cloud tunnels.
 */

export const DEFAULT_LOCAL_API = 'http://127.0.0.1:8001';
export const DEFAULT_LIVE_TUNNEL_API = 'https://vulntwin-api.loca.lt';

export function resolveApiBase() {
  if (typeof window === 'undefined') {
    return DEFAULT_LOCAL_API;
  }

  // 1. Manual user override stored in localStorage
  const saved = window.localStorage.getItem('vulntwin_api_base');
  if (saved && saved.trim().length > 0) {
    return saved.trim().replace(/\/+$/, '');
  }

  // 2. Build-time Vite environment variable
  if (import.meta.env?.VITE_API_BASE) {
    return import.meta.env.VITE_API_BASE.trim().replace(/\/+$/, '');
  }

  // 3. Protocol-aware default: Use HTTPS tunnel on live domains (prevents browser Mixed Content blocks)
  if (window.location.protocol === 'https:' || window.location.hostname.includes('web.app') || window.location.hostname.includes('firebaseapp.com')) {
    return DEFAULT_LIVE_TUNNEL_API;
  }

  // 4. Default to local backend for local development
  return DEFAULT_LOCAL_API;
}

export let API_BASE = resolveApiBase();

export function setCustomApiBase(newUrl) {
  if (typeof window === 'undefined') return;
  
  if (newUrl && newUrl.trim().length > 0) {
    const cleaned = newUrl.trim().replace(/\/+$/, '');
    window.localStorage.setItem('vulntwin_api_base', cleaned);
    API_BASE = cleaned;
  } else {
    window.localStorage.removeItem('vulntwin_api_base');
    API_BASE = resolveApiBase();
  }

  // Dispatch custom event to notify components
  window.dispatchEvent(new CustomEvent('vulntwin:api-base-changed', { detail: { apiBase: API_BASE } }));
}

export function getApiBase() {
  return API_BASE;
}

/**
 * Health check helper for verifying connection to the backend
 */
export async function checkBackendHealth(targetUrl) {
  const base = (targetUrl || API_BASE).replace(/\/+$/, '');
  const startTime = Date.now();
  try {
    const res = await fetch(`${base}/health`, {
      method: 'GET',
      headers: {
        'Bypass-Tunnel-Reminder': 'true',
      },
    });
    const latencyMs = Date.now() - startTime;
    if (res.ok) {
      const data = await res.json();
      return { ok: true, latencyMs, data, url: base };
    }
    return { ok: false, error: `HTTP ${res.status}: ${res.statusText}`, latencyMs, url: base };
  } catch (err) {
    return { ok: false, error: err.message || 'Connection refused or unreachable', latencyMs: Date.now() - startTime, url: base };
  }
}

// Global fetch wrapper to ensure Bypass-Tunnel-Reminder header is consistently sent for tunnels
if (typeof window !== 'undefined' && window.fetch) {
  const originalFetch = window.fetch.bind(window);
  window.fetch = async function(resource, init = {}) {
    const headers = new Headers(init.headers || {});
    if (!headers.has('Bypass-Tunnel-Reminder')) {
      headers.set('Bypass-Tunnel-Reminder', 'true');
    }
    return originalFetch(resource, { ...init, headers });
  };
}
