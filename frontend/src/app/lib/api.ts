export const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

export async function fetcher<T = unknown>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${res.statusText}`);
  }
  return res.json();
}
