export const API_BASE = "http://localhost:8000";

export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}
