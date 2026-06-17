// =============================================================================
// API Configuration — Single source for backend URL
// =============================================================================
// Change API_BASE if the FastAPI backend is on a different host/port.
// All API calls in the frontend use the apiUrl() helper from this module.
// =============================================================================

export const API_BASE = "http://localhost:8000";

export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}
