# Frontend Guide — Next.js Static Export
# =============================================================================
# Purpose: Next.js frontend with output: 'export' (static site).
#          Served by FastAPI at / in production (port 8000).
# =============================================================================

- API base URL is in `src/app/lib/api.ts`. Change `API_BASE` for a different backend host/port.
- All API URLs use the `apiUrl()` helper from that module.
- This is a static export (`output: 'export'`), served by FastAPI at `/` on port 8000.
- `npm start` just serves the static export on port 3000 (no rebuild).
- For dev: `npm run dev` on port 3000 + FastAPI on port 8000 (CORS enabled).
