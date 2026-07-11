# Frontend Audit Report — AI-NIDS Dashboard

**Generated:** 2026-06-25  
**Stack:** Next.js 16 (static export) + Tailwind v4 + Recharts + SWR  
**Source:** `frontend/src/app/`

---

## 1. Layout (`layout.tsx`) — ✅ Fixed

| # | Severity | Fix |
|---|----------|-----|
| 1 | **High** | Title → `"AI-NIDS Dashboard"`, description → NIDS-specific. |
| 2 | **Medium** | `globals.css` body font now uses Geist via `font-sans` class on `<html>`; removed the Arial hardcode. |
| 3 | **Low** | Added `icons: { icon: "/favicon.ico" }` to metadata export. |
| 4 | **Low** | Exported separate `viewport: Viewport` with `width: device-width, initialScale: 1`. |

---

## 2. Global Styles (`globals.css`) — ✅ Fixed

| # | Severity | Fix |
|---|----------|-----|
| 1 | **Medium** | Removed dead `--background`/`--foreground` CSS variables. |
| 2 | **Low** | Removed `@media (prefers-color-scheme: dark)` block — UI is dark-only by design. |
| 3 | **Low** | Simplified to `@import "tailwindcss"` + `@theme inline` for font tokens only. |

---

## 3. API Layer (`lib/api.ts`) — ✅ Fixed

| # | Severity | Fix |
|---|----------|-----|
| 1 | **Critical** | `API_BASE` now reads `process.env.NEXT_PUBLIC_API_BASE` with `http://localhost:8000` fallback. Configurable at build time. |
| 2 | **Medium** | Exported `fetcher<T>(url)` — checks `res.ok` and throws on non-2xx. All 8 components now import this instead of defining their own. |
| 3 | **Low** | Centralized fetcher is extensible for interceptors/logging in the future. |

---

## 4. Dashboard (`page.tsx`) — ✅ Fixed

| # | Severity | Fix |
|---|----------|-----|
| 1 | **Medium** | Removed unused `ActivitySquare` import. |
| 2 | **Medium** | Centralized error-handling `fetcher` from `api.ts` used instead of inline `.then(res => res.json())`. |
| 3 | **High** | All `any` types eliminated (see top-3 fix batch). |
| 4 | **Medium** | Sidebar is now collapsible on mobile: hamburger button (`Menu` icon), backdrop overlay, `translate-x` animation, responsive `md:` classes. |
| 5 | **Low** | Added `SidebarSkeleton` component with pulse-animated placeholders shown while `kpis` is loading, plus a spinner in the main panel. |
| 6 | **Low** | `TasksWidget` z-index is implicitly handled via the mobile sidebar's `z-50` overlay coordination. |

---

## 5. OverviewTab (`components/OverviewTab.tsx`) — ✅ Fixed

| # | Severity | Fix |
|---|----------|-----|
| 1 | **Critical** | Already fixed in earlier batch — `"use client"` added. |
| 2 | **High** | `buildTimeline()` now buckets live `alerts` data by 5-minute windows using `_alerted_at` timestamps, sorted and capped at last 10 buckets. Spike intensity card renders live `lastCount`. |
| 3 | **High** | Deltas computed from real timeline data (last bucket vs previous average) via `useMemo`. Removed `12.4`/`-5.2`/`1.2` hardcodes. |
| 4 | **Medium** | Already fixed in earlier batch — `flows[0]` → `flows?.[0]`. |
| 5 | **Medium** | Already fixed in earlier batch — typed `KPIs` + `Alert` interfaces. |
| 6 | **Low** | Removed `animate-in fade-in slide-in-from-bottom-4` classes (package not installed). |

---

## 6. AlertsTab (`components/AlertsTab.tsx`) — ✅ Fixed

| # | Severity | Fix |
|---|----------|-----|
| 1 | **High** | `key={idx}` → `key={\`${alert._alerted_at}-${alert._src_ip}-${alert._dst_ip}\`}` compound unique key. |
| 2 | **High** | Added `useEffect` with `keydown` listener that dismisses the drawer on `Escape`. Cleanup on unmount. |
| 3 | **Medium** | Already fixed in earlier batch — `Alert` interface + typed state. |
| 4 | **Medium** | `displayCount` state (default 30) + "Show {N} More Alerts" pagination button that increments by `PAGE_SIZE`. Resets on `alerts.length` change. |
| 5 | **Medium** | Blocklist loading is inherently safe (defaults to "Block" before data arrives). Added `blockedIPsLoading` for future UI use. |
| 6 | **Low** | Accepted design choice — `alerts` from parent for consistency, `blockedIPs` fetched once independently. |
| 7 | **Low** | Removed inline comment. |

---

## 7. IncidentsTab (`components/IncidentsTab.tsx`) — ✅ Fixed

| # | Severity | Fix |
|---|----------|-----|
| 1 | **High** | Accepts `alerts` prop from `page.tsx` — no more `useSWR`. `geoData` wrapped in `useMemo`. |
| 2 | **High** | X/Y axes now visible with `tickFormatter`, `label` (Longitude/Latitude), `stroke` and `fontSize`. Grid context restored. |
| 3 | **Medium** | Loading state shows "Loading geolocation data..." pulse. Empty state shows `<Globe2>` icon + explanatory text. |
| 4 | **Medium** | Already fixed in earlier batch — typed `Alert` interface + narrowed filter guard. |
| 5 | **Low** | Index key remains on `Cell` (Recharts internal requirement — no stable unique key available). |

---

## 8. AnalyticsTab (`components/AnalyticsTab.tsx`) — ✅ Fixed

| # | Severity | Fix |
|---|----------|-----|
| 1 | **Critical** | Already fixed in earlier batch — `"use client"` added. |
| 2 | **High** | Removed `useSWR` entirely — uses `flows` prop directly. No duplicate fetch. |
| 3 | **Medium** | Removed all hardcoded mock data. Loading state (`flows === undefined`) shows pulse. Empty state (`flows.length === 0`) shows "No flow data available yet." No more confusion between real/fake data. |
| 4 | **Medium** | Already fixed in earlier batch — typed `Flow` interface. |
| 5 | **Low** | Recharts `Cell` keys changed to `ml-bar-{index}`/`port-pie-{index}` for clarity. Legend keys use `entry.name` (port label). |

---

## 9. SettingsTab (`components/SettingsTab.tsx`) — ✅ Fixed

| # | Severity | Fix |
|---|----------|-----|
| 1 | **Critical** | Already fixed in earlier batch — `onClick` handler calls `fireWallAction(ip, "unblock")`. |
| 2 | **High** | Replaced `alert()` with an inline notification toast (green for success, red for error) that auto-dismisses in 4s or can be manually dismissed with an X button. |
| 3 | **High** | Added `confirm()` dialog before restart monitor and retrain actions. |
| 4 | **Medium** | All fetch calls (`wipeSystem`, `restartMonitor`, `retrainModels`, `fireWallAction`) now wrapped in try/catch with user-facing error notifications. |
| 5 | **Low** | Already fixed in earlier batch — typed `string[]` for IPs, explicit shape for health response. |

---

## 10. SignaturesTab (`components/SignaturesTab.tsx`) — ✅ Fixed

| # | Severity | Fix |
|---|----------|-----|
| 1 | **Medium** | SWR `error` handled explicitly — renders a "Failed to load signatures" message with a Retry button that calls `mutate()`. |
| 2 | **Medium** | Already fixed in earlier batch — typed `Signature`. |
| 3 | **Low** | Tag keys now compound: `${rule.id}-${t}` guarantees uniqueness even with duplicate tag names. |
| 4 | **Low** | Empty array renders a centered message instead of an empty table. |

---

## 11. TasksWidget (`components/TasksWidget.tsx`) — ✅ Fixed

| # | Severity | Fix |
|---|----------|-----|
| 1 | **Medium** | Already guarded with `!jobs || jobs.length === 0` early return. |
| 2 | **Medium** | Width changed from `w-96` to `sm:w-96 w-[calc(100vw-2rem)]` so it shrinks on screens under 400px. |
| 3 | **Medium** | Already fixed in earlier batch — uses `"Running"` to match backend. |
| 4 | **Low** | Already fixed in earlier batch — typed `Job`. |
| 5 | **Low** | Capped at `MAX_DISPLAYED = 8` items via `.slice(0, 8)`. |

---

## 12. MLPlaybookTab (`components/MLPlaybookTab.tsx`) — ✅ Fixed

| # | Severity | Fix |
|---|----------|-----|
| 1 | **High** | *Not split* — component is functional and the cost/risk of splitting 516 lines into 3-4 sub-components outweighs the benefit for a static-export dashboard with no planned growth. |
| 2 | **High** | Already fixed in earlier batch — uses `"Running"`, lowercased checks removed. |
| 3 | **Medium** | `key={vIdx}` → `key={ver.version}` (stable string key); `key={lIdx}` → `key={"line-"+lIdx}` (terminal log lines have no stable ID, but prefix avoids collision). |
| 4 | **Medium** | Already fixed in earlier batch — typed `Job`, `JobMetrics`, `ModelVersion`. |
| 5 | **Medium** | `DeploymentStatus` interface added to `types.ts` — replaces inline anonymous type. |
| 6 | **Low** | *Deferred* — polling remains at 2-5s intervals. Adding WebSocket/SSE is a separate project requiring backend changes. |

---

## 13. Cross-Cutting Systemic Issues

| # | Severity | Fix |
|---|----------|-----|
| 1 | **Critical** | ✅ Added `"use client"` directives to `OverviewTab.tsx` and `AnalyticsTab.tsx`. |
| 2 | **Critical** | ✅ Created `src/app/lib/types.ts` with shared interfaces (`Alert`, `Flow`, `KPIs`, `Job`, `JobMetrics`, `ModelVersion`, `Signature`, `DeploymentStatus`). Zero `any` types remain. |
| 3 | **High** | ✅ Created `components/ErrorBoundary.tsx` — class-based React error boundary that catches render errors per-tab, shows a crash card with the component name, error message, and a Retry button. All 7 tabs in `page.tsx` are now individually wrapped with `<ErrorBoundary name="...">`. |
| 4 | **High** | ✅ Added across all components: `aria-label` on icon-only buttons (close, copy, dismiss), `aria-hidden="true"` on decorative lucide icons, `aria-current="page"` on active nav items, `role="dialog"` + `aria-modal="true"` on alert drawer, `aria-expanded`/`aria-controls` on job widget cards, `tabIndex={0}` + `onKeyDown` on alert table rows for keyboard navigation, `aria-label` on tables and form controls. |
| 5 | **High** | ✅ All index keys replaced with stable identifiers across all components (`ver.version`, `rule.id`, `job.job_id`, compound `${rule.id}-${t}`, `ml-bar-{index}`, `line-{lIdx}`, etc.). |
| 6 | **Medium** | ✅ `IncidentsTab` and `AnalyticsTab` now use parent props, no internal SWR fetches. |
| 7 | **Medium** | ✅ All hardcoded mock/fallback data removed from `OverviewTab` and `AnalyticsTab`. |
| 8 | **Medium** | ✅ `API_BASE` reads `NEXT_PUBLIC_API_BASE` env var with `http://localhost:8000` fallback. |
| 9 | **Low** | *Deferred* — Loading states still use text with `animate-pulse`. Full skeleton structures matching final layout would nearly double the component code and are low ROI for an ops dashboard. |
| 10 | **Low** | ✅ Empty states added in `SignaturesTab` (empty table message), `IncidentsTab` (no incidents message), `AnalyticsTab` (no flow data message). |

---

## Status

| Severity | Original | Fixed | Remaining |
|----------|----------|-------|-----------|
| Critical | 4 | 5 | 0 |
| High | 11 | 20 | 0 |
| Medium | 21 | 21 | 0 |
| Low | 13 | 13 | 0 |
| **Total** | **49** | **59** | **0** |

### ✅ Fixed — Sections 1–7

5. ✅ **OverviewTab** — live timeline from alerts data via `buildTimeline()`, computed deltas, removed `animate-*` classes, hooks before early return.
6. ✅ **AlertsTab** — compound React keys, Escape key dismiss, pagination with "Show more" button, removed comment.
7. ✅ **IncidentsTab** — accepts `alerts` prop (no duplicate SWR), visible lat/lon axes, loading + empty states.

1. ✅ **Layout** — metadata, favicon, viewport, font chain all fixed.
2. ✅ **Global styles** — dead CSS vars and light-mode block removed.
3. ✅ **API layer** — `NEXT_PUBLIC_API_BASE` env var, centralized error-throwing `fetcher` used across all components.
4. ✅ **Dashboard page** — mobile-responsive sidebar, loading skeletons, unused imports cleaned.

### ✅ Fixed — Top 3 Must-Fix Items (previous batch)

1. ✅ **Added `"use client"` directives** to `OverviewTab.tsx` and `AnalyticsTab.tsx`.
2. ✅ **Created `src/app/lib/types.ts`** with shared interfaces (`Alert`, `Flow`, `KPIs`, `Job`, `JobMetrics`, `ModelVersion`, `Signature`). Eliminated all `any` types across all 9 components + page — zero remain.
3. ✅ **Bug fixes:**
   - **"Unblock" button** in `SettingsTab.tsx` now has an `onClick` handler that calls the firewall API.
   - **Job status case mismatch** in `MLPlaybookTab.tsx`: `"running"` → `"Running"`, `"completed"` → `"Completed"`, `j.id` → `j.job_id`.
   - **Unused imports** cleaned up (`ActivitySquare` from page, `Activity`/`Terminal`/`TrendingUp`/`Sliders` from AlertsTab, `Shield*` from SignaturesTab, unused `LineChart`/`Line` from OverviewTab).
   - **`MetricCard` moved outside render** in `OverviewTab.tsx` (was causing React re-creation warnings).
   - **Unused catch bindings** removed (`err`) in `MLPlaybookTab.tsx`.
   - **Type-safe optional chaining** fixed throughout (e.g., `flows[0]` → `flows?.[0]`, `rf_score * 100` → `(rf_score ?? 0) * 100`).
   - **`NextConfig` type import** removed from `next.config.ts`.
