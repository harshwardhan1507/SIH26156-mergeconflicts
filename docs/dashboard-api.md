# ULPF Operations Dashboard

A lightweight, air-gapped web dashboard for browsing normalized events, inspecting raw/dead-letter logs, and monitoring pipeline health.

- **Backend**: FastAPI with an incremental SQLite indexing cache.
- **Frontend**: Zero-dependency Vanilla JS + CSS custom properties with a virtualized DOM table.
- **Dual Themes**: Default (clean, spacious light view for newcomers) and Professional (dense dark view for SOC operators).
- **Air-Gapped**: Zero external requests, no CDN scripts, no Google Fonts, inline SVGs only.

---

## Running the Dashboard

### 1. CLI Command

```bash
# Point to your output directory
ulpf-dashboard --output-dir output --port 8000

# Or using python module invocation:
python -m ulpf.dashboard.app --output-dir output --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your web browser.

### 2. CLI Options

```
ulpf-dashboard [OPTIONS]

Options:
  -o, --output-dir TEXT  Path to pipeline output folder containing events.ndjson
                         and raw_store/ [default: auto-detected]
  -h, --host TEXT        Bind address [default: 127.0.0.1]
  -p, --port INTEGER     Bind port [default: 8000]
  --reload               Enable live reload for development
  --help                 Show this message and exit
```

---

## Architecture & SQLite Indexer

```
events.ndjson (Source of Truth)
   │
   ▼ (Incremental byte-offset sync)
dashboard_index.db (Disposable SQLite Cache)
   │
   ▼ (Sub-millisecond query / filter / pagination)
FastAPI REST Endpoints (/api/events, /api/stats, /api/parsers)
   │
   ▼ (HTTP / SSE Stream)
Vanilla JS Frontend (Virtualized Table, Dual Themes)
```

1. **Source of Truth**: `events.ndjson` and `raw_store/<aa>/<bb>/<uuid>.raw` are the single source of truth.
2. **Disposable Cache**: The SQLite index (`dashboard_index.db`) is automatically populated and updated incrementally as new events are written to `events.ndjson`.
3. **Rebuilding the Index**: If the SQLite index is ever deleted or corrupted, it automatically rebuilds from `events.ndjson` on the next request, or via `POST /api/reindex`.

---

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `/` | Focus search box |
| `j` / `↓` | Select next event row |
| `k` / `↑` | Select previous event row |
| `Enter` | Open side-by-side Traceability Inspector |
| `p` / `d` | Toggle between Default and Professional Theme |
| `Esc` | Close inspector / modals |
| `?` | Open keyboard shortcuts help |

---

## Docker Execution

The dashboard runs in the same air-gapped container setup:

```bash
docker compose -f docker/docker-compose.yml up dashboard
```
