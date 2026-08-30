# 08 — Dashboard Architecture

This diagram illustrates the operational dashboard architecture, FastAPI web service, SQLite query acceleration layer, static asset serving, and streaming interfaces.

---

## Dashboard Architecture Diagram

```mermaid
flowchart TD
    subgraph CLIENT_BROWSER["1. Client Browser / API Consumer"]
        SPA["Single Page App (HTML5 / JS / Chart.js)"]
        HTTP_CLIENT["REST Client / Automation Scripts"]
    end

    subgraph FASTAPI_SERVER["2. FastAPI Application Server (dashboard/app.py :8000)"]
        ROUTER["FastAPI Router & Lifespan Handler\n• Startup: indexer.sync_from_ndjson()\n• Shutdown: live_monitor.stop()"]
        CORS["CORS Middleware\nRestricted Origins via _default_cors_origins()"]
        AUTH_GATE{"API Key Check\n(_require_api_key)\nChecks X-API-Key if ULPF_API_KEY set"}

        subgraph ENDPOINTS["REST & Streaming Endpoints"]
            EP_EVENTS["GET /api/events\n(Pagination, Multi-Field Search, Sorting)"]
            EP_DETAIL["GET /api/events/{event_id}\n(Joined UES + Exact Raw Payload)"]
            EP_STATS["GET /api/stats\n(KPI Totals, Categories, Top Vendors, Velocities)"]
            EP_PARSERS["GET /api/parsers\n(Parser Plugin Health & Counts)"]
            EP_DEAD["GET /api/dead-letter\n(Paginated Quarantine Records)"]
            EP_EXPORT["GET /api/export\n(StreamingResponse CSV / NDJSON)"]
            EP_REINDEX["POST /api/reindex\n(Full SQLite Index Rebuild)"]
            EP_INGEST["POST /api/ingest/{line, batch, stream}\n(Real-Time API Ingestion)"]
            EP_SSE["GET /api/stream\n(Server-Sent Events Real-Time Stream)"]
            EP_LIVE["GET/POST /api/live-monitor/*\n(OS Process/Socket Control)"]
            EP_STATIC["Static Mount /\n(Serves dashboard/static/index.html, app.js, style.css)"]
        end

        ROUTER --> CORS
        CORS --> AUTH_GATE
        AUTH_GATE --> ENDPOINTS
    end

    subgraph DATA_ACCESS["3. Data Access & Indexing Layer"]
        INDEXER["EventIndexer (dashboard/indexer.py)"]
        RAW_STORE["FileRawStore (core/raw_store.py)"]
        LIVE_MON["LiveSystemMonitor (collectors/live_monitor.py)"]
        EPHEM_PIPE["Ephemeral Pipeline (_get_ingest_pipeline)"]
    end

    subgraph STORAGE_PERSISTENCE["4. Underlying Storage Files"]
        SQLITE_DB[("dashboard_index.db\n(events_index table, 8 B-Trees)")]
        NDJSON_FILE[("output/events.ndjson\n(Primary Event Log)")]
        RAW_DIR[("output/raw_store/\n(2-Tier Sharded *.raw Files)")]
        DEAD_FILE[("output/dead_letter.ndjson\n(Quarantine Queue)")]
    end

    SPA & HTTP_CLIENT <-->|HTTP / SSE on Port 8000| ROUTER

    EP_EVENTS & EP_STATS & EP_PARSERS & EP_EXPORT & EP_REINDEX --> INDEXER
    EP_DETAIL --> INDEXER & RAW_STORE
    EP_DEAD --> INDEXER
    EP_INGEST --> EPHEM_PIPE
    EP_SSE --> NDJSON_FILE
    EP_LIVE --> LIVE_MON

    INDEXER <--> SQLITE_DB
    INDEXER <--> NDJSON_FILE
    RAW_STORE <--> RAW_DIR
    INDEXER <--> DEAD_FILE
    EPHEM_PIPE --> NDJSON_FILE & RAW_DIR
```

---

## Evidence

| Dashboard Component | Source File | Symbol / Method | Confidence |
|---|---|---|---|
| FastAPI App Factory & Lifespan | `ulpf/dashboard/app.py:150-177` | `create_app()`, `lifespan` handler | **CONFIRMED** |
| CORS & API Key Enforcement | `ulpf/dashboard/app.py:178-192, 137-147` | `CORSMiddleware`, `_require_api_key()` | **CONFIRMED** |
| REST Query Endpoints | `ulpf/dashboard/app.py:200-312` | `/api/events`, `/api/events/{id}`, `/api/stats`, `/api/parsers`, `/api/dead-letter`, `/api/export`, `/api/reindex` | **CONFIRMED** |
| REST Ingestion Pipelines | `ulpf/dashboard/app.py:317-380` | `/api/ingest/line`, `/api/ingest/batch`, `/api/ingest/stream`, `_get_ingest_pipeline()` | **CONFIRMED** |
| Server-Sent Events (SSE) | `ulpf/dashboard/app.py:382-411` | `/api/stream`, `StreamingResponse(event_stream(), media_type="text/event-stream")` | **CONFIRMED** |
| Live Monitor Controller | `ulpf/dashboard/app.py:413-485` | `/api/live-monitor/status`, `/api/live-monitor/start`, `/api/live-monitor/stop`, `/api/live-monitor/events` | **CONFIRMED** |
| SQLite B-Tree Indexed Engine | `ulpf/dashboard/indexer.py:25-66, 142-300` | `CREATE TABLE events_index`, 8 indexes, `query_events()`, `get_stats()` | **CONFIRMED** |
| Static Asset Mount | `ulpf/dashboard/app.py:490-500` | `app.mount("/static", ...)` | **CONFIRMED** |
