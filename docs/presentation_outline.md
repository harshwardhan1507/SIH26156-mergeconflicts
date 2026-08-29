# <img src="ulpf-icon.svg" width="28" height="28" alt="ULPF" /> ULPF Presentation Outline (5 Slides)

---

## Slide 1 — The problem

**Title:** Why perimeter log normalization is harder than it looks

- Every vendor format is structurally different: syslog RFC 3164/5424, CEF, LEEF,
  Windows/generic XML, vendor CSV, cloud-provider JSON (AWS/Azure/GCP) — different
  field names, different severity scales, different timestamp formats
- A 10-vendor SOC maintains 10 hand-built parsers; a firmware update on any one
  device can silently break its parser with no alert
- `src_ip` in one source is `srcaddr` in another — correlation, compliance
  queries, and ML features all require a common schema *before* they're possible
- Goal: one pipeline, one schema, the original bytes always recoverable,
  new vendors added without touching the core

---

## Slide 2 — Architecture

**Title:** Reader → Detect → Parse → Raw-store → Normalize → Enrich → Validate → Sink

*(show the diagram from `docs/ARCHITECTURE.md`)*

- Raw bytes are hashed and persisted to the raw store **before** detection or
  parsing runs — a format nobody recognizes still lands in the forensic store
  and the dead-letter queue, not just a log line
- Format detection is a fast heuristic chain with a `sources.yaml` override,
  falling back to asking every registered parser to self-identify
- Field mapping lives in per-parser YAML, not Python — adding a vendor is one
  parser file + one YAML file, zero edits to `core/`
- Event IDs are deterministic (UUIDv5 over tenant + source + raw hash), so
  reprocessing the same input never creates duplicate events downstream

---

## Slide 3 — The schema (UES v1.2.0)

**Title:** Universal Event Schema — lossless by construction

- `raw`: original payload, format, and a SHA-256 computed over the authentic
  bytes — not a lossy text decode of them
- `source` / `event` / `network` / `identity` / `rule`: the common taxonomy,
  with OCSF-aligned `class_name`/`class_uid`/`activity_name` on every event
- `vendor_attributes`: an open bag holding every extracted field that doesn't
  map to a UES column — nothing gets thrown away because the schema is fixed-width
- `severity_inferred`: true when severity was defaulted rather than read from
  the source, so a fabricated value is never indistinguishable from a real one
- `lineage`: parser name/version + ruleset version — every event traces back
  to exactly what produced it
- Anything that fails JSON-Schema validation goes to `dead_letter.ndjson` with
  the raw payload and the reason — nothing is silently dropped

---

## Slide 4 — What actually runs today

**Title:** Demonstrated, not aspirational

- 11 parsers, self-registering via `pkgutil` — zero core edits to add one
- `ulpf listen` — real UDP/TCP syslog ingestion (not just file/stdin batch)
- `ulpf ingest --workers N` — streaming multi-process fan-out, chunked so the
  whole input is never buffered in memory
- Multi-sink fan-out in one run: `--sink ndjson,parquet,cef-egress,leef-egress`
  — same normalized event, NDJSON + columnar data lake + legacy SIEM egress
- Offline IP/threat enrichment and a statistical anomaly engine
  (Z-score, IQR, burst, rare-category, auth-failure-chain) — pure Python,
  zero network calls, air-gap safe
- Dashboard: SQLite-indexed search, SSE live stream, forensic raw/normalized
  split view — CORS restricted to its own origin, write endpoints gated
  behind an optional API key
- 132 automated tests, all green; every claim on this slide has a
  corresponding test or was independently reproduced against the CLI

---

## Slide 5 — Honest limitations & roadmap

**Title:** What we'd build next

- Draft-7 JSON Schema validation is per-event and not yet at billions/day
  throughput — needs sampling or a compiled validator at that scale
- One raw-store file per event; needs time-partitioned, compacted segments
  for real Big Data volumes (the Parquet sink is the first step)
- Taxonomy is OCSF-*aligned*, not full OCSF/ECS conformance — a proper
  crosswalk is the next schema iteration
- No built-in multi-tenant access control beyond the `tenant_id` field and
  the dashboard's API-key gate — a real deployment needs an auth layer in front
- Next: real Kafka/TLS syslog intake, schema registry, OCSF exporter
