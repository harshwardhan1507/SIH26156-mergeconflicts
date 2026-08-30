# ULPF Human Understanding Guide

> **Start here if you are new to ULPF.** This folder explains the Universal Log Pre-processing Framework in simple, natural English before you dive into deep technical architecture or source code.

---

## 1. Start Here

Welcome to ULPF! 

Security systems and log processing pipelines can quickly become overwhelming with complex technical jargon, hundreds of classes, and deep math.

This **`04-understanding/`** documentation layer was created specifically to give you a clean, simple **mental model** of the project first. Whether you are a new developer joining the team, an analyst learning how logs are transformed, or someone preparing to pitch and demo the project, start with the guides in this folder.

---

## 2. What Is ULPF?

**ULPF** stands for **Universal Log Pre-processing Framework**.

It is a high-performance pre-processing engine that takes messy, mismatched security logs from firewalls, routers, servers, and clouds (such as Cisco ASA, Palo Alto Networks, Linux Syslog, and AWS CloudTrail). ULPF preserves the original raw evidence on disk with cryptographic SHA-256 fingerprints, translates proprietary vendor fields into a single standardized format called the **Unified Event Schema (UES)**, enriches the data with offline threat intelligence, and delivers clean, verified events to storage files, streaming message queues (Kafka), and live web dashboards.

---

## 3. Recommended Reading Order

To understand the system step-by-step without getting lost, follow this sequence:

```text
STEP 1: [Diagram 01: The Big Picture](./diagrams/01-big-picture.md)
        "What is ULPF and what problem does it solve in 30 seconds?"
           │
           ▼
STEP 2: [Diagram 02: The Journey of a Log](./diagrams/02-log-journey.md)
        "What exact path does a single log take through the pipeline?"
           │
           ▼
STEP 3: [Diagram 03: The Repository Map](./diagrams/03-repository-map.md)
        "Where does each part of the process live in the codebase?"
           │
           ▼
STEP 4: [Diagram 04: The Failure Path](./diagrams/04-failure-path.md)
        "What happens when a log is broken, unknown, or malformed?"
           │
           ▼
STEP 5: [How ULPF Works (The Complete Guide)](./HOW_ULPF_WORKS.md)
        "Explain everything together: why we built it, how it works, and our key technical decisions."
           │
           ▼
STEP 6: [Quick Reference & Cheat Sheet](./QUICK_REFERENCE.md)
        "Keep this open while working, pitching, or debugging."
```

---

## 4. What Each File Is For

| Document | Core Question Answered | When to Use It |
| :--- | :--- | :--- |
| **[01-big-picture.md](./diagrams/01-big-picture.md)** | *"What is ULPF at a high level?"* | First-time orientation and executive overviews. |
| **[02-log-journey.md](./diagrams/02-log-journey.md)** | *"What happens to one log after it enters?"* | Learning the 9 runtime processing steps. |
| **[03-repository-map.md](./diagrams/03-repository-map.md)** | *"Where does each functional area live?"* | Finding the right files before writing code. |
| **[04-failure-path.md](./diagrams/04-failure-path.md)** | *"How are errors and bad logs handled?"* | Debugging parse errors and understanding quarantine. |
| **[HOW_ULPF_WORKS.md](./HOW_ULPF_WORKS.md)** | *"Explain the entire project in plain English."* | Full team onboarding, architectural rationale, and deep understanding. |
| **[QUICK_REFERENCE.md](./QUICK_REFERENCE.md)** | *"Give me the cheat sheet and jump tables."* | Daily coding reference, team discussions, demos, and pitch prep. |

---

## 5. Which Documentation Layer Should I Read?

ULPF documentation is organized into four distinct progressive layers:

```text
docs/
├── 04-understanding/  ──► Layer 1: "Explain it to me simply." (Mental models & human guides)
│
├── 02-architecture/   ──► Layer 2: "Show me the technical system architecture." (Runtime flows, concurrency, diagrams)
│
├── 03-data-analysis/  ──► Layer 3: "Show me the data model and parser details." (UES schema, losslessness, field mappings)
│
└── 00-investigation/  ──► Layer 4: "Show me the raw evidence and code audit." (Truth verification vs code, line numbers)
```

> **Rule of thumb:** Always start in **`04-understanding/`**. Only jump to `02-architecture/` or `03-data-analysis/` when you need specific class interfaces, JSON Schema definitions, or byte-level cryptographic proofs.

---

## 6. If You Are a New Teammate

If you just joined the team or repository:
1. Read **[01-big-picture.md](./diagrams/01-big-picture.md)** to grasp the concept.
2. Read **[02-log-journey.md](./diagrams/02-log-journey.md)** to understand how data moves.
3. Read **[03-repository-map.md](./diagrams/03-repository-map.md)** to see where files live.
4. Read **[04-failure-path.md](./diagrams/04-failure-path.md)** to see how safety works.
5. Read **[HOW_ULPF_WORKS.md](./HOW_ULPF_WORKS.md)** for the complete picture.
6. Keep **[QUICK_REFERENCE.md](./QUICK_REFERENCE.md)** open as your daily cheat sheet.

> **Tip:** You do *not* need to understand every parser regex or statistical algorithm before contributing. Focus on the pipeline flow first, then dive into the specific module you are changing.

---

## 7. If You Are Preparing for the Pitch or Demo

If you are presenting ULPF to evaluators, customers, or teammates:
* Start with **[QUICK_REFERENCE.md](./QUICK_REFERENCE.md)** (Sections 1, 2, and 11) for spoken 30-second elevator pitches.
* Use the visual diagram in **[01-big-picture.md](./diagrams/01-big-picture.md)** to demonstrate the core value proposition.
* Review Section 11 of **[HOW_ULPF_WORKS.md](./HOW_ULPF_WORKS.md)** (*Key Technical Decisions*) to confidently answer *"Why did you design it this way?"* questions regarding raw evidence preservation, offline air-gapped enrichment, and declarative YAML normalization.

---

## 8. If You Are Debugging an Issue

When a log is not parsing correctly or failing to appear in sinks:
```text
Something failed or missing
           │
           ▼
1. Read [04-failure-path.md](./diagrams/04-failure-path.md)
   (Understand how dead-letter quarantine works)
           │
           ▼
2. Check output/dead_letter.ndjson & identify the failure stage:
   - Unknown format? ──► Check detector.py or sources.yaml
   - Parse error?    ──► Check parsers/<vendor>.py
   - Schema error?   ──► Check schemas/mappings/<vendor>.yaml
   - Sink error?     ──► Check destination connectivity
           │
           ▼
3. Use [03-repository-map.md](./diagrams/03-repository-map.md)
   (Jump directly to the relevant code files)
           │
           ▼
4. (Optional) Go deeper into [../03-data-analysis/](../03-data-analysis/) for field-level schema specifications
```

---

## 9. Important Principle: Progressive Learning

**Simple documentation does not replace technical documentation — it introduces it.**

```text
Human Understanding (04-understanding/)
         │  Builds the mental model & big-picture rationale
         ▼
Technical Specifications (02-architecture/ & 03-data-analysis/)
         │  Provides exact data contracts, class diagrams & proofs
         ▼
Actual Source Code (ulpf/)
            Makes the changes & runs tests
```

---

## 10. Folder Structure

The complete `04-understanding` directory structure:

```text
docs/04-understanding/
│
├── README.md                      # You are here: Navigation, reading order, and quick guide
├── HOW_ULPF_WORKS.md              # The comprehensive plain-English guide to ULPF
├── QUICK_REFERENCE.md             # Developer cheat sheet, jump tables, and elevator pitches
│
└── diagrams/                      # Four essential visual mental models
    ├── 01-big-picture.md          # High-level conceptual overview
    ├── 02-log-journey.md          # Step-by-step lifecycle of an individual log
    ├── 03-repository-map.md       # Directory and component layout map
    └── 04-failure-path.md         # Error handling, validation, and quarantine paths
```

---

## 11. The One-Minute Mental Model

```text
[ Different Security Logs ] ──► (Cisco, Palo Alto, Syslog, CloudTrail)
             │
             ▼
      [ ULPF Engine ]       ──► 1. Save raw bytes & calculate SHA-256
             │                  2. Detect format & select parser
             │                  3. Extract fields & normalize to UES
             │                  4. Enrich with offline IP intelligence
             │                  5. Validate against JSON Schema gate
             ▼
   [ Validated Deliveries ] ──► Storage (NDJSON/Parquet), Streaming (Kafka),
                                Live UI Dashboard, or Dead-Letter Quarantine
```

> **In plain English:** ULPF takes raw, messy security logs from any device, locks the original evidence to disk, translates the fields into one clean universal language (UES), verifies the quality, and delivers clean events to your storage and dashboards so your team can write detection rules once and guarantee zero data loss.
