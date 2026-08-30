# 04 — Ingestion Architecture

This diagram maps all verified ingestion mechanisms in the ULPF framework and traces how incoming data streams enter the pipeline.

---

## Ingestion Architecture Diagram

```mermaid
flowchart TD
    subgraph SOURCES["1. Source Inputs"]
        FILE_SRC["Log File / Directory\n(/var/log/*.log, sample_logs/)"]
        STDIN_SRC["Standard Input Pipe\n(cat log.txt | ulpf ingest -i -)"]
        UDP_SRC["Syslog UDP Packets\n(Port 1514)"]
        TCP_SRC["Syslog TCP Streams\n(Port 1514)"]
        HOST_SRC["Local Host OS Activity\n(Processes & Sockets)"]
        REST_SRC["REST HTTP Ingestion\n(POST /api/ingest/{line, batch, stream})"]
    end

    subgraph COLLECTORS["2. Readers & Ingestion Collectors"]
        subgraph FILE_READER["FileReader (core/ingestion.py)"]
            F_DISC["Path.glob(pattern)"]
            F_OPEN["open(fpath, 'rb')"]
            F_DEC["decode('utf-8', errors='surrogateescape')"]
            F_DISC --> F_OPEN --> F_DEC
        end

        subgraph STDIN_READER["StdinReader (core/ingestion.py)"]
            S_READ["sys.stdin.buffer stream"]
            S_DEC["decode('utf-8', errors='surrogateescape')"]
            S_READ --> S_DEC
        end

        subgraph SYSLOG_LISTENER["SyslogNetworkListener (collectors/syslog_listener.py)"]
            UDP_TH["_udp_worker (Thread)\nrecvfrom(65535)"]
            TCP_TH["_tcp_worker (Thread)\naccept() -> _handle_tcp_client (Thread)\nrecv(4096) -> newline buffer"]
        end

        subgraph LIVE_MONITOR["LiveSystemMonitor (collectors/live_monitor.py)"]
            WIN_API["Win32 ToolHelp32 / iphlpapi / wevtutil (Thread 250ms)"]
            UNIX_API["ps -eo pid,ppid,comm (Thread 250ms)"]
            CIRC_BUF[("event_history Ring Buffer\ndeque(maxlen=250)")]
            WIN_API --> CIRC_BUF
            UNIX_API --> CIRC_BUF
        end

        subgraph REST_GATEWAY["FastAPI Ingest Router (dashboard/app.py)"]
            REST_LINE["/api/ingest/line"]
            REST_BATCH["/api/ingest/batch"]
            REST_STREAM["/api/ingest/stream"]
        end
    end

    subgraph WRAPPER["3. RawEvent Packaging"]
        RAW_OBJ["RawEvent(line, raw_bytes, source_tag, ingest_timestamp)"]
    end

    subgraph PIPELINE_DISPATCH["4. Pipeline Execution Mode"]
        SINGLE_PIPE["Pipeline.process_event()\n(Single-Worker Mode)"]
        MULTI_PIPE["ParallelPipeline.run()\n(multiprocessing.Pool Chunks)"]
    end

    FILE_SRC --> F_DISC
    STDIN_SRC --> S_READ
    UDP_SRC --> UDP_TH
    TCP_SRC --> TCP_TH
    HOST_SRC --> WIN_API & UNIX_API
    REST_SRC --> REST_LINE & REST_BATCH & REST_STREAM

    F_DEC --> RAW_OBJ
    S_DEC --> RAW_OBJ
    UDP_TH -->|on_event callback| SINGLE_PIPE
    TCP_TH -->|on_event callback| SINGLE_PIPE
    REST_LINE & REST_BATCH & REST_STREAM -->|Ephemeral Pipeline| SINGLE_PIPE
    LIVE_MONITOR -.->|Optional pipeline_callback| SINGLE_PIPE

    RAW_OBJ -->|workers <= 1| SINGLE_PIPE
    RAW_OBJ -->|workers > 1| MULTI_PIPE
```

---

## Evidence

| Ingestion Mechanism | Source File | Class / Method | Confidence |
|---|---|---|---|
| Binary File Ingestion | `ulpf/core/ingestion.py:46-84` | `FileReader.read()`, opens `rb`, strips `\r\n` | **CONFIRMED** |
| Standard Input Streaming | `ulpf/core/ingestion.py:85-110` | `StdinReader.read()`, reads `sys.stdin.buffer` | **CONFIRMED** |
| Multi-Threaded Syslog UDP | `ulpf/collectors/syslog_listener.py:43-52, 66-78` | `_udp_sock = socket.SOCK_DGRAM`, `_udp_worker` thread | **CONFIRMED** |
| Multi-Threaded Syslog TCP | `ulpf/collectors/syslog_listener.py:54-65, 79-110` | `_tcp_sock = socket.SOCK_STREAM`, `_handle_tcp_client` | **CONFIRMED** |
| Real-time OS Process Monitor | `ulpf/collectors/live_monitor.py:77-128` | `LiveSystemMonitor`, Win32 C APIs & ring buffer | **CONFIRMED** |
| REST Ingest Endpoints | `ulpf/dashboard/app.py:317-380` | `_get_ingest_pipeline()`, `/api/ingest/*` | **CONFIRMED** |
| Multi-Process Worker Pool | `ulpf/core/worker_pool.py:102-179` | `ParallelPipeline.run()`, 500-event chunks | **CONFIRMED** |
