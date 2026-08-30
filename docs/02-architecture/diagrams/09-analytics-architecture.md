# 09 — Analytics & Machine Learning Architecture

This diagram details the statistical profiling, anomaly detection, rolling baseline maintenance, and 24-dimensional feature extraction subsystems. It explicitly clarifies that analytics executes as an **asynchronous batch / on-demand path**, rather than inline within `Pipeline.process_event()`.

---

## Analytics Subsystem Diagram

```mermaid
flowchart TD
    subgraph INPUT_SOURCES["1. Input Data Source"]
        NDJSON_FILE[("output/events.ndjson\n(Normalized UES Stream)")]
        CLI_ANALYZE["CLI Entry Point:\nulpf analyze --input output/events.ndjson\n[--output output/anomalies.ndjson] [--emit-features]"]
        API_ANALYZE["REST Endpoint:\nGET /api/analytics/anomalies"]
    end

    subgraph PROFILER_ENGINE["2. Baseline Profiler (analytics/baseline.py)"]
        PROFILER["BaselineProfiler"]
        WELFORD["RollingStats (Welford Online Algorithm)\n• Sliding window deque(maxlen=1000)\n• Online mean, variance, standard deviation\n• Z-score calculation (z = |val - mean| / std)\n• IQR outlier detection (Q1 - 1.5*IQR .. Q3 + 1.5*IQR)"]
        
        subgraph DIMENSIONS["Tracked Profiling Dimensions"]
            DIM_SEV["Per-Source-IP Severity Baseline\n(_ip_severity: dict[str, RollingStats])"]
            DIM_BYTES["Per-Source-IP Byte Volume Baseline\n(_ip_bytes: dict[str, RollingStats])"]
            DIM_BURST["Per-Source-IP Event Timestamps\n(_ip_event_times: dict[str, deque[float]])"]
            DIM_CAT["Global Category Distribution\n(_category_counts: dict[str, int])"]
        end

        BASE_STORE[("output/analytics_baseline.json\n(Persisted Baseline State)")]

        PROFILER --> WELFORD
        WELFORD --> DIM_SEV & DIM_BYTES & DIM_BURST & DIM_CAT
        PROFILER <--> BASE_STORE
    end

    subgraph DETECTOR_ENGINE["3. Anomaly Detection Engine (analytics/anomaly.py)"]
        ANOM_DET["AnomalyDetector\n_SCORE_THRESHOLD = 0.15"]
        
        subgraph SCORING_MODEL["6 Weighted Detection Methods"]
            M1["1. Severity Z-Score (>3σ = 0.35, 2-3σ = 0.20)"]
            M2["2. Bytes IQR Outlier (IQR Outlier = 0.25)"]
            M3["3. Event Burst (>3x baseline rate = 0.30)"]
            M4["4. Rare Category (<1% historical count = 0.15)"]
            M5["5. Threat Intel Match (threat_ip_detected = 0.40)"]
            M6["6. Auth Failure Chain (>=5 consecutive failures = 0.30)"]
        end

        SCORE_CALC["Compute Aggregated anomaly_score [0.0 - 1.0]\nBuild anomaly_reasons list\nCalculate risk_score"]
        ANNOTATE["Annotate UES Event:\nevent['analytics'] = {\n  'anomaly_score': float,\n  'is_anomalous': bool,\n  'anomaly_reasons': list[str],\n  'risk_score': float\n}"]

        ANOM_DET --> SCORING_MODEL
        SCORING_MODEL --> SCORE_CALC --> ANNOTATE
    end

    subgraph VECTORIZER_ENGINE["4. ML Feature Engineering (analytics/features.py)"]
        FEAT_EXTRACT["FeatureVectorExtractor.extract_vector(event)"]
        
        subgraph VECTOR_24DIM["24-Dimensional Normalized Numeric Vector [-1.0, 1.0]"]
            V_TIME["4 Temporal Features: hour_sin, hour_cos, dow_sin, dow_cos"]
            V_SEV["2 Severity Features: severity_norm, severity_inferred"]
            V_VOL["2 Volume Features: log_bytes_in, log_bytes_out (Log10 scale)"]
            V_PORT["3 Port Features: port_well_known, port_registered, port_dynamic"]
            V_OUT["3 Outcome Features: outcome_success, outcome_failure, outcome_unknown"]
            V_IND["2 Indicator Features: threat_detected, cloud_origin"]
            V_CAT["8 Category Features: category_{network, auth, threat, system, policy, api, db, unknown}"]
        end

        FEAT_EXTRACT --> V_TIME & V_SEV & V_VOL & V_PORT & V_OUT & V_IND & V_CAT
    end

    subgraph OUTPUT_ANALYTICS["5. Analytics Outputs"]
        ANOM_FILE[("output/anomalies.ndjson\n(Annotated Anomaly Records)")]
        ML_ARRAY["NumPy Arrays / Python Floats\n(Input for Isolation Forest, PCA, Clustering)"]
    end

    NDJSON_FILE --> CLI_ANALYZE & API_ANALYZE
    CLI_ANALYZE & API_ANALYZE --> ANOM_DET
    ANOM_DET <--> PROFILER
    ANNOTATE --> ANOM_FILE
    ANNOTATE -->|If --emit-features| FEAT_EXTRACT
    V_TIME & V_SEV & V_VOL & V_PORT & V_OUT & V_IND & V_CAT --> ML_ARRAY
```

---

## Evidence

| Subsystem Component | Source File | Class / Method | Confidence |
|---|---|---|---|
| Welford Online Algorithm | `ulpf/analytics/baseline.py:27-104` | `RollingStats`, `update()`, `z_score()`, `iqr_outlier()` | **CONFIRMED** |
| Multi-Dimensional Profiler | `ulpf/analytics/baseline.py:105-218` | `BaselineProfiler`, `_ip_severity`, `_ip_bytes`, `_ip_event_times`, `analytics_baseline.json` | **CONFIRMED** |
| 6-Method Weighted Scoring | `ulpf/analytics/anomaly.py:29-37, 68-150` | `_SCORE_WEIGHTS`, `AnomalyDetector.analyze()` | **CONFIRMED** |
| Auth Failure Chain Tracker | `ulpf/analytics/anomaly.py:116-128` | `self._auth_failures[src_ip] >= 5` | **CONFIRMED** |
| 24-Dimensional Vectorizer | `ulpf/analytics/features.py:15-104` | `FeatureVectorExtractor.extract_vector()`, `CATEGORIES`, `OUTCOMES` | **CONFIRMED** |
| CLI & REST Analytics Execution | `ulpf/cli.py:225-281`, `ulpf/dashboard/app.py:488` | `ulpf analyze`, `GET /api/analytics/anomalies` | **CONFIRMED** |
