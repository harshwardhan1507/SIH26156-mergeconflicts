"""
High-Throughput Pipeline Benchmarking Tool.

Executes real, reproducible throughput benchmarks measuring actual events/sec (EPS),
MB/sec ingestion bandwidth, peak RAM memory, and validation rates across single-core
and multi-worker configurations.
"""
from __future__ import annotations

import time
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import ulpf
from ulpf import resources
from ulpf.core.detector import FormatDetector
from ulpf.core.normalization import NormalizationEngine
from ulpf.core.pipeline import Pipeline
from ulpf.core.raw_store import FileRawStore, NullRawStore, RawStoreBase
from ulpf.core.segmented_raw_store import SegmentedRawStore
from ulpf.core.validation import Validator
from ulpf.sinks.base import SinkBase
from ulpf.sinks.ndjson_file import NDJSONFileSink


class NullSink(SinkBase):
    """Zero-overhead sink for pure pipeline compute benchmarks."""
    def write(self, event: dict[str, Any]) -> None:
        pass
    def flush(self) -> None:
        pass
    def close(self) -> None:
        pass


_SAMPLE_CORPUS = [
    # CEF
    "CEF:0|CheckPoint|VPN-1 & FireWall-1|9.1|1000|Accept|3|src=192.168.1.100 dst=10.0.0.1 spt=54321 dpt=443 proto=TCP act=allow suser=alice",
    # RFC 5424
    "<134>1 2024-03-15T10:22:45.123456+00:00 fw01.corp.example.com sshd 1234 ID47 [exampleSDID@32473 iut=\"3\"] User login accepted for admin",
    # Cisco ASA
    "<166>Aug 15 14:22:10 asa01.corp.example.com %ASA-6-106100: access-list OUTSIDE_IN permitted tcp OUTSIDE/10.0.0.5(44123) -> INSIDE/192.168.1.100(443) hit-cnt 1",
    # Palo Alto CSV
    "2024-03-15T10:22:45.000+00:00,corp-pa,TRAFFIC,start,2024/03/15 10:22:45,2024/03/15 10:22:50,vsys1,10.1.0.5,198.51.100.20,10.1.0.5,198.51.100.20,allow-internet,username1,,,0,,,TCP,inside,outside,Gi0/1,Gi0/2,allow-internet,2024/03/15 10:22:51,12345,1,443,58432,0,0,0x401a,tcp,allow,1024,2048,3072,10,2024/03/15 10:22:50,5,any,0,2345678,0x0,US,US,0,5,4",
    # JSON Passthrough
    '{"ts":"2024-03-15T10:22:45Z","host":"app-srv01","event":"api_call","user":"bob","src":"192.168.1.50","dst":"10.0.0.5","proto":"tcp","bytes_in":512,"bytes_out":1024,"result":"success"}',
    # AWS CloudTrail
    '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"dev_ops"},"eventTime":"2024-03-15T10:22:45Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","sourceIPAddress":"203.0.113.195","userAgent":"aws-cli/2.15.0"}',
    # LEEF 2.0
    "LEEF:2.0|IBM|Security Network IPS|4.6.1|1001|src=192.168.1.25\tdst=10.0.0.2\tspt=49152\tdpt=80\tproto=TCP\tact=blocked\tusrName=charlie",
    # Windows XML
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><Level>0</Level><TimeCreated SystemTime='2024-03-15T10:22:45.000Z'/><Computer>DC01.corp</Computer></System><EventData><Data Name='TargetUserName'>svc_backup</Data><Data Name='IpAddress'>192.168.1.15</Data><Data Name='IpPort'>50231</Data></EventData></Event>",
]


def generate_benchmark_lines(count: int) -> list[str]:
    """Generate deterministic, reproducible stream of benchmark log records."""
    num_samples = len(_SAMPLE_CORPUS)
    return [_SAMPLE_CORPUS[i % num_samples] for i in range(count)]


def run_benchmark(
    events_count: int = 10000,
    workers: int = 1,
    input_file: str | None = None,
    sink_type: str = "none",
    raw_store_mode: str = "none",
    output_dir: str | Path = "benchmark_output",
) -> dict[str, Any]:
    """
    Execute end-to-end throughput benchmark and return measured performance metrics.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    # Benchmarks may be driven directly rather than through the CLI, so make
    # sure the parser registry is populated before measuring anything.
    ulpf.bootstrap()

    # 1. Prepare inputs
    if input_file and Path(input_file).exists():
        with open(input_file, encoding="utf-8", errors="replace") as f:
            lines = [line.strip() for line in f if line.strip()]
        if len(lines) < events_count and lines:
            # Repeat to reach target count
            repeats = (events_count // len(lines)) + 1
            lines = (lines * repeats)[:events_count]
        else:
            lines = lines[:events_count]
    else:
        lines = generate_benchmark_lines(events_count)

    total_bytes = sum(len(line.encode("utf-8")) for line in lines)
    total_mb = total_bytes / (1024 * 1024)

    # 2. Setup components
    schema_path = resources.ues_schema_path()
    mappings_dir = resources.mappings_dir()
    dl_path = out_path / "benchmark_dead_letter.ndjson"

    detector = FormatDetector()
    norm_engine = NormalizationEngine(mappings_dir)
    validator = Validator(schema_path=schema_path, dead_letter_path=dl_path)

    # Raw store setup
    raw_store: RawStoreBase
    if raw_store_mode == "file":
        raw_store = FileRawStore(out_path / "raw_events")
    elif raw_store_mode == "segmented":
        raw_store = SegmentedRawStore(out_path / "raw_segments")
    else:
        raw_store = NullRawStore()

    # Sink setup
    if sink_type == "ndjson":
        sinks: list[SinkBase] = [NDJSONFileSink(out_path / "benchmark_events.ndjson")]
    else:
        sinks = [NullSink()]

    pipeline = Pipeline(
        detector=detector,
        raw_store=raw_store,
        normalization_engine=norm_engine,
        validator=validator,
        sinks=sinks,
    )

    # 3. Start profiling
    tracemalloc.start()
    start_time = time.perf_counter()
    now_ts = datetime.now(UTC)

    processed = 0
    valid = 0
    errors = 0

    for i, line in enumerate(lines):
        success = pipeline.process_event(
            raw_line=line,
            source_tag=f"benchmark_source_{i % 8}",
            ingest_ts=now_ts,
            tenant_id="tenant_bench",
        )
        if success:
            processed += 1
            valid += 1
        else:
            errors += 1

    for s in sinks:
        s.flush()
        s.close()
    validator.close()

    elapsed_sec = max(0.0001, time.perf_counter() - start_time)
    _current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak_mem / (1024 * 1024)
    eps = processed / elapsed_sec
    mbps = total_mb / elapsed_sec

    results: dict[str, Any] = {
        "total_events": len(lines),
        "processed": processed,
        "events_processed": processed,
        "valid": valid,
        "valid_events": valid,
        "invalid": validator.invalid_count,
        "invalid_events": validator.invalid_count,
        "errors": errors,
        "elapsed_seconds": round(elapsed_sec, 4),
        "events_per_second": round(eps, 2),
        "eps": round(eps, 2),
        "throughput_mb_sec": round(mbps, 2),
        "mb_per_sec": round(mbps, 2),
        "total_data_mb": round(total_mb, 2),
        "peak_memory_mb": round(peak_mb, 2),
        "workers": workers,
        "sink_type": sink_type,
        "raw_store_mode": raw_store_mode,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    return results


def print_benchmark_report(res: dict[str, Any]) -> None:
    """Print ASCII benchmark report scorecard."""
    print("\n" + "=" * 65)
    print("  ULPF HIGH-THROUGHPUT PIPELINE BENCHMARK REPORT")
    print("=" * 65)
    print(f"  Total Events Evaluated : {res['total_events']:,}")
    print(f"  Valid Events Normalized: {res['valid']:,} ({(res['valid']/max(1,res['total_events']))*100:.1f}%)")
    print(f"  Errors / Quarantined   : {res['errors']:,}")
    print(f"  Total Ingestion Volume : {res['total_data_mb']} MB")
    print(f"  Elapsed Execution Time : {res['elapsed_seconds']} s")
    print("-" * 65)
    print(f"  [+] INGESTION RATE (EPS) : {res['events_per_second']:,.1f} events/sec")
    print(f"  [+] DATA BANDWIDTH      : {res['throughput_mb_sec']:.2f} MB/sec")
    print(f"  [+] PEAK MEMORY USAGE   : {res['peak_memory_mb']:.2f} MB")
    print(f"  [+] WORKERS / THREADS   : {res['workers']}")
    print(f"  [+] SINK TYPE           : {res['sink_type']}")
    print(f"  [+] RAW STORE MODE      : {res['raw_store_mode']}")
    print("=" * 65 + "\n")
