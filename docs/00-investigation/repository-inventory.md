# Repository Inventory

## 1. Overview and Repository Metrics

* **Primary Language**: Python (>=3.11 target defined in `pyproject.toml:9`)
* **Project Name & Version**: `ulpf` v1.2.0 (`pyproject.toml:6-7`)
* **Total Tracked Files (Non-.git)**: ~65 source, config, test, and documentation files (plus generated build/asset artifacts).
* **Package Structure**: Single top-level Python package `ulpf/` with 8 primary subpackages/directories (`core`, `parsers`, `schemas`, `collectors`, `analytics`, `sinks`, `dashboard`, `tests`).

---

## 2. Directory Structure and Purpose

| Directory Path | Observed Purpose / Contents | Key Files Found |
|---|---|---|
| `ulpf/` | Top-level Python application root package | `__init__.py`, `cli.py` |
| `ulpf/core/` | Ingestion, format detection, normalization, validation, raw persistence, and execution coordination | `pipeline.py`, `ingestion.py`, `detector.py`, `registry.py`, `normalization.py`, `validation.py`, `raw_store.py`, `worker_pool.py` |
| `ulpf/parsers/` | Format-specific parsing implementations subclassing `BaseParser` | `base.py`, `__init__.py`, `cef.py`, `leef.py`, `syslog_rfc3164.py`, `syslog_rfc5424.py`, `cisco_asa.py`, `paloalto_csv.py`, `aws_cloudtrail.py`, `azure_monitor.py`, `gcp_audit.py`, `xml_generic.py`, `json_passthrough.py` |
| `ulpf/schemas/` | Draft-7 JSON schema for Universal Event Schema (UES) and declarative YAML parser mappings | `ues_schema.json`, `mappings/*.yaml` (11 mapping files) |
| `ulpf/collectors/` | Real-time stream collectors (Syslog network receiver and local OS/Process monitor) | `syslog_listener.py`, `live_monitor.py` |
| `ulpf/analytics/` | Statistical anomaly scoring, baseline profiling, and numerical feature vector extraction | `anomaly.py`, `baseline.py`, `features.py` |
| `ulpf/sinks/` | Egress writer implementations (NDJSON, Apache Parquet, Apache Kafka, CEF egress, LEEF egress) | `base.py`, `ndjson_file.py`, `parquet_sink.py`, `kafka_producer.py`, `kafka_stub.py`, `cef_egress.py`, `leef_egress.py` |
| `ulpf/dashboard/` | FastAPI REST service, SQLite search indexer, and web static UI | `app.py`, `indexer.py`, `static/index.html`, `static/app.js`, `static/style.css` |
| `ulpf/tests/` | Pytest-based unit and integration test suite | `conftest.py`, `test_parser_*.py` (11 modules), `test_detector.py`, `test_e2e.py`, `test_dashboard.py`, `test_criteria_conformance.py`, `test_worker_pool.py`, `test_enrichment_ip.py`, `test_analytics_anomaly.py`, `test_live_monitor.py` |
| `sample_logs/` | Sample raw perimeter log files for manual testing and bootstrap | 11 sample log files (`aws_cloudtrail.log`, `azure_monitor.log`, `cef.log`, `cisco_asa.log`, `gcp_audit.log`, `generic_json.log`, `leef.log`, `paloalto_traffic.csv`, `rfc3164.log`, `rfc5424.log`, `windows_xml.log`) |
| `packaging/` | Platform bundling scripts, packaging configurations, service unit files, and metadata | Subdirectories `windows/`, `macos/`, `linux/`, and build scripts `build_all_platforms.py`, `make_release_zip.py` |
| `docker/` | Container definitions and multi-container orchestrations | `Dockerfile`, `docker-compose.yml` |
| `docs/` | System architecture, dashboard walkthrough, diagrams, screenshots, presentation assets | `ARCHITECTURE.md`, `architecture-diagram.svg`, `dashboard_walkthrough.md`, `demo_script.md`, `presentation_outline.md`, `screenshots/` |

---

## 3. Configuration Files

* **`pyproject.toml`**: Defines setuptools build system, project metadata (`ulpf 1.2.0`), required dependencies (`pydantic>=2.0`, `jsonschema>=4.17`, `click>=8.1`, `pyyaml>=6.0`, `python-dateutil>=2.8`, `fastapi>=0.110.0`, `uvicorn>=0.28.0`), optional extras (`dev`, `parquet`, `kafka`), package scripts (`ulpf`, `ulpf-dashboard`), and package data inclusions.
* **`requirements.txt`**: Mirrors runtime dependencies for non-wheel or isolated installations.
* **`requirements-dev.txt`**: Includes test dependencies (`pytest>=7.4`, `pytest-cov>=4.0`, `httpx>=0.27.0`).
* **`ulpf/config/sources.yaml`**: Configuration file for source-specific overrides mapping `source_tag` prefixes directly to specific `format_id`s, plus global pipeline directory defaults.
* **`ulpf/schemas/ues_schema.json`**: Draft-7 JSON schema specifying mandatory structure, types, constraints, and allowed values for UES v1.2.0.
* **`ulpf/schemas/mappings/*.yaml`**: 11 YAML files specifying declarative field transformations and vendor attribute extractions per parser plugin.

---

## 4. Build, Packaging, and Deployment Files

* **Docker Deployment**:
  - `docker/Dockerfile`: Two-stage build (Stage 1: wheel compilation with dependencies; Stage 2: air-gapped runtime with non-root user `ulpf`, installing from local wheels via `--no-index --find-links /wheels`).
  - `docker/docker-compose.yml`: Defines two services: `ulpf` (batch ingestion CLI running with `network_mode: none`) and `dashboard` (web UI running on port `8000:8000`).
* **Windows Packaging**:
  - `packaging/windows/build_exe.py` / `packaging/windows/ulpf.spec`: PyInstaller one-dir/one-file bundle generator.
  - `packaging/windows/launcher.py`: Safe GUI launcher with stdout redirection to prevent console crashes.
  - `packaging/windows/ulpf.wxs`: WiX Toolset XML configuration for building Windows `.msi` installers.
  - `packaging/windows/build_msi.ps1` / `packaging/windows/build_exe.ps1`: PowerShell automation scripts for Windows builds.
* **macOS Packaging**:
  - `packaging/macos/make_macos_bundle.py`: Automates macOS `.app` bundle construction.
  - `packaging/macos/build_dmg.py`: Creates signed/compressed Apple Disk Images (`.dmg`) using `hdiutil`.
  - `packaging/macos/build_pkg.sh`: Builds macOS component packages via `pkgbuild`/`productbuild`.
  - `packaging/macos/com.noturnio.ulpf.dashboard.plist`: Launchd daemon service definition.
* **Linux Packaging**:
  - `packaging/linux/build_deb_package.py` / `packaging/linux/build_deb.sh`: Debian package (`.deb`) construction.
  - `packaging/linux/ulpf-dashboard.service`: Systemd service unit definition for background execution.
  - `packaging/linux/ulpf.desktop`: Desktop launcher entry for Linux desktop environments.
* **Master Distribution**:
  - `packaging/build_all_platforms.py`: Master orchestration script building Windows, macOS, Linux, and air-gapped zip bundles.
  - `packaging/bundle_master_zip.py` / `packaging/make_release_zip.py`: Archives distribution artifacts.

---

## 5. Scripts and Launchers

* **`Run_Tests.bat`**: Windows batch script running `python test_all.py`.
* **`Launch_ULPF_Dashboard.bat` / `Run_Dashboard.bat`**: Windows 1-click batch scripts starting the dashboard server and opening the default browser.
* **`Create_Desktop_Shortcut.bat`**: Windows VBScript helper creating desktop shortcuts for the ULPF Dashboard.
* **`start_dashboard.sh`**: Shell launcher script for Unix/Linux/macOS environments.
* **`test_all.py`**: Standalone master integration and criteria verification script executing end-to-end API, parser, and storage audits.

---

## 6. Sample Data Inventory

The repository contains 11 sample log files in `sample_logs/` (with a duplicate reference in `ulpf/sample_logs/` bundled for distribution):
1. `sample_logs/aws_cloudtrail.log`: AWS CloudTrail S3/IAM/STS JSON records.
2. `sample_logs/azure_monitor.log`: Microsoft Azure Monitor activity logs in JSON format.
3. `sample_logs/cef.log`: ArcSight / CheckPoint / Fortinet Common Event Format log lines.
4. `sample_logs/cisco_asa.log`: Cisco ASA `%ASA-` mnemonic syslog lines.
5. `sample_logs/gcp_audit.log`: Google Cloud Platform Audit logs in `protoPayload` JSON format.
6. `sample_logs/generic_json.log`: Unstructured and generic key-value JSON records.
7. `sample_logs/leef.log`: IBM QRadar LEEF 1.0 and 2.0 tab-delimited and caret-delimited log lines.
8. `sample_logs/paloalto_traffic.csv`: PAN-OS traffic logs in 35+ column comma-separated format.
9. `sample_logs/rfc3164.log`: BSD Unix syslog lines with `<PRI>` headers and month-day timestamps.
10. `sample_logs/rfc5424.log`: Structured syslog lines with version, ISO timestamps, and SD-ID structured data.
11. `sample_logs/windows_xml.log`: Windows Security EventLog XML structures (EventIDs 4624, 4625, 1102, 5156, etc.).
