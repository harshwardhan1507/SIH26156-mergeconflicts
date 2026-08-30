"""
Live System Monitor & High-Frequency Process/Network Collector.

Captures live local OS events, process executions (e.g. VALORANT, Chrome, Discord),
process terminations, active network connections (Source IP:Port -> Destination IP:Port, Protocol),
and Windows Event Logs in real-time with sub-second resolution (every 250ms - 500ms).

Ingests captured events directly into the ULPF pipeline, updating the forensic
raw store, normalized events stream, SQLite indexer, and web dashboard in real time.
"""
from __future__ import annotations

import ctypes
import datetime
import getpass
import logging
import platform
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path
from typing import Any

logger = logging.getLogger("ulpf.collectors.live")

# Windows ToolHelp & IP Helper constants
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]



_PORT_SERVICE_MAP: dict[int, str] = {
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    27017: "MongoDB",
    6379: "Redis Cache",
    443: "HTTPS Web",
    80: "HTTP Web",
    22: "SSH Terminal",
    53: "DNS Name Resolution",
    8080: "HTTP Alternate",
    8000: "HTTP Dev / API",
    9092: "Apache Kafka",
    9200: "Elasticsearch",
    389: "LDAP Directory",
    636: "LDAPS Secure",
    88: "Kerberos Auth",
    445: "SMB File Sharing",
}

_TCP_STATE_MAP: dict[int, str] = {
    1: "CLOSED",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RCVD",
    5: "ESTABLISHED",
    6: "FIN_WAIT1",
    7: "FIN_WAIT2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}


class LiveSystemMonitor:
    """
    Background worker that monitors real-time OS changes, process launches,
    and active process network connections (IPs & ports).
    Stores events in a dedicated host-monitoring buffer isolated from the main events store.
    """

    def __init__(
        self,
        output_dir: str | Path = "output",
        interval_ms: int = 250,
        write_to_main_pipeline: bool = False,
        pipeline_callback: Callable[[str, str, datetime.datetime], bool] | None = None,
    ):
        self.output_dir = Path(output_dir)
        self.interval_sec = max(0.05, interval_ms / 1000.0)
        self.write_to_main_pipeline = write_to_main_pipeline
        self.pipeline_callback = pipeline_callback
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        # Built on first use and reused for the monitor's lifetime.
        self._session = None

        self.hostname = socket.gethostname()
        self.username = getpass.getuser()
        self.os_type = platform.system().lower()

        # State tracking
        self.known_pids: dict[int, dict[str, Any]] = {}
        self.seen_connections: set[tuple] = set()
        self.event_history: deque = deque(maxlen=250)
        self.events_captured = 0
        self.seen_win_record_ids: set[str] = set()
        self.permission_error: str | None = None
        self.last_scan_time: datetime.datetime | None = None

        # Initialize Windows DLLs
        self.is_windows = self.os_type == "windows"
        if self.is_windows:
            try:
                self.kernel32 = ctypes.windll.kernel32
                self.iphlpapi = ctypes.windll.iphlpapi
            except Exception:
                self.is_windows = False

    def _get_process_path_windows(self, pid: int) -> str:
        """Query full executable path for a PID on Windows."""
        try:
            h = self.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h:
                return ""
            buf = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(1024)
            path = ""
            if self.kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                path = buf.value
            self.kernel32.CloseHandle(h)
            return path
        except Exception:
            return ""

    def _scan_processes_windows(self) -> dict[int, dict[str, Any]]:
        """Fast ToolHelp32 snapshot scan (<5ms in C)."""
        current_procs: dict[int, dict[str, Any]] = {}
        try:
            hSnap = self.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if hSnap == -1:
                return current_procs

            pe32 = PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

            if self.kernel32.Process32First(hSnap, ctypes.byref(pe32)):
                while True:
                    pid = pe32.th32ProcessID
                    name = pe32.szExeFile.decode("latin1", errors="replace")
                    ppid = pe32.th32ParentProcessID
                    current_procs[pid] = {
                        "pid": pid,
                        "name": name,
                        "ppid": ppid,
                    }
                    if not self.kernel32.Process32Next(hSnap, ctypes.byref(pe32)):
                        break

            self.kernel32.CloseHandle(hSnap)
        except Exception as e:
            logger.debug(f"Process scan error: {e}")
        return current_procs

    def _scan_processes_unix(self) -> dict[int, dict[str, Any]]:
        """Fallback process scan for Linux/macOS."""
        current_procs: dict[int, dict[str, Any]] = {}
        try:
            extra_kwargs: dict[str, Any] = {}
            if sys.platform == "win32":
                extra_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            res = subprocess.run(
                ["ps", "-eo", "pid,ppid,comm"],
                capture_output=True,
                text=True,
                timeout=1,
                **extra_kwargs,
            )
            if res.returncode == 0:
                for line in res.stdout.strip().split("\n")[1:]:
                    parts = line.strip().split(None, 2)
                    if len(parts) >= 3:
                        try:
                            pid = int(parts[0])
                            ppid = int(parts[1])
                            name = parts[2]
                            current_procs[pid] = {"pid": pid, "name": name, "ppid": ppid}
                        except ValueError:
                            pass
        except Exception:
            pass
        return current_procs

    def _scan_processes(self) -> dict[int, dict[str, Any]]:
        if self.is_windows:
            return self._scan_processes_windows()
        return self._scan_processes_unix()

    def _scan_network_connections_windows(self) -> list[dict[str, Any]]:
        """Scan active TCP/UDP outbound sockets using iphlpapi (<2ms)."""
        conns = []
        try:
            # 1. TCP Connections
            dwSize = wintypes.DWORD(0)
            self.iphlpapi.GetExtendedTcpTable(None, ctypes.byref(dwSize), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            if dwSize.value > 0:
                buf = ctypes.create_string_buffer(dwSize.value)
                ret = self.iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(dwSize), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
                if ret == 0:
                    num_entries = struct.unpack("I", buf[:4])[0]
                    sz = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
                    for i in range(num_entries):
                        offset = 4 + i * sz
                        row = MIB_TCPROW_OWNER_PID.from_buffer_copy(buf[offset : offset + sz])
                        dst_ip = socket.inet_ntoa(struct.pack("<I", row.dwRemoteAddr))
                        dst_port = socket.ntohs(row.dwRemotePort & 0xFFFF)
                        src_ip = socket.inet_ntoa(struct.pack("<I", row.dwLocalAddr))
                        src_port = socket.ntohs(row.dwLocalPort & 0xFFFF)

                        # Only filter out unbound listening addresses with 0 port, allow localhost (127.0.0.1)
                        if dst_ip != "0.0.0.0" and dst_ip != "255.255.255.255" and dst_port > 0:
                            state_str = _TCP_STATE_MAP.get(row.dwState, str(row.dwState))
                            service_lbl = _PORT_SERVICE_MAP.get(dst_port, _PORT_SERVICE_MAP.get(src_port, "TCP Socket"))
                            conns.append({
                                "pid": row.dwOwningPid,
                                "src_ip": src_ip,
                                "src_port": src_port,
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "proto": "tcp",
                                "state": state_str,
                                "state_raw": row.dwState,
                                "service_inferred": service_lbl,
                                "is_localhost": dst_ip in ("127.0.0.1", "::1") or src_ip in ("127.0.0.1", "::1"),
                            })
        except Exception as e:
            logger.debug(f"TCP scan error: {e}")
        self.last_scan_time = datetime.datetime.now(datetime.UTC)
        return conns

    def _scan_network_connections_posix(self) -> list[dict[str, Any]]:
        """
        Scan active network sockets on Linux / macOS / POSIX systems using psutil.
        Returns identical schema to Windows network scan.
        Distinguishes psutil.AccessDenied from empty connection list and surfaces
        it through self.permission_error and get_stats().
        """
        conns: list[dict[str, Any]] = []
        try:
            import psutil
        except ImportError:
            self.permission_error = "psutil is not installed (required for POSIX socket scanning)"
            logger.warning("psutil is not installed: POSIX live network socket scanning unavailable")
            return []

        try:
            raw_sconns = psutil.net_connections(kind="inet")
            self.permission_error = None
            self.last_scan_time = datetime.datetime.now(datetime.UTC)
            for sconn in raw_sconns:
                if not sconn.raddr:
                    continue
                dst_ip = str(getattr(sconn.raddr, "ip", "") or "")
                dst_port = int(getattr(sconn.raddr, "port", 0) or 0)
                src_ip = str(getattr(sconn.laddr, "ip", "0.0.0.0") or "0.0.0.0") if sconn.laddr else "0.0.0.0"
                src_port = int(getattr(sconn.laddr, "port", 0) or 0) if sconn.laddr else 0
                proto = "tcp" if sconn.type == socket.SOCK_STREAM else "udp"

                if dst_ip not in ("0.0.0.0", "255.255.255.255", "") and dst_port > 0:
                    state_str = str(sconn.status or "ESTABLISHED")
                    service_lbl = _PORT_SERVICE_MAP.get(dst_port, _PORT_SERVICE_MAP.get(src_port, "TCP Socket" if proto == "tcp" else "UDP Socket"))
                    conns.append({
                        "pid": int(sconn.pid or 0),
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "proto": proto,
                        "state": state_str,
                        "state_raw": state_str,
                        "service_inferred": service_lbl,
                        "is_localhost": dst_ip in ("127.0.0.1", "::1", "localhost") or src_ip in ("127.0.0.1", "::1", "localhost"),
                    })
        except getattr(psutil, "AccessDenied", Exception) as ad:
            self.permission_error = "AccessDenied: Insufficient OS privileges to inspect network sockets (run as root/administrator)"
            logger.warning(f"POSIX network socket scan failed with AccessDenied: {ad}")
            return []
        except Exception as e:
            self.permission_error = f"POSIX socket scan error: {e}"
            logger.warning(f"POSIX network socket scan error: {e}")
            return []
        return conns

    def _build_process_event_xml(
        self,
        event_id_num: int,
        proc_info: dict[str, Any],
        action_type: str,
        now: datetime.datetime,
    ) -> str:
        """Create a Windows Security Log XML string matching EventID 4688/4689."""
        pid = proc_info.get("pid", 0)
        name = proc_info.get("name", "unknown.exe")
        path = proc_info.get("path") or name
        ppid = proc_info.get("ppid", 0)
        now_iso = now.isoformat()

        if event_id_num == 4688:
            msg = f"A new process has been created (Process: {name}, PID: {pid})"
        else:
            msg = f"A process has exited (Process: {name}, PID: {pid})"

        xml_str = (
            f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f"<System>"
            f"<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/>"
            f"<EventID>{event_id_num}</EventID>"
            f"<Version>2</Version>"
            f"<Level>0</Level>"
            f"<Task>13312</Task>"
            f"<Opcode>0</Opcode>"
            f"<Keywords>0x8020000000000000</Keywords>"
            f"<TimeCreated SystemTime='{now_iso}'/>"
            f"<EventRecordID>{int(time.time() * 1000) % 10000000}</EventRecordID>"
            f"<Execution ProcessID='4' ThreadID='0'/>"
            f"<Channel>Security</Channel>"
            f"<Computer>{self.hostname}</Computer>"
            f"<Security/>"
            f"</System>"
            f"<EventData>"
            f"<Data Name='SubjectUserName'>{self.username}</Data>"
            f"<Data Name='NewProcessId'>0x{pid:x}</Data>"
            f"<Data Name='ProcessId'>{pid}</Data>"
            f"<Data Name='NewProcessName'>{path}</Data>"
            f"<Data Name='ProcessName'>{name}</Data>"
            f"<Data Name='ParentProcessId'>0x{ppid:x}</Data>"
            f"<Data Name='Action'>{action_type}</Data>"
            f"<Data Name='Message'>{msg}</Data>"
            f"</EventData>"
            f"</Event>"
        )
        return xml_str

    def _build_network_connection_xml(
        self,
        conn_info: dict[str, Any],
        proc_info: dict[str, Any],
        now: datetime.datetime,
    ) -> str:
        """Create a Windows Filtering Platform EventID 5156 XML string."""
        pid = conn_info.get("pid", 0)
        src_ip = conn_info.get("src_ip", "127.0.0.1")
        src_port = conn_info.get("src_port", 0)
        dst_ip = conn_info.get("dst_ip", "0.0.0.0")
        dst_port = conn_info.get("dst_port", 0)
        proto = conn_info.get("proto", "tcp")
        name = proc_info.get("name", "unknown.exe")
        path = proc_info.get("path") or name
        now_iso = now.isoformat()

        msg = f"{name} connected to {dst_ip}:{dst_port} ({proto.upper()})"

        xml_str = (
            f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f"<System>"
            f"<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/>"
            f"<EventID>5156</EventID>"
            f"<Version>1</Version>"
            f"<Level>0</Level>"
            f"<Task>12810</Task>"
            f"<Opcode>0</Opcode>"
            f"<Keywords>0x8020000000000000</Keywords>"
            f"<TimeCreated SystemTime='{now_iso}'/>"
            f"<EventRecordID>{int(time.time() * 1000) % 10000000}</EventRecordID>"
            f"<Execution ProcessID='4' ThreadID='0'/>"
            f"<Channel>Security</Channel>"
            f"<Computer>{self.hostname}</Computer>"
            f"<Security/>"
            f"</System>"
            f"<EventData>"
            f"<Data Name='ProcessId'>{pid}</Data>"
            f"<Data Name='Application'>{path}</Data>"
            f"<Data Name='ProcessName'>{name}</Data>"
            f"<Data Name='Direction'>outbound</Data>"
            f"<Data Name='SourceAddress'>{src_ip}</Data>"
            f"<Data Name='SourcePort'>{src_port}</Data>"
            f"<Data Name='DestAddress'>{dst_ip}</Data>"
            f"<Data Name='DestPort'>{dst_port}</Data>"
            f"<Data Name='Protocol'>{proto}</Data>"
            f"<Data Name='ProtocolName'>{proto.upper()}</Data>"
            f"<Data Name='Action'>connection_permit</Data>"
            f"<Data Name='Message'>{msg}</Data>"
            f"</EventData>"
            f"</Event>"
        )
        return xml_str

    def _poll_windows_event_logs(self, now: datetime.datetime):
        """Poll recent Windows Application and System logs via wevtutil silently without console popups."""
        if not self.is_windows:
            return
        extra_kwargs: dict[str, Any] = {}
        if sys.platform == "win32":
            extra_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0  # SW_HIDE
                extra_kwargs["startupinfo"] = si
            except Exception:
                pass

        try:
            for channel in ["Application", "System"]:
                cmd = ["wevtutil.exe", "qe", channel, "/c:3", "/rd:true", "/f:xml"]
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=1.5,
                    **extra_kwargs,
                )
                if res.returncode == 0 and res.stdout.strip():
                    raw_xmls = re.findall(r"<Event\s+xmlns=.*?</Event>", res.stdout, re.DOTALL)
                    for x in raw_xmls:
                        # Extract record id to prevent duplicates
                        rec_m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", x)
                        rec_id = f"{channel}_{rec_m.group(1)}" if rec_m else x[:60]
                        if rec_id not in self.seen_win_record_ids:
                            self.seen_win_record_ids.add(rec_id)
                            if len(self.seen_win_record_ids) > 5000:
                                self.seen_win_record_ids.clear()
                            self._dispatch_event(x, f"win_evt_{channel.lower()}", now)
        except Exception as e:
            logger.debug(f"Event log poll error: {e}")

    def _dispatch_event(self, raw_line: str, source_tag: str, ts: datetime.datetime):
        """Record live event in dedicated host buffer and optionally push to main pipeline."""
        try:
            from ulpf.parsers.xml_generic import XMLGenericParser

            p = XMLGenericParser()
            extracted = p.extract(raw_line) if p.match(raw_line) else {}

            event_summary = {
                "id": str(int(time.time() * 1000) % 10000000),
                "timestamp": ts.isoformat(),
                "source_tag": source_tag,
                "vendor": "Microsoft (Windows)" if self.is_windows else "Host System",
                "category": extracted.get("category", "system"),
                "action": extracted.get("action", "system_event"),
                "severity_numeric": extracted.get("severity_numeric", 3),
                "process_name": extracted.get("process_name") or "",
                "username": extracted.get("username") or self.username,
                "src_ip": extracted.get("src_ip"),
                "src_port": extracted.get("src_port"),
                "dst_ip": extracted.get("dst_ip"),
                "dst_port": extracted.get("dst_port"),
                "protocol": extracted.get("protocol"),
                "message": extracted.get("message") or raw_line[:120],
                "raw_payload": raw_line,
            }

            with self._lock:
                self.event_history.appendleft(event_summary)
                self.events_captured += 1

            if self.pipeline_callback:
                self.pipeline_callback(raw_line, source_tag, ts)
            elif self.write_to_main_pipeline:
                # One session for the monitor's lifetime. Building a pipeline
                # per event re-parsed every mapping and recompiled the schema
                # for a single line, several times a second. Consumers such as
                # the dashboard pick the new events up from the NDJSON tail, so
                # nothing here needs to know they exist.
                self._pipeline_session().process_event(
                    raw_line=raw_line, source_tag=source_tag, ingest_ts=ts
                )

        except Exception as exc:
            logger.error(f"Error recording live host event: {exc}")

    def _pipeline_session(self):
        """Lazily build and cache the ingest pipeline this monitor writes through."""
        if self._session is None:
            from ulpf.runtime import build_session

            self._session = build_session(output_dir=self.output_dir, sinks="ndjson")
        return self._session

    def _monitor_loop(self):
        """Main high-frequency background polling loop."""
        logger.info(f"Live System Monitor started (interval: {self.interval_sec*1000:.0f}ms)")

        # Initial baseline process snapshot
        self.known_pids = self._scan_processes()
        for pid, info in self.known_pids.items():
            if self.is_windows:
                info["path"] = self._get_process_path_windows(pid)

        # Baseline connections
        if self.is_windows:
            initial_conns = self._scan_network_connections_windows()
        else:
            initial_conns = self._scan_network_connections_posix()
        for c in initial_conns:
            key = (c["pid"], c["src_ip"], c["src_port"], c["dst_ip"], c["dst_port"], c["proto"])
            self.seen_connections.add(key)

        win_poll_counter = 0

        while self._running:
            try:
                now = datetime.datetime.now(datetime.UTC)
                current_procs = self._scan_processes()

                # 1. Detect New Process Launches
                for pid, info in current_procs.items():
                    if pid not in self.known_pids:
                        if self.is_windows:
                            info["path"] = self._get_process_path_windows(pid)
                        event_xml = self._build_process_event_xml(4688, info, "process_start", now)
                        self._dispatch_event(event_xml, "live_process_monitor", now)
                        logger.info(f"Captured process launch: {info['name']} (PID: {pid})")

                # 2. Detect Process Terminations
                for pid, old_info in list(self.known_pids.items()):
                    if pid not in current_procs:
                        event_xml = self._build_process_event_xml(4689, old_info, "process_stop", now)
                        self._dispatch_event(event_xml, "live_process_monitor", now)
                        logger.info(f"Captured process exit: {old_info['name']} (PID: {pid})")

                self.known_pids = current_procs

                # 3. Detect Active Network Connections (IPs, Ports, Protocols)
                if self.is_windows:
                    active_conns = self._scan_network_connections_windows()
                else:
                    active_conns = self._scan_network_connections_posix()

                for conn in active_conns:
                    key = (conn["pid"], conn["src_ip"], conn["src_port"], conn["dst_ip"], conn["dst_port"], conn["proto"])
                    if key not in self.seen_connections:
                        self.seen_connections.add(key)
                        if len(self.seen_connections) > 10000:
                            self.seen_connections.clear()
                        # Resolve process info
                        default_name = "system.exe" if self.is_windows else "system"
                        proc_info = self.known_pids.get(conn["pid"], {"name": default_name, "path": ""})
                        net_xml = self._build_network_connection_xml(conn, proc_info, now)
                        self._dispatch_event(net_xml, "live_network_monitor", now)
                        logger.info(f"Captured connection: {proc_info['name']} -> {conn['dst_ip']}:{conn['dst_port']}")

                # 4. Poll Windows Event Logs every 4th iteration (~1 second)
                win_poll_counter += 1
                if win_poll_counter >= 4:
                    win_poll_counter = 0
                    self._poll_windows_event_logs(now)

            except Exception as e:
                logger.error(f"Error in Live Monitor loop: {e}")

            time.sleep(self.interval_sec)

        logger.info("Live System Monitor stopped.")

    def start(self):
        """Start the live monitor in a background thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="ULPF-LiveMonitor")
            self._thread.start()

    def stop(self):
        """Stop the background monitor thread and release the ingest pipeline."""
        with self._lock:
            self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        if self._session is not None:
            try:
                self._session.close()
            except Exception as exc:
                logger.warning("Closing the monitor's pipeline session failed: %s", exc)
            self._session = None

    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "events_captured": self.events_captured,
                "tracked_processes": len(self.known_pids),
                "tracked_connections": len(self.seen_connections),
                "interval_ms": int(self.interval_sec * 1000),
                "platform": self.os_type,
                "hostname": self.hostname,
                "username": self.username,
                "permission_error": self.permission_error,
                "scan_status": "permission_denied" if self.permission_error else ("running" if self._running else "stopped"),
                "last_scan_time": self.last_scan_time.isoformat() if self.last_scan_time else None,
            }

    def get_recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recently captured live host events from ring buffer."""
        with self._lock:
            return list(self.event_history)[:limit]

    def get_active_connections(self) -> list[dict[str, Any]]:
        """Return currently active outbound TCP/UDP socket connections across Windows, Linux, and macOS."""
        if self.is_windows:
            raw_conns = self._scan_network_connections_windows()
        else:
            raw_conns = self._scan_network_connections_posix()
        resolved = []
        default_name = "system.exe" if self.is_windows else "system"
        for c in raw_conns:
            p_info = self.known_pids.get(c["pid"], {"name": default_name, "path": ""})
            resolved.append({
                **c,
                "process_name": p_info.get("name", default_name),
                "process_path": p_info.get("path", ""),
            })
        return resolved

    def get_running_processes(self, limit: int = 150) -> list[dict[str, Any]]:
        """Return snapshot of currently running processes."""
        with self._lock:
            if not self.known_pids:
                current = self._scan_processes()
                for pid, info in current.items():
                    if self.is_windows:
                        info["path"] = self._get_process_path_windows(pid)
                return list(current.values())[:limit]
            procs = list(self.known_pids.values())
        return procs[:limit]


# Backward-compatible alias
LiveHostMonitor = LiveSystemMonitor


