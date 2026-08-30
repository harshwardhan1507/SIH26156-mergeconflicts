"""
High-Throughput Syslog Network Listener (UDP & TCP).

Listens on UDP and TCP ports (e.g. 514, 1514) to ingest real syslog packets
from enterprise network appliances, firewalls, and servers directly into the ULPF pipeline.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from collections.abc import Callable

logger = logging.getLogger("ulpf.collectors.syslog")

#: Largest single syslog record accepted over TCP before the connection is
#: reset. A peer that never sends a newline would otherwise grow the per-client
#: buffer without bound.
MAX_TCP_RECORD_BYTES = 1 * 1024 * 1024

#: Cap on simultaneous TCP clients. One thread is spawned per connection, so
#: without a cap a connection flood becomes thread exhaustion.
MAX_TCP_CLIENTS = 256


class SyslogNetworkListener:
    """Multi-protocol (UDP/TCP) asynchronous Syslog receiver."""

    def __init__(
        self,
        on_event: Callable[[str, str], None],
        host: str = "127.0.0.1",
        port: int = 1514,
    ):
        self.on_event = on_event
        self.host = host
        self.port = port
        self._running = False
        self._udp_sock: socket.socket | None = None
        self._tcp_sock: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._packet_count = 0
        self._dropped_count = 0
        self._rejected_connections = 0
        # A plain += from several receiver threads can lose increments; the
        # counters back operator-facing stats, so they are guarded.
        self._counter_lock = threading.Lock()
        self._client_sem = threading.BoundedSemaphore(MAX_TCP_CLIENTS)

    def start(self) -> None:
        """
        Start the UDP and TCP listeners on background daemon threads.

        Binding to a non-loopback address exposes an unauthenticated ingest
        path, so that is logged prominently rather than left implicit.
        """
        if self.host in ("0.0.0.0", "::"):  # noqa: S104 — operator's explicit choice
            logger.warning(
                "Syslog listener binding to ALL interfaces on port %d — "
                "anyone who can reach this host can inject log records.",
                self.port,
            )
        if self._running:
            return
        self._running = True

        # 1. UDP Listener Socket
        try:
            self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_sock.bind((self.host, self.port))
            t_udp = threading.Thread(target=self._udp_worker, daemon=True, name="ULPF-Syslog-UDP")
            t_udp.start()
            self._threads.append(t_udp)
            logger.info("Syslog UDP listener active on %s:%d", self.host, self.port)
        except Exception as exc:
            logger.warning("Could not bind Syslog UDP socket on %s:%d: %s", self.host, self.port, exc)

        # 2. TCP Listener Socket
        try:
            self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._tcp_sock.bind((self.host, self.port))
            self._tcp_sock.listen(128)
            t_tcp = threading.Thread(target=self._tcp_worker, daemon=True, name="ULPF-Syslog-TCP")
            t_tcp.start()
            self._threads.append(t_tcp)
            logger.info("Syslog TCP listener active on %s:%d", self.host, self.port)
        except Exception as exc:
            logger.warning("Could not bind Syslog TCP socket on %s:%d: %s", self.host, self.port, exc)

    def _bump(self, attr: str) -> None:
        """Increment a shared counter atomically."""
        with self._counter_lock:
            setattr(self, attr, getattr(self, attr) + 1)

    def _udp_worker(self) -> None:
        while self._running and self._udp_sock:
            try:
                data, addr = self._udp_sock.recvfrom(65535)
                if data:
                    line = data.decode("utf-8", errors="surrogateescape").strip()
                    if line:
                        self._bump("_packet_count")
                        self.on_event(line, f"syslog_udp_{addr[0]}")
            except OSError:
                if not self._running:
                    break
                # A closed or reset socket would otherwise spin this loop at
                # 100% CPU; back off briefly and re-check the running flag.
                time.sleep(0.05)
            except Exception as exc:
                if not self._running:
                    break
                self._bump("_dropped_count")
                logger.warning("Dropping malformed UDP syslog packet: %s", exc)

    def _tcp_worker(self) -> None:
        while self._running and self._tcp_sock:
            try:
                client_sock, addr = self._tcp_sock.accept()
            except OSError:
                if not self._running:
                    break
                time.sleep(0.05)
                continue

            if not self._client_sem.acquire(blocking=False):
                self._bump("_rejected_connections")
                logger.warning(
                    "Refusing syslog TCP connection from %s: at %d client limit",
                    addr[0], MAX_TCP_CLIENTS,
                )
                try:
                    client_sock.close()
                except OSError:
                    pass
                continue

            threading.Thread(
                target=self._handle_tcp_client,
                args=(client_sock, addr),
                daemon=True,
                name=f"ULPF-Syslog-TCP-{addr[0]}",
            ).start()

    def _handle_tcp_client(self, client_sock: socket.socket, addr: tuple[str, int]) -> None:
        source_tag = f"syslog_tcp_{addr[0]}"
        try:
            with client_sock:
                buffer = ""
                while self._running:
                    try:
                        data = client_sock.recv(4096)
                    except OSError:
                        break
                    if not data:
                        break
                    buffer += data.decode("utf-8", errors="surrogateescape")

                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if line:
                            self._bump("_packet_count")
                            try:
                                self.on_event(line, source_tag)
                            except Exception as exc:
                                self._bump("_dropped_count")
                                logger.warning("Handler rejected TCP record: %s", exc)

                    # Records are newline-delimited; a peer that sends none is
                    # either broken or hostile. Drop it rather than buffering.
                    if len(buffer) > MAX_TCP_RECORD_BYTES:
                        self._bump("_dropped_count")
                        logger.warning(
                            "Closing syslog TCP client %s: %d bytes with no record delimiter",
                            addr[0], len(buffer),
                        )
                        break
        finally:
            self._client_sem.release()

    def stop(self) -> None:
        """Stop listening and close sockets."""
        self._running = False
        for attr in ("_udp_sock", "_tcp_sock"):
            sock = getattr(self, attr)
            if sock is None:
                continue
            try:
                sock.close()
            except OSError as exc:
                logger.debug("Closing %s failed during shutdown: %s", attr, exc)
            setattr(self, attr, None)

    def get_stats(self) -> dict:
        """Operational counters for this listener."""
        return {
            "running": self._running,
            "port": self.port,
            "host": self.host,
            "packets_received": self._packet_count,
            "packets_dropped": self._dropped_count,
            "connections_rejected": self._rejected_connections,
            "max_tcp_clients": MAX_TCP_CLIENTS,
        }
