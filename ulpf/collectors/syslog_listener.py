"""
High-Throughput Syslog Network Listener (UDP & TCP).

Listens on UDP and TCP ports (e.g. 514, 1514) to ingest real syslog packets
from enterprise network appliances, firewalls, and servers directly into the ULPF pipeline.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import threading
from typing import Callable

logger = logging.getLogger("ulpf.collectors.syslog")


class SyslogNetworkListener:
    """Multi-protocol (UDP/TCP) asynchronous Syslog receiver."""

    def __init__(
        self,
        on_event: Callable[[str, str], None],
        host: str = "0.0.0.0",
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

    def start(self) -> None:
        """Start both UDP and TCP listeners on background daemon threads."""
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

    def _udp_worker(self) -> None:
        while self._running and self._udp_sock:
            try:
                data, addr = self._udp_sock.recvfrom(65535)
                if data:
                    line = data.decode("utf-8", errors="surrogateescape").strip()
                    if line:
                        self._packet_count += 1
                        self.on_event(line, f"syslog_udp_{addr[0]}")
            except Exception:
                if not self._running:
                    break

    def _tcp_worker(self) -> None:
        while self._running and self._tcp_sock:
            try:
                client_sock, addr = self._tcp_sock.accept()
                client_thread = threading.Thread(
                    target=self._handle_tcp_client,
                    args=(client_sock, addr),
                    daemon=True,
                )
                client_thread.start()
            except Exception:
                if not self._running:
                    break

    def _handle_tcp_client(self, client_sock: socket.socket, addr: tuple[str, int]) -> None:
        with client_sock:
            buffer = ""
            while self._running:
                try:
                    data = client_sock.recv(4096)
                    if not data:
                        break
                    chunk = data.decode("utf-8", errors="surrogateescape")
                    buffer += chunk
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if line:
                            self._packet_count += 1
                            self.on_event(line, f"syslog_tcp_{addr[0]}")
                except Exception:
                    break

    def stop(self) -> None:
        """Stop listening and close sockets."""
        self._running = False
        if self._udp_sock:
            try: self._udp_sock.close()
            except Exception: pass
            self._udp_sock = None
        if self._tcp_sock:
            try: self._tcp_sock.close()
            except Exception: pass
            self._tcp_sock = None

    def get_stats(self) -> dict:
        return {
            "running": self._running,
            "port": self.port,
            "host": self.host,
            "packets_received": self._packet_count,
        }
