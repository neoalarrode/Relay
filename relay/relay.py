#!/usr/bin/env python3
"""
Movistar IPTV Multicast-to-HTTP Relay
Home Assistant Add-on

Converts multicast RTP/UDP IPTV streams to plain HTTP MPEG-TS.
Compatible with the scanner's --udpxy option.

Endpoints:
  GET /udp/<addr>:<port>/   Stream multicast channel as HTTP
  GET /status               Relay status (JSON)
  GET /rtp/<addr>:<port>/   Same as /udp/ (alias)
"""

import argparse
import json
import re
import socket
import struct
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

TS_SYNC = 0x47
TS_SIZE = 188


def detect_iptv_ip():
    for dns in ("172.26.23.3", "172.23.3.3"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.connect((dns, 53))
                return s.getsockname()[0]
        except OSError:
            continue

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip.startswith("192.168.2."):
                return ip
    except OSError:
        pass

    return None


def strip_rtp(data):
    if len(data) < 12 or data[0] == TS_SYNC:
        return data
    if (data[0] >> 6) != 2:
        return data

    cc = data[0] & 0x0F
    has_padding = bool(data[0] & 0x20)
    has_extension = bool(data[0] & 0x10)

    offset = 12 + cc * 4

    if has_extension and len(data) > offset + 4:
        ext_len = (data[offset + 2] << 8) | data[offset + 3]
        offset += 4 + ext_len * 4

    end = len(data)
    if has_padding and end > offset:
        pad_count = data[-1]
        if pad_count < (end - offset):
            end -= pad_count

    return data[offset:end]


class RelayState:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = {}
        self.total_served = 0
        self.start_time = time.time()
        self.bytes_relayed = 0

    def connect(self, key, client):
        with self.lock:
            if key not in self.active:
                self.active[key] = []
            self.active[key].append(client)
            self.total_served += 1

    def disconnect(self, key, client):
        with self.lock:
            if key in self.active:
                try:
                    self.active[key].remove(client)
                except ValueError:
                    pass
                if not self.active[key]:
                    del self.active[key]

    def add_bytes(self, n):
        with self.lock:
            self.bytes_relayed += n

    def status(self):
        with self.lock:
            uptime = int(time.time() - self.start_time)
            h, m = divmod(uptime, 3600)
            m, s = divmod(m, 60)
            mb = self.bytes_relayed / (1024 * 1024)
            return {
                "version": "1.0.0",
                "uptime": f"{h}h {m}m {s}s",
                "active_streams": sum(len(v) for v in self.active.values()),
                "active_channels": list(self.active.keys()),
                "total_served": self.total_served,
                "bytes_relayed_mb": round(mb, 1),
            }


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "MovistarRelay/1.0"
    interface = "0.0.0.0"
    buffer_kb = 1024
    max_clients = 10
    state = None

    def log_message(self, fmt, *args):
        print(f"[relay] {self.client_address[0]} {fmt % args}", flush=True)

    def do_GET(self):
        path = self.path.rstrip("/")

        m = re.match(r"/(udp|rtp)/(\d+\.\d+\.\d+\.\d+):(\d+)", path)
        if m:
            addr = m.group(2)
            port = int(m.group(3))
            self._relay(addr, port)
            return

        if path in ("/status", "/stat"):
            data = json.dumps(self.state.status(), indent=2)
            self._respond(200, data.encode(), "application/json")
            return

        if path in ("", "/"):
            body = (
                "<html><head><title>Movistar IPTV Relay</title></head><body>"
                "<h2>Movistar IPTV Relay</h2>"
                "<p>Uso: <code>/udp/239.x.x.x:8208/</code></p>"
                "<p><a href='/status'>Estado</a></p>"
                "</body></html>"
            )
            self._respond(200, body.encode(), "text/html")
            return

        self.send_error(404)

    def _respond(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _relay(self, addr, port):
        key = f"{addr}:{port}"
        state = self.state

        active = sum(len(v) for v in state.active.values())
        if active >= self.max_clients:
            self.send_error(503, "Max clients reached")
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_kb * 1024)
            sock.settimeout(10)
            sock.bind(("", port))
            mreq = struct.pack("4s4s",
                               socket.inet_aton(addr),
                               socket.inet_aton(self.interface))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError as e:
            self.send_error(503, f"Multicast join failed: {e}")
            return

        client = f"{self.client_address[0]}:{self.client_address[1]}"
        state.connect(key, client)
        print(f"[relay] + {client} -> {key}", flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "video/MP2T")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        try:
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        total_bytes = 0
        try:
            buf = bytearray()
            while True:
                try:
                    data = sock.recv(65535)
                except socket.timeout:
                    if buf:
                        self.wfile.write(buf)
                        self.wfile.flush()
                        buf.clear()
                    continue
                if not data:
                    break

                ts_payload = strip_rtp(data)
                buf.extend(ts_payload)

                if len(buf) >= TS_SIZE * 49:
                    self.wfile.write(buf)
                    self.wfile.flush()
                    total_bytes += len(buf)
                    buf.clear()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            state.disconnect(key, client)
            state.add_bytes(total_bytes)
            print(f"[relay] - {client} -x {key} ({total_bytes // 1024} KB)", flush=True)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            except OSError:
                pass
            sock.close()


class ThreadedHTTPServer(HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def process_request(self, request, client_address):
        t = threading.Thread(target=self.process_request_thread,
                             args=(request, client_address), daemon=True)
        t.start()

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


def load_ha_options():
    opts_path = "/data/options.json"
    try:
        with open(opts_path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[relay] ERROR: {opts_path} not found", flush=True)
        sys.exit(1)


def main():
    p = argparse.ArgumentParser(description="Movistar IPTV Multicast-to-HTTP Relay")
    p.add_argument("--port", type=int, default=4022)
    p.add_argument("--interface", default="auto",
                   help="Multicast interface IP (auto = detect Movistar VLAN)")
    p.add_argument("--max-clients", type=int, default=10)
    p.add_argument("--buffer", type=int, default=1024, help="UDP receive buffer (KB)")
    p.add_argument("--ha-addon", action="store_true",
                   help="Read config from /data/options.json (Home Assistant mode)")
    args = p.parse_args()

    if args.ha_addon:
        opts = load_ha_options()
        args.port = int(opts.get("port", 4022))
        args.interface = opts.get("mcast_interface", "auto")
        args.max_clients = int(opts.get("max_clients", 10))
        args.buffer = int(opts.get("buffer_kb", 1024))

    if args.interface == "auto":
        iface = detect_iptv_ip()
        if not iface:
            print("[relay] ERROR: No se detecta la red IPTV de Movistar", flush=True)
            print("[relay] Configura mcast_interface con la IP de tu interfaz en la VLAN IPTV", flush=True)
            sys.exit(1)
        print(f"[relay] Auto-detected IPTV interface: {iface}", flush=True)
    else:
        iface = args.interface
        print(f"[relay] Using configured interface: {iface}", flush=True)

    state = RelayState()
    RelayHandler.interface = iface
    RelayHandler.buffer_kb = args.buffer
    RelayHandler.max_clients = args.max_clients
    RelayHandler.state = state

    server = ThreadedHTTPServer(("0.0.0.0", args.port), RelayHandler)

    print(f"[relay] Movistar IPTV Relay v1.0.2", flush=True)
    print(f"[relay] Listening on 0.0.0.0:{args.port}", flush=True)
    print(f"[relay] Multicast interface: {iface}", flush=True)
    print(f"[relay] Max clients: {args.max_clients}", flush=True)
    print(f"[relay] Uso: http://<ip>:{args.port}/udp/239.x.x.x:8208/", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[relay] Stopping...", flush=True)
        server.shutdown()


if __name__ == "__main__":
    main()
