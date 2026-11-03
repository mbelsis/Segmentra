#!/usr/bin/env python3
"""Simulated IoT/OT devices and clients for the iot lab of scripts/demo-lab.py.

  iot-device.py serve modbus s7     answer these protocols on their usual ports, until stopped
  iot-device.py probe modbus IP     send a real request; exit 0 only when a valid answer came back

Each service speaks just enough of its protocol for one request and one answer, so a passing probe
means the request crossed the network and a device answered. These test firewall rules; they are
not a model of how real equipment behaves.
"""
import socket
import socketserver
import sys
import threading

TIMEOUT_SECONDS = 2


def modbus_reply(request):
    # Read Holding Registers answered with one register. Keeps the client's transaction id.
    return request[:2] + bytes.fromhex("00 00 00 05 01 03 02 00 2a")


SERVICES = {
    # name: (port, request, how to answer it, the bytes a valid answer starts with)
    "modbus": (502, bytes.fromhex("00 01 00 00 00 06 01 03 00 00 00 01"), modbus_reply, bytes.fromhex("00 01 00 00 00 05 01 03")),
    # S7comm starts with a COTP connection request (0xE0); the answer is a connection confirm (0xD0).
    "s7": (102, bytes.fromhex("03 00 00 16 11 e0 00 00 00 01 00 c1 02 01 00 c2 02 01 02 c0 01 0a"), lambda _: bytes.fromhex("03 00 00 16 11 d0 00 01 00 01 00 c1 02 01 00 c2 02 01 02 c0 01 0a"), bytes.fromhex("03 00 00 16 11 d0")),
    # DNP3 link layer: request link status, answered with link status.
    "dnp3": (20000, bytes.fromhex("05 64 05 c9 01 00 00 04 00 00"), lambda _: bytes.fromhex("05 64 05 0b 00 04 01 00 00 00"), bytes.fromhex("05 64 05 0b")),
    # MQTT CONNECT, answered with CONNACK "accepted".
    "mqtt": (1883, bytes.fromhex("10 0f 00 04 4d 51 54 54 04 02 00 3c 00 03 6c 61 62"), lambda _: bytes.fromhex("20 02 00 00"), bytes.fromhex("20 02 00 00")),
    "rtsp": (554, b"OPTIONS rtsp://camera/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", lambda _: b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: DESCRIBE, SETUP, PLAY\r\n\r\n", b"RTSP/1.0 200"),
    "http": (80, b"GET / HTTP/1.0\r\n\r\n", lambda _: b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nok\n", b"HTTP/1.0 200"),
    # Printer port: a PJL status request.
    "jetdirect": (9100, b"@PJL INFO STATUS\r\n", lambda _: b"@PJL INFO STATUS\r\nCODE=10001\r\nONLINE=TRUE\r\n", b"@PJL INFO STATUS"),
}


def serve(names):
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    threads = []
    for name in names:
        port, _, answer, _ = SERVICES[name]

        class Handler(socketserver.BaseRequestHandler):
            reply = staticmethod(answer)

            def handle(self):
                self.request.settimeout(TIMEOUT_SECONDS)
                try:
                    self.request.sendall(self.reply(self.request.recv(1024)))
                except OSError:
                    pass

        thread = threading.Thread(target=Server(("", port), Handler).serve_forever)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    threading.Event().wait()  # a machine with nothing to serve keeps running as a client


def probe(name, ip):
    port, request, _, expected = SERVICES[name]
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT_SECONDS) as connection:
            connection.settimeout(TIMEOUT_SECONDS)
            connection.sendall(request)
            return 0 if connection.recv(1024).startswith(expected) else 1
    except OSError:
        return 1


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "serve":
        serve(sys.argv[2:])
    elif len(sys.argv) == 4 and sys.argv[1] == "probe":
        sys.exit(probe(sys.argv[2], sys.argv[3]))
    else:
        sys.exit(__doc__)
