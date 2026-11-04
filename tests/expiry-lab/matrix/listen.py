#!/usr/bin/env python3
# Test listeners started at boot, so that real traffic can be checked after a reboot.
import socket, threading
def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', port)); s.listen(16)
    while True:
        c, _ = s.accept(); c.close()
for p in (8081, 8082, 8083):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
threading.Event().wait()
