from __future__ import annotations

import random
import socket
import struct


def probe_socks5_udp(port: int, timeout: float = 8.0) -> int:
    socks_host = "127.0.0.1"
    with socket.create_connection((socks_host, port), timeout=timeout) as control:
        control.sendall(b"\x05\x01\x00")
        if _recv_exact(control, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS method negotiation failed")
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        relay = _parse_bound_address(control, socks_host)
        query_id, payload = _dns_query()
        frame = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 53) + payload
        family = socket.AF_INET6 if ":" in relay[0] else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(timeout)
            udp.sendto(frame, relay)
            response, _ = udp.recvfrom(4096)
    if len(response) < 12 or response[:2] != b"\x00\x00" or response[2] != 0:
        raise RuntimeError("invalid SOCKS UDP response")
    atyp = response[3]
    offset = 10 if atyp == 1 else 22 if atyp == 4 else 5 + response[4]
    dns = response[offset:]
    received_id, flags, _, answers, _, _ = struct.unpack("!HHHHHH", dns[:12])
    if received_id != query_id or not (flags & 0x8000) or answers < 1:
        raise RuntimeError("DNS response did not contain an answer")
    return answers


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError("SOCKS control connection closed")
        data += part
    return data


def _parse_bound_address(sock: socket.socket, fallback_host: str) -> tuple[str, int]:
    header = _recv_exact(sock, 4)
    if header[0] != 5 or header[1] != 0:
        raise RuntimeError("SOCKS UDP ASSOCIATE failed")
    atyp = header[3]
    if atyp == 1:
        host = socket.inet_ntoa(_recv_exact(sock, 4))
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, _recv_exact(sock, 16))
    elif atyp == 3:
        host = _recv_exact(sock, _recv_exact(sock, 1)[0]).decode("ascii")
    else:
        raise RuntimeError("unexpected SOCKS address type")
    port = struct.unpack("!H", _recv_exact(sock, 2))[0]
    if host in ("0.0.0.0", "::"):
        host = fallback_host
    return host, port


def _dns_query() -> tuple[int, bytes]:
    query_id = random.randint(0, 65535)
    question = b"".join(bytes([len(label)]) + label for label in b"cloudflare.com".split(b".")) + b"\x00"
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)
    return query_id, packet
