"""Passive client RTT via Linux TCP_INFO."""
import socket
import struct

_TCP_INFO = 11
_RTT_OFFSET = 72
_BUF_SIZE = 104


def read_client_rtt_us(sock) -> int | None:
    """Smoothed RTT in microseconds from the kernel, or None if unavailable.

    Linux only. No extra round trips. Works through SSLSocket wrappers since
    getsockopt is forwarded to the underlying TCP fd.
    """
    try:
        buf = sock.getsockopt(socket.IPPROTO_TCP, _TCP_INFO, _BUF_SIZE)
    except (OSError, AttributeError):
        return None
    if len(buf) < _RTT_OFFSET + 4:
        return None
    rtt_us, = struct.unpack_from("I", buf, _RTT_OFFSET)
    return rtt_us or None
