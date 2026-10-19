import ctypes
import errno
import socket
import sys

assert socket.gethostname() == "coop-sandbox", socket.gethostname()

left, right = socket.socketpair()
left.close()
right.close()

libc = ctypes.CDLL(None, use_errno=True)
fds = (ctypes.c_int * 2)()
ctypes.set_errno(0)
pair_result = libc.socketpair(socket.AF_INET, socket.SOCK_STREAM, 0, fds)
assert pair_result == -1 and ctypes.get_errno() == errno.EAFNOSUPPORT, (
    pair_result,
    ctypes.get_errno(),
)

ctypes.set_errno(0)
uring_result = libc.syscall(425, 1, 0)
assert uring_result == -1 and ctypes.get_errno() == errno.EPERM, (
    uring_result,
    ctypes.get_errno(),
)
print("RUNTIME-PROBES-DENIED-SAFELY")

try:
    sock = socket.create_connection(("example.com", 443), timeout=3)
    sock.close()
except OSError as e:
    print(f"network blocked: {e}")
    sys.exit(0)

print("network UP - sandbox leak!")
sys.exit(3)
