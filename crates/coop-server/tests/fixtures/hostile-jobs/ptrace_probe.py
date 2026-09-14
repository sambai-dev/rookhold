# F-005: ptrace sits on the seccomp trap list; calling it must kill this job
# with SIGSYS before it can report success. If the filter were missing or
# misconfigured, this script would print "ptrace returned ..." and exit 0.
import sys

try:
    import ctypes

    libc = ctypes.CDLL(None)
    # PTRACE_TRACEME == 0. A trapped call never returns; an allowed one does.
    rc = libc.ptrace(0, 0, 0, 0)
except Exception as exc:  # noqa: BLE001 - any failure still means "no ptrace"
    print(f"ptrace unavailable: {exc}")
    sys.exit(0)

print(f"ptrace returned {rc}")
sys.exit(0)
