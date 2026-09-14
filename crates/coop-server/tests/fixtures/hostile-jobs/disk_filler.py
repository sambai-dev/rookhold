import sys

written = 0
try:
    with open("/tmp/blob", "wb") as f:
        block = b"\0" * (8 * 1024 * 1024)
        while written < 4 * 1024 * 1024 * 1024:
            f.write(block)
            f.flush()
            written += len(block)
except OSError as e:
    print(f"write refused after {written} bytes: {e}")
    sys.exit(1)

print("wrote 4GiB - no filesystem cap!")
sys.exit(1)
