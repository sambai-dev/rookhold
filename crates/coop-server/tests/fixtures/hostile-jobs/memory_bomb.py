import os
import time

# Each process remains comfortably below the requested per-process address
# space, while their faulted pages exceed the aggregate cgroup memory.max.
# memory.oom.group must therefore kill the whole job, including namespace PID1,
# before PID1 can send its normal final control frame.
for _ in range(4):
    if os.fork() == 0:
        chunks = [bytearray(4 * 1024 * 1024) for _ in range(12)]
        for chunk in chunks:
            for offset in range(0, len(chunk), 4096):
                chunk[offset] = 1
        time.sleep(30)
        os._exit(0)

time.sleep(30)
raise RuntimeError("aggregate memory bomb survived the cgroup cap")
