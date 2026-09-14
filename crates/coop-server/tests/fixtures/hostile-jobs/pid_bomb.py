import multiprocessing
import sys

def sleeper():
    while True:
        try:
            __import__("time").sleep(3600)
        except Exception:
            return

if __name__ == "__main__":
    procs = []
    try:
        for i in range(500):
            p = multiprocessing.Process(target=sleeper, daemon=True)
            p.start()
            procs.append(p)
    except (OSError, PermissionError) as e:
        print(f"spawn refused after {len(procs)} processes: {e}")
        sys.exit(2)

    print(f"spawned {len(procs)} processes - no cap!")
    sys.exit(1)
