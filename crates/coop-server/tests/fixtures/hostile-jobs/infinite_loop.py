import time

# Exercise the wall-clock supervisor without racing the separate CPU-budget
# gate or depending on a hot interpreter loop remaining healthy.
while True:
    time.sleep(60)
