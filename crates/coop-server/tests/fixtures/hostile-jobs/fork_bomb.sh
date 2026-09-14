for i in $(seq 1 200); do
    sleep 5 2>/dev/null &
done

# Count the processes that actually exist, rather than accepted background
# job syntax: bash may assign `$!` even when clone later fails at pids.max.
alive=0
for process in /proc/[0-9]*; do
    alive=$((alive + 1))
done
echo "alive=$alive"
if [ "$alive" -gt 33 ]; then
    echo "FORK BOMB NOT CONTAINED"
    exit 1
fi
wait
exit 0
