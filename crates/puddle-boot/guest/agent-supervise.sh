#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Keeps puddle-agent running: restarts it whenever it exits or is killed. boot.sh starts it in
# its own session, once per boot.
#
#   /bin/sh agent-supervise.sh <agent> [args...]
#
# A restart takes 0.2 s, so the agent is back well within 1 s after a kill -9. An agent that
# keeps dying within seconds of starting is restarted with a growing delay (up to 10 s), so a
# broken binary doesn't spin.
set -u
[ "$#" -ge 1 ] || {
    echo "usage: agent-supervise.sh <agent> [args...]" >&2
    exit 2
}
agent=$1
shift
quick=0
while :; do
    started=$(date +%s)
    "$agent" "$@"
    rc=$?
    ran=$(($(date +%s) - started))
    if [ "$ran" -ge 5 ]; then quick=0; else quick=$((quick + 1)); fi
    echo "puddle-agent exited with status $rc after ${ran}s; restarting"
    if [ "$quick" -le 3 ]; then
        sleep 0.2 2>/dev/null || sleep 1
    else
        sleep $((quick < 10 ? quick : 10))
    fi
done
