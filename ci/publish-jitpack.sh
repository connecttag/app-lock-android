#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
log_file=$(mktemp)
trap 'rm -f "$log_file"' EXIT
for attempt in 1 2 3; do
    set +e
    ./gradlew --no-daemon --max-workers=2 publishToMavenLocal "$@" 2>&1 | tee "$log_file"
    result=${PIPESTATUS[0]}
    set -e
    if [ "$result" -eq 0 ]; then exit 0; fi
    # Only retry transient repository failures. Never hide compilation errors.
    if [ "$attempt" -eq 3 ] || ! grep -Eqi 'HTTP 429|status code (429|502|503)|Too Many Requests|Read timed out|Connection reset' "$log_file"; then
        exit "$result"
    fi
    sleep "$((attempt * 30))"
done
