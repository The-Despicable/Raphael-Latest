#!/bin/sh
set -e

OPERATOR_CONFIG="/config/operator.cfg"
SLIVER_LISEN_PORT="${SLIVER_LISEN_PORT:-31337}"

# Generate operator config if it doesn't exist
if [ ! -f "$OPERATOR_CONFIG" ]; then
    echo "[sliver] First run — starting daemon to generate config..."

    # Start server daemon in background (this generates CA + certs on first run)
    sliver-server daemon --lhost 0.0.0.0 --lport "$SLIVER_LISEN_PORT" &
    DAEMON_PID=$!

    # Wait for daemon to be ready
    sleep 5

    # Generate operator config (connects to running daemon to get proper CA)
    sliver-server operator --name raphael --lhost sliver-server --lport "$SLIVER_LISEN_PORT" --permissions all -s "$OPERATOR_CONFIG" 2>&1 || true

    # Make config readable by non-root
    chmod 644 "$OPERATOR_CONFIG" 2>/dev/null || true

    echo "[sliver] Operator config saved to $OPERATOR_CONFIG"

    # Kill the background daemon — we'll restart it as the main process below
    kill "$DAEMON_PID" 2>/dev/null || true
    sleep 2
fi

echo "[sliver] Starting Sliver server daemon..."
exec sliver-server daemon --lhost 0.0.0.0 --lport "$SLIVER_LISEN_PORT"
