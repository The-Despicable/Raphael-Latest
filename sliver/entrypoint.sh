#!/bin/sh
set -e

OPERATOR_CONFIG="/config/operator.cfg"
SLIVER_LISEN_PORT="${SLIVER_LISEN_PORT:-31337}"

# Generate operator config if it doesn't exist
if [ ! -f "$OPERATOR_CONFIG" ]; then
    echo "[sliver] Generating operator config..."

    # Start server in background for config generation
    sliver-server daemon --daemon --lhost 0.0.0.0 --lport "$SLIVER_LISEN_PORT" &
    SERVER_PID=$!

    # Wait for server to start
    sleep 3

    # Create operator config
    sliver-server operator --name raphael --lhost sliver-server --lport "$SLIVER_LISEN_PORT" --save "$OPERATOR_CONFIG" 2>&1 || true

    # Create default implant profile
    sliver-server profiles --save 2>/dev/null || true

    echo "[sliver] Operator config saved to $OPERATOR_CONFIG"

    # Keep server running in foreground
    wait $SERVER_PID
else
    echo "[sliver] Operator config exists at $OPERATOR_CONFIG"
    echo "[sliver] Starting Sliver server daemon..."

    exec sliver-server daemon --daemon --lhost 0.0.0.0 --lport "$SLIVER_LISEN_PORT"
fi
