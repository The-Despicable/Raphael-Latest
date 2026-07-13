#!/bin/bash
# Raphael 2.0 CLI launcher
# Usage: ./raphael.sh scan 10.10.11.21
export DOCKER_HOST=unix:///var/run/docker.sock
DIR="$(dirname "$(readlink -f "$0")")"
# Read API key from .env
API_KEY=$(grep '^RAPHAEL_API_KEY=' "$DIR/.env" 2>/dev/null | head -1 | cut -d= -f2-)
[ -z "$API_KEY" ] && API_KEY=$(grep '^API_KEY=' "$DIR/.env" 2>/dev/null | head -1 | cut -d= -f2-)
export RAPHAEL_API_KEY="$API_KEY"
exec python3 "$DIR/cli/raphael.py" "$@"
