#!/bin/bash
# =============================================================
# Raphael 2.0 — HTB Environment Setup
# =============================================================
# Source this file in your shell before starting an HTB session:
#   source htb_setup.sh
# =============================================================

export DOCKER_HOST=unix:///var/run/docker.sock
RAPHAEL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load .env values for the CLI (export what health_check.py needs)
set -a
source "$RAPHAEL_DIR/.env" 2>/dev/null
set +a

# The raphael CLI reads RAPHAEL_API_KEY for auth
# If not in .env, fall back to the Docker container's current API_KEY
if [ -z "$RAPHAEL_API_KEY" ]; then
  RAPHAEL_API_KEY=$(docker compose exec raphael-api printenv API_KEY 2>/dev/null | tr -d '\r')
fi
export RAPHAEL_API_KEY

alias raphael="python3 $RAPHAEL_DIR/cli/raphael.py"

echo "=== Raphael 2.0 — HTB Ready ==="
echo "  API:       http://localhost:3900"
echo "  Auth:      \$RAPHAEL_API_KEY set"
echo "  Docker:    \$DOCKER_HOST set"
echo "  Alias:     raphael -> $RAPHAEL_DIR/cli/raphael.py"
echo ""
echo "  Quick start:"
echo "    raphael health               # Check all services"
echo "    raphael models --list        # List available AI models"
echo "    raphael scan <htb-ip>        # Quick scan"
echo "    raphael engage run <htb-ip>  # Full engagement"
echo "    raphael chat                 # Interactive AI chat"
echo ""
